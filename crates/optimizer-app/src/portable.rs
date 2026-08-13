//! Where application state lives.
//!
//! The shipped portable executable keeps its state next to itself, in
//! `cove-app-data\cove-windows-optimizer\` - the classic "carry it on a USB
//! stick" arrangement. Any other copy of the executable can opt in by placing a
//! `portable.marker` file beside it. The installed build uses the per-user
//! application-data directory.
//!
//! Adjacent storage is privileged: the app runs elevated, so following a
//! reparse point planted next to the executable would let an unprivileged user
//! redirect elevated log, snapshot, and rollback writes into a location they do
//! not own. Every directory this module hands out is therefore created by us
//! and re-checked on each use, and any component that is a reparse point (of any
//! tag - junction, symlink, or otherwise) disables portable mode for the rest of
//! the session and falls back to per-user AppData. Note that this protects the
//! data directory only: an attacker who can write into the folder holding the
//! executable can replace the executable itself, so portable mode should be used
//! from media the operator controls.

use optimizer_core::storage::{ensure_plain_directory, is_reparse_point};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Opt-in marker the operator drops next to the executable.
const MARKER_NAME: &str = "portable.marker";
/// Adjacent state root, e.g. `D:\Cove\cove-app-data\cove-windows-optimizer\`.
const DATA_ROOT_NAME: &str = "cove-app-data";

/// Resolved once: `Some(root)` when adjacent storage was verified safe at
/// startup, `None` for a normal per-user install.
static PORTABLE_ROOT: OnceLock<Option<PathBuf>> = OnceLock::new();

fn portable_root() -> Option<&'static Path> {
    PORTABLE_ROOT.get_or_init(detect_portable_root).as_deref()
}

/// Portable mode is on when the shipped portable executable is being run (its
/// file name carries `Portable`, which is how the release asset is named), or
/// when a `portable.marker` file is placed next to any copy of the executable.
/// The installed build is named `Cove Windows Toolkit.exe` and never matches.
fn wants_portable_mode(executable: &Path, beside_executable: &Path) -> bool {
    let named_portable = executable
        .file_stem()
        .and_then(|stem| stem.to_str())
        .is_some_and(|stem| stem.to_ascii_lowercase().contains("portable"));
    if named_portable {
        return true;
    }
    let marker = beside_executable.join(MARKER_NAME);
    // The marker itself must be a plain file. A reparse point here would mean
    // the folder is already being used to redirect us somewhere else.
    marker.is_file() && !is_reparse_point(&marker)
}

fn detect_portable_root() -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    let beside_executable = executable.parent()?;
    if !wants_portable_mode(&executable, beside_executable) {
        return None;
    }
    match ensure_plain_directory(&beside_executable.join(DATA_ROOT_NAME)) {
        Ok(root) => Some(root),
        Err(reason) => {
            tracing::warn!(
                target: "cove::storage",
                reason = %reason,
                "portable mode requested but adjacent storage is not safe to use; falling back to AppData"
            );
            None
        }
    }
}

/// True when state is being kept next to the executable.
pub fn is_portable() -> bool {
    portable_root().is_some()
}

/// Root directory for this app's state: the verified adjacent directory in
/// portable mode, otherwise the per-user local application-data directory.
///
/// Re-verified on every call, so a reparse point planted after startup makes the
/// call fall back to AppData instead of writing through it.
pub fn data_dir(app_name: &str) -> PathBuf {
    if let Some(root) = portable_root() {
        match ensure_plain_directory(&root.join(app_name)) {
            Ok(directory) => return directory,
            Err(reason) => tracing::warn!(
                target: "cove::storage",
                reason = %reason,
                "adjacent storage became unsafe; using AppData for this write"
            ),
        }
    }
    user_data_dir()
}

fn user_data_dir() -> PathBuf {
    let dir = directories::ProjectDirs::from("com", "cove", "optimizer")
        .map(|directories| directories.data_local_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&dir).ok();
    dir
}
