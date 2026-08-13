//! Directory checks for state that an elevated process writes.
//!
//! Cove runs elevated. Any directory it writes to that an unprivileged user can
//! also reach is a redirection target: replacing it with a reparse point sends
//! privileged writes wherever the attacker points them. These helpers create a
//! directory ourselves and refuse anything that is not a plain directory, so
//! callers can fail closed instead of writing through a junction.

use std::path::{Path, PathBuf};

/// Create `path` if it is missing, then confirm it is a real directory and not
/// a reparse point. Only the final component is created; the parent must
/// already exist and be trusted by the caller.
pub fn ensure_plain_directory(path: &Path) -> Result<PathBuf, String> {
    match std::fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(format!("{} could not be created: {error}", path.display())),
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("{} could not be inspected: {error}", path.display()))?;
    // Reparse check first: a junction reports as a link rather than a directory,
    // and the specific reason is what belongs in the log.
    if has_reparse_attribute(&metadata) {
        return Err(format!("{} is a reparse point", path.display()));
    }
    if !metadata.is_dir() {
        return Err(format!("{} is not a directory", path.display()));
    }
    Ok(path.to_path_buf())
}

/// True when `path` is a reparse point, or cannot be inspected at all.
pub fn is_reparse_point(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| has_reparse_attribute(&metadata))
}

#[cfg(target_os = "windows")]
fn has_reparse_attribute(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    // The raw attribute covers every reparse tag, unlike `is_symlink()`, which
    // only reports the symlink and mount-point tags.
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(target_os = "windows"))]
fn has_reparse_attribute(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(test)]
mod tests {
    use super::{ensure_plain_directory, is_reparse_point};

    fn temp_base() -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!("cove-storage-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&base).expect("test base directory");
        base
    }

    #[test]
    fn creates_a_missing_directory_and_accepts_it_again() {
        let base = temp_base();
        let target = base.join("cove-app-data");

        let created = ensure_plain_directory(&target).expect("first call creates the directory");
        assert!(created.is_dir());
        assert!(!is_reparse_point(&target));
        ensure_plain_directory(&target).expect("second call accepts the existing directory");

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn rejects_a_path_that_is_not_a_directory() {
        let base = temp_base();
        let target = base.join("cove-app-data");
        std::fs::write(&target, b"not a directory").expect("test file");

        let error = ensure_plain_directory(&target).expect_err("a file must be refused");
        assert!(
            error.contains("not a directory"),
            "unexpected reason: {error}"
        );

        std::fs::remove_dir_all(&base).ok();
    }

    /// The case that made adjacent storage unsafe in the first place: an
    /// unprivileged user plants a junction where elevated writes will land.
    #[cfg(target_os = "windows")]
    #[test]
    fn rejects_a_planted_junction() {
        let base = temp_base();
        let elsewhere = base.join("redirect-target");
        std::fs::create_dir(&elsewhere).expect("redirect target");
        let target = base.join("cove-app-data");

        let created = std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &target.to_string_lossy(),
                &elsewhere.to_string_lossy(),
            ])
            .status()
            .expect("mklink runs");
        assert!(
            created.success(),
            "could not create the junction under test"
        );

        assert!(is_reparse_point(&target));
        let error = ensure_plain_directory(&target).expect_err("a junction must be refused");
        assert!(
            error.contains("reparse point"),
            "unexpected reason: {error}"
        );

        std::fs::remove_dir(&target).ok();
        std::fs::remove_dir_all(&base).ok();
    }
}
