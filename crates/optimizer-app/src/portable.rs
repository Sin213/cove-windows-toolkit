use std::path::PathBuf;

/// The single-file build is portable in the no-install sense, but state is
/// deliberately kept in the per-user application-data directory. Following an
/// adjacent `portable.marker`/`cove-app-data` directory from an elevated process
/// would let an unprivileged junction redirect privileged log and snapshot
/// writes. A future true side-by-side mode must use handle-relative, no-reparse
/// storage before it can be enabled safely.
pub fn is_portable() -> bool {
    false
}

pub fn portable_data_dir(_app_name: &str) -> PathBuf {
    let dir = directories::ProjectDirs::from("com", "cove", "optimizer")
        .map(|directories| directories.data_local_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&dir).ok();
    dir
}
