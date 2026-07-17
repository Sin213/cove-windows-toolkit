use std::path::PathBuf;

pub fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .expect("cannot determine exe path")
        .parent()
        .expect("exe has no parent directory")
        .to_path_buf()
}

pub fn is_portable() -> bool {
    let base = exe_dir();
    let portable_name = std::env::current_exe()
        .ok()
        .and_then(|path| {
            path.file_stem()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .is_some_and(|name| name.ends_with("-Portable"));
    portable_name || base.join("cove-app-data").is_dir() || base.join("portable.marker").is_file()
}

pub fn portable_data_dir(app_name: &str) -> PathBuf {
    let dir = exe_dir().join("cove-app-data").join(app_name);
    std::fs::create_dir_all(&dir).ok();
    dir
}
