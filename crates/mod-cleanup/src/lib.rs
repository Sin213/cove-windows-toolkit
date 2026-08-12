use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct CleanupTarget {
    pub id: String,
    pub name: String,
    pub path: String,
    pub size_bytes: u64,
    pub file_count: u64,
    pub safety: String,
    pub scan_error: Option<String>,
    pub scan_warning: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct CleanupResult {
    pub id: String,
    pub success: bool,
    pub partial: bool,
    pub message: String,
    pub freed_bytes: u64,
    pub deleted_files: u64,
    pub skipped_items: u64,
}

#[cfg(target_os = "windows")]
struct CleanupTargetSpec {
    id: &'static str,
    name: &'static str,
    path: String,
    safety: &'static str,
}

#[cfg(target_os = "windows")]
fn target_specs() -> Vec<CleanupTargetSpec> {
    let windows = optimizer_core::windows_directory();
    let local = directories::BaseDirs::new().map(|dirs| dirs.data_local_dir().to_path_buf());

    vec![
        CleanupTargetSpec {
            id: "clean.user_temp",
            name: "User Temp Files",
            path: local
                .as_ref()
                .map(|p| p.join("Temp"))
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            safety: "green",
        },
        CleanupTargetSpec {
            id: "clean.system_temp",
            name: "System Temp Files",
            path: windows.join("Temp").to_string_lossy().into(),
            safety: "green",
        },
        CleanupTargetSpec {
            id: "clean.prefetch",
            name: "Prefetch Cache",
            path: windows.join("Prefetch").to_string_lossy().into(),
            safety: "green",
        },
        CleanupTargetSpec {
            id: "clean.thumbnails",
            name: "Thumbnail Cache",
            path: local
                .as_ref()
                .map(|p| p.join(r"Microsoft\Windows\Explorer"))
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            safety: "green",
        },
        CleanupTargetSpec {
            id: "clean.error_reports",
            name: "Error Reports",
            path: local
                .as_ref()
                .map(|p| p.join(r"Microsoft\Windows\WER"))
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            safety: "green",
        },
        CleanupTargetSpec {
            id: "clean.wu_cache",
            name: "Windows Update Cache",
            path: windows
                .join(r"SoftwareDistribution\Download")
                .to_string_lossy()
                .into(),
            safety: "yellow",
        },
        CleanupTargetSpec {
            id: "clean.delivery_opt",
            name: "Delivery Optimization",
            path: windows
                .join(r"SoftwareDistribution\DeliveryOptimization")
                .to_string_lossy()
                .into(),
            safety: "yellow",
        },
    ]
}

#[cfg(target_os = "windows")]
pub fn scan_targets() -> Vec<CleanupTarget> {
    target_specs()
        .into_iter()
        .map(|target| {
            let measurement = measure_dir(&target.path);
            let (size, count, scan_error, scan_warning) = match measurement {
                Ok(measurement) => {
                    let warning = (measurement.skipped_items > 0).then(|| {
                        format!(
                            "Size estimate is partial; {} inaccessible or linked item(s) were skipped.",
                            measurement.skipped_items
                        )
                    });
                    (measurement.size_bytes, measurement.file_count, None, warning)
                }
                Err(error) => (0, 0, Some(error), None),
            };
            CleanupTarget {
                id: target.id.to_string(),
                name: target.name.to_string(),
                path: target.path,
                size_bytes: size,
                file_count: count,
                safety: target.safety.to_string(),
                scan_error,
                scan_warning,
            }
        })
        .collect()
}

#[cfg(not(target_os = "windows"))]
pub fn scan_targets() -> Vec<CleanupTarget> {
    Vec::new()
}

#[cfg(target_os = "windows")]
fn measure_dir(path: &str) -> Result<DirectoryMeasurement, String> {
    use std::path::Path;

    let Some(root) = secure_cleanup::open_root(Path::new(path))? else {
        return Ok(DirectoryMeasurement::default());
    };
    secure_cleanup::measure_tree(root)
}

#[cfg(target_os = "windows")]
pub fn clean_targets(ids: &[String]) -> Vec<CleanupResult> {
    let all = target_specs();
    let mut results = Vec::new();

    for id in ids {
        if let Some(target) = all.iter().find(|target| target.id == id) {
            match clean_directory(&target.path) {
                Ok(outcome) => results.push(CleanupResult {
                    id: id.clone(),
                    success: true,
                    partial: outcome.skipped_items > 0,
                    message: outcome.message(),
                    freed_bytes: outcome.freed_bytes,
                    deleted_files: outcome.deleted_files,
                    skipped_items: outcome.skipped_items,
                }),
                Err(message) => results.push(CleanupResult {
                    id: id.clone(),
                    success: false,
                    partial: false,
                    message,
                    freed_bytes: 0,
                    deleted_files: 0,
                    skipped_items: 0,
                }),
            }
        } else {
            results.push(CleanupResult {
                id: id.clone(),
                success: false,
                partial: false,
                message: "Unknown cleanup target.".into(),
                freed_bytes: 0,
                deleted_files: 0,
                skipped_items: 0,
            });
        }
    }
    results
}

#[cfg(not(target_os = "windows"))]
pub fn clean_targets(_ids: &[String]) -> Vec<CleanupResult> {
    Vec::new()
}

#[cfg(target_os = "windows")]
#[derive(Debug, Default)]
struct CleanOutcome {
    freed_bytes: u64,
    deleted_files: u64,
    skipped_items: u64,
    root_missing: bool,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Default)]
struct DirectoryMeasurement {
    size_bytes: u64,
    file_count: u64,
    skipped_items: u64,
}

#[cfg(target_os = "windows")]
impl CleanOutcome {
    fn message(&self) -> String {
        if self.root_missing {
            return "Already clean (folder does not exist).".into();
        }

        let cleaned = format_cleanup_bytes(self.freed_bytes);
        if self.skipped_items == 0 {
            return format!("Cleaned {cleaned}");
        }

        let noun = if self.skipped_items == 1 {
            "item"
        } else {
            "items"
        };
        format!(
            "Cleaned {cleaned}; skipped {} in-use, protected, or linked {noun}.",
            self.skipped_items
        )
    }
}

#[cfg(target_os = "windows")]
fn format_cleanup_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;

    if bytes >= GIB {
        format!("{:.1} GB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{} MB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{} KB", bytes / KIB)
    } else if bytes == 0 {
        "0 MB".into()
    } else {
        format!("{bytes} bytes")
    }
}

#[cfg(target_os = "windows")]
fn clean_directory(path: &str) -> Result<CleanOutcome, String> {
    use std::path::Path;

    let root = match secure_cleanup::open_root(Path::new(path))? {
        Some(root) => root,
        None => {
            return Ok(CleanOutcome {
                root_missing: true,
                ..CleanOutcome::default()
            });
        }
    };
    secure_cleanup::clean_tree(root)
}

#[cfg(target_os = "windows")]
mod secure_cleanup {
    use super::CleanOutcome;
    use std::ffi::{OsStr, OsString};
    use std::io;
    use std::mem::{offset_of, size_of};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::{Component, Path, Prefix};
    use std::ptr::{null, null_mut};
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_DIRECTORY_FILE, FILE_ID_BOTH_DIR_INFORMATION, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
        FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, FileIdBothDirectoryInformation,
        NtCreateFile, NtQueryDirectoryFile,
    };
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_DIRECTORY, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, HANDLE,
        INVALID_HANDLE_VALUE, RtlNtStatusToDosError, STATUS_NO_MORE_FILES, UNICODE_STRING,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_ATTRIBUTE_TAG_INFO, FILE_DISPOSITION_FLAG_DELETE,
        FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE, FILE_DISPOSITION_INFO_EX,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_STANDARD_INFO, FileAttributeTagInfo, FileDispositionInfoEx, FileStandardInfo,
        GetFileInformationByHandleEx, OPEN_EXISTING, SYNCHRONIZE, SetFileInformationByHandle,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
    use windows_sys::Win32::System::Kernel::OBJ_CASE_INSENSITIVE;

    const DIRECTORY_BUFFER_SIZE: usize = 64 * 1024;
    const MAX_PENDING_DIRECTORIES: usize = 8_192;
    const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    const DIRECTORY_ACCESS: u32 = FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    const CHILD_DIRECTORY_ACCESS: u32 = DIRECTORY_ACCESS | DELETE;
    const TRAVERSE_ACCESS: u32 = FILE_READ_ATTRIBUTES;
    const FILE_ACCESS: u32 = DELETE | FILE_READ_ATTRIBUTES;

    pub(super) struct OwnedHandle(HANDLE);

    impl OwnedHandle {
        fn raw(&self) -> HANDLE {
            self.0
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    #[derive(Clone, Copy)]
    enum EntryKind {
        Directory,
        File,
    }

    struct DirectoryEntry {
        name: Vec<u16>,
        attributes: u32,
    }

    pub(super) fn open_root(path: &Path) -> Result<Option<OwnedHandle>, String> {
        let (drive, components) = parse_absolute_drive_path(path)?;
        let drive_path = format!("{}:\\", char::from(drive));
        let drive_wide = nul_terminated(OsStr::new(&drive_path));
        let raw = unsafe {
            CreateFileW(
                drive_wide.as_ptr(),
                DIRECTORY_ACCESS,
                SHARE_ALL,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(format!(
                "Could not open the cleanup drive: {}",
                io::Error::last_os_error()
            ));
        }

        let mut current = OwnedHandle(raw);
        validate_kind(&current, EntryKind::Directory)
            .map_err(|error| format!("Could not validate the cleanup drive: {error}"))?;
        let last_component = components.len().saturating_sub(1);
        for (index, component) in components.into_iter().enumerate() {
            current = match open_relative(
                &current,
                &component,
                EntryKind::Directory,
                index == last_component,
                false,
            ) {
                Ok(handle) => handle,
                Err(error) if is_missing(&error) => return Ok(None),
                Err(error)
                    if index == last_component
                        && error.raw_os_error() == Some(ERROR_DIRECTORY as i32) =>
                {
                    return Err("Cleanup target exists but is not a directory.".into());
                }
                Err(error) => {
                    return Err(format!(
                        "Could not open cleanup path component '{}' safely: {error}",
                        OsString::from_wide(&component).to_string_lossy()
                    ));
                }
            };
            validate_kind(&current, EntryKind::Directory).map_err(|error| {
                format!("Cleanup target is linked, invalid, or inaccessible: {error}")
            })?;
        }
        Ok(Some(current))
    }

    pub(super) fn clean_tree(root: OwnedHandle) -> Result<CleanOutcome, String> {
        let mut outcome = CleanOutcome::default();
        // The final flag is a post-order marker. Parent handles stay open until
        // every child directory has been emptied and deleted; otherwise a
        // parent containing a nested directory is attempted too early and is
        // never retried.
        let mut pending = vec![(root, true, false)];

        while let Some((directory, is_root, delete_after_children)) = pending.pop() {
            if delete_after_children {
                if !is_root && delete_by_handle(&directory).is_err() {
                    outcome.skipped_items = outcome.skipped_items.saturating_add(1);
                }
                continue;
            }

            let mut restart = true;
            let mut enumerated_any = false;
            let mut child_directories = Vec::new();
            loop {
                let entry = match query_next(&directory, restart) {
                    Ok(Some(entry)) => entry,
                    Ok(None) => break,
                    Err(error) if is_root && !enumerated_any => {
                        return Err(format!("Could not enumerate cleanup folder: {error}"));
                    }
                    Err(_) => {
                        outcome.skipped_items = outcome.skipped_items.saturating_add(1);
                        break;
                    }
                };
                restart = false;
                enumerated_any = true;

                if is_dot_entry(&entry.name) {
                    continue;
                }
                if !is_safe_child_name(&entry.name)
                    || entry.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                {
                    outcome.skipped_items = outcome.skipped_items.saturating_add(1);
                    continue;
                }

                let kind = if entry.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                    EntryKind::Directory
                } else {
                    EntryKind::File
                };
                let child = match open_relative(
                    &directory,
                    &entry.name,
                    kind,
                    true,
                    matches!(kind, EntryKind::Directory),
                ) {
                    Ok(handle) => handle,
                    Err(error) if is_missing(&error) => continue,
                    Err(_) => {
                        outcome.skipped_items = outcome.skipped_items.saturating_add(1);
                        continue;
                    }
                };
                if validate_kind(&child, kind).is_err() {
                    outcome.skipped_items = outcome.skipped_items.saturating_add(1);
                    continue;
                }

                match kind {
                    EntryKind::Directory => {
                        if pending.len().saturating_add(child_directories.len())
                            >= MAX_PENDING_DIRECTORIES
                        {
                            outcome.skipped_items = outcome.skipped_items.saturating_add(1);
                        } else {
                            child_directories.push(child);
                        }
                    }
                    EntryKind::File => {
                        let length = file_length(&child).unwrap_or(0);
                        if delete_by_handle(&child).is_ok() {
                            outcome.deleted_files = outcome.deleted_files.saturating_add(1);
                            outcome.freed_bytes = outcome.freed_bytes.saturating_add(length);
                        } else {
                            outcome.skipped_items = outcome.skipped_items.saturating_add(1);
                        }
                    }
                }
            }
            if !is_root {
                pending.push((directory, false, true));
            }
            for child in child_directories {
                pending.push((child, false, false));
            }
        }

        Ok(outcome)
    }

    pub(super) fn measure_tree(root: OwnedHandle) -> Result<super::DirectoryMeasurement, String> {
        let mut measurement = super::DirectoryMeasurement::default();
        let mut pending = vec![(root, true)];

        while let Some((directory, is_root)) = pending.pop() {
            let mut restart = true;
            let mut enumerated_any = false;
            loop {
                let entry = match query_next(&directory, restart) {
                    Ok(Some(entry)) => entry,
                    Ok(None) => break,
                    Err(error) if is_root && !enumerated_any => {
                        return Err(format!("Could not enumerate cleanup folder: {error}"));
                    }
                    Err(_) => {
                        measurement.skipped_items = measurement.skipped_items.saturating_add(1);
                        break;
                    }
                };
                restart = false;
                enumerated_any = true;

                if is_dot_entry(&entry.name) {
                    continue;
                }
                if !is_safe_child_name(&entry.name)
                    || entry.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                {
                    measurement.skipped_items = measurement.skipped_items.saturating_add(1);
                    continue;
                }

                let kind = if entry.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                    EntryKind::Directory
                } else {
                    EntryKind::File
                };
                let child = match open_relative(&directory, &entry.name, kind, true, false) {
                    Ok(handle) => handle,
                    Err(error) if is_missing(&error) => continue,
                    Err(_) => {
                        measurement.skipped_items = measurement.skipped_items.saturating_add(1);
                        continue;
                    }
                };
                if validate_kind(&child, kind).is_err() {
                    measurement.skipped_items = measurement.skipped_items.saturating_add(1);
                    continue;
                }

                match kind {
                    EntryKind::Directory => {
                        if pending.len() >= MAX_PENDING_DIRECTORIES {
                            measurement.skipped_items = measurement.skipped_items.saturating_add(1);
                        } else {
                            pending.push((child, false));
                        }
                    }
                    EntryKind::File => match file_length(&child) {
                        Ok(length) => {
                            measurement.file_count = measurement.file_count.saturating_add(1);
                            measurement.size_bytes = measurement.size_bytes.saturating_add(length);
                        }
                        Err(_) => {
                            measurement.skipped_items = measurement.skipped_items.saturating_add(1);
                        }
                    },
                }
            }
        }

        Ok(measurement)
    }

    fn parse_absolute_drive_path(path: &Path) -> Result<(u8, Vec<Vec<u16>>), String> {
        let mut parts = path.components();
        let drive = match parts.next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(drive) => drive,
                _ => return Err("Cleanup target must be an absolute local drive path.".into()),
            },
            _ => return Err("Cleanup target must be an absolute local drive path.".into()),
        };
        if !matches!(parts.next(), Some(Component::RootDir)) {
            return Err("Cleanup target must be an absolute local drive path.".into());
        }

        let mut components = Vec::new();
        for part in parts {
            let Component::Normal(name) = part else {
                return Err("Cleanup target contains an unsafe path component.".into());
            };
            let wide: Vec<u16> = name.encode_wide().collect();
            if !is_safe_child_name(&wide) {
                return Err("Cleanup target contains an unsafe path component.".into());
            }
            components.push(wide);
        }
        if components.is_empty() {
            return Err("Refusing to clean a drive root.".into());
        }
        Ok((drive.to_ascii_uppercase(), components))
    }

    fn open_relative(
        parent: &OwnedHandle,
        name: &[u16],
        kind: EntryKind,
        enumerate_directory: bool,
        delete_directory: bool,
    ) -> io::Result<OwnedHandle> {
        let byte_length = name
            .len()
            .checked_mul(size_of::<u16>())
            .and_then(|length| u16::try_from(length).ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file name is too long"))?;
        let unicode = UNICODE_STRING {
            Length: byte_length,
            MaximumLength: byte_length,
            Buffer: name.as_ptr().cast_mut(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: parent.raw(),
            ObjectName: &unicode,
            Attributes: OBJ_CASE_INSENSITIVE as u32,
            SecurityDescriptor: null(),
            SecurityQualityOfService: null(),
        };
        let mut handle: HANDLE = null_mut();
        let mut status_block: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
        let (access, type_option) = match kind {
            EntryKind::Directory if enumerate_directory && delete_directory => {
                (CHILD_DIRECTORY_ACCESS, FILE_DIRECTORY_FILE)
            }
            EntryKind::Directory if enumerate_directory => (DIRECTORY_ACCESS, FILE_DIRECTORY_FILE),
            EntryKind::Directory => (TRAVERSE_ACCESS, FILE_DIRECTORY_FILE),
            EntryKind::File => (FILE_ACCESS, FILE_NON_DIRECTORY_FILE),
        };
        let synchronous = matches!(kind, EntryKind::Directory) && enumerate_directory;
        let options = type_option
            | FILE_OPEN_REPARSE_POINT
            | if synchronous {
                FILE_SYNCHRONOUS_IO_NONALERT
            } else {
                0
            };
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                access,
                &attributes,
                &mut status_block,
                null(),
                0,
                SHARE_ALL,
                FILE_OPEN,
                options,
                null(),
                0,
            )
        };
        if status < 0 {
            let code = unsafe { RtlNtStatusToDosError(status) };
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::other("Windows returned an invalid file handle"));
        }
        Ok(OwnedHandle(handle))
    }

    fn query_next(directory: &OwnedHandle, restart: bool) -> io::Result<Option<DirectoryEntry>> {
        let mut buffer = vec![0u64; DIRECTORY_BUFFER_SIZE / size_of::<u64>()];
        let mut status_block: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
        let status = unsafe {
            NtQueryDirectoryFile(
                directory.raw(),
                null_mut(),
                None,
                null(),
                &mut status_block,
                buffer.as_mut_ptr().cast(),
                DIRECTORY_BUFFER_SIZE as u32,
                FileIdBothDirectoryInformation,
                1,
                null(),
                u8::from(restart),
            )
        };
        if status == STATUS_NO_MORE_FILES {
            return Ok(None);
        }
        if status < 0 {
            let code = unsafe { RtlNtStatusToDosError(status) };
            return Err(io::Error::from_raw_os_error(code as i32));
        }

        let used = status_block.Information.min(DIRECTORY_BUFFER_SIZE);
        let name_offset = offset_of!(FILE_ID_BOTH_DIR_INFORMATION, FileName);
        if used < name_offset {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows returned a truncated directory entry",
            ));
        }
        let info = buffer.as_ptr().cast::<FILE_ID_BOTH_DIR_INFORMATION>();
        let (attributes, name_length) =
            unsafe { ((*info).FileAttributes, (*info).FileNameLength as usize) };
        if name_length % size_of::<u16>() != 0 || name_length > used - name_offset {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows returned an invalid directory entry name",
            ));
        }
        let name = unsafe {
            std::slice::from_raw_parts(
                std::ptr::addr_of!((*info).FileName).cast::<u16>(),
                name_length / size_of::<u16>(),
            )
            .to_vec()
        };
        Ok(Some(DirectoryEntry { name, attributes }))
    }

    fn validate_kind(handle: &OwnedHandle, expected: EntryKind) -> io::Result<()> {
        let attributes = handle_attributes(handle)?;
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::other("reparse points are not followed"));
        }
        let is_directory = attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        if is_directory != matches!(expected, EntryKind::Directory) {
            return Err(io::Error::other("file type changed while opening"));
        }
        Ok(())
    }

    fn handle_attributes(handle: &OwnedHandle) -> io::Result<u32> {
        let mut info: FILE_ATTRIBUTE_TAG_INFO = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            GetFileInformationByHandleEx(
                handle.raw(),
                FileAttributeTagInfo,
                (&mut info as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
                size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
        };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(info.FileAttributes)
        }
    }

    fn file_length(handle: &OwnedHandle) -> io::Result<u64> {
        let mut info: FILE_STANDARD_INFO = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            GetFileInformationByHandleEx(
                handle.raw(),
                FileStandardInfo,
                (&mut info as *mut FILE_STANDARD_INFO).cast(),
                size_of::<FILE_STANDARD_INFO>() as u32,
            )
        };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(info.EndOfFile.max(0) as u64)
        }
    }

    fn delete_by_handle(handle: &OwnedHandle) -> io::Result<()> {
        let disposition = FILE_DISPOSITION_INFO_EX {
            Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
        };
        let ok = unsafe {
            SetFileInformationByHandle(
                handle.raw(),
                FileDispositionInfoEx,
                (&disposition as *const FILE_DISPOSITION_INFO_EX).cast(),
                size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
            )
        };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn nul_terminated(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }

    fn is_missing(error: &io::Error) -> bool {
        matches!(
            error.raw_os_error(),
            Some(code) if code == ERROR_FILE_NOT_FOUND as i32 || code == ERROR_PATH_NOT_FOUND as i32
        )
    }

    fn is_dot_entry(name: &[u16]) -> bool {
        name == [b'.' as u16] || name == [b'.' as u16, b'.' as u16]
    }

    fn is_safe_child_name(name: &[u16]) -> bool {
        !name.is_empty()
            && !is_dot_entry(name)
            && !name.iter().any(|unit| matches!(*unit, 0 | 47 | 58 | 92))
            && OsString::from_wide(name)
                .encode_wide()
                .eq(name.iter().copied())
    }
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::os::windows::fs::{OpenOptionsExt, symlink_dir};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let id = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("cove-cleanup-{label}-{}-{id}", std::process::id()));
            fs::create_dir(&path).expect("create isolated cleanup test directory");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn clean(path: &Path) -> Result<CleanOutcome, String> {
        clean_directory(&path.to_string_lossy())
    }

    #[test]
    fn missing_directory_is_an_idempotent_noop() {
        let test_directory = TestDirectory::new("missing");
        let outcome = clean(&test_directory.path().join("not-created")).unwrap();

        assert!(outcome.root_missing);
        assert_eq!(outcome.deleted_files, 0);
        assert_eq!(outcome.skipped_items, 0);
        assert_eq!(outcome.message(), "Already clean (folder does not exist).");
    }

    #[test]
    fn empty_directory_cleans_zero_bytes() {
        let test_directory = TestDirectory::new("empty");
        let outcome = clean(test_directory.path()).unwrap();

        assert!(!outcome.root_missing);
        assert_eq!(outcome.freed_bytes, 0);
        assert_eq!(outcome.deleted_files, 0);
        assert_eq!(outcome.skipped_items, 0);
        assert_eq!(outcome.message(), "Cleaned 0 MB");
    }

    #[test]
    fn measurement_skips_locked_children_but_keeps_partial_totals() {
        let test_directory = TestDirectory::new("measure-locked");
        let locked_path = test_directory.path().join("locked.tmp");
        let readable_path = test_directory.path().join("readable.tmp");
        fs::write(&locked_path, b"locked").unwrap();
        fs::write(&readable_path, b"read me").unwrap();
        let locked_file = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&locked_path)
            .unwrap();

        let root = secure_cleanup::open_root(test_directory.path())
            .unwrap()
            .unwrap();
        let measurement = secure_cleanup::measure_tree(root).unwrap();

        assert_eq!(measurement.file_count, 1);
        assert_eq!(measurement.size_bytes, 7);
        assert_eq!(measurement.skipped_items, 1);

        drop(locked_file);
    }

    #[test]
    fn locked_child_does_not_abort_other_deletions() {
        let test_directory = TestDirectory::new("locked");
        let locked_path = test_directory.path().join("locked.tmp");
        let removable_path = test_directory.path().join("removable.tmp");
        fs::write(&locked_path, b"locked").unwrap();
        fs::write(&removable_path, b"remove me").unwrap();
        let locked_file = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&locked_path)
            .unwrap();

        let outcome = clean(test_directory.path()).unwrap();

        assert!(locked_path.exists());
        assert!(!removable_path.exists());
        assert_eq!(outcome.deleted_files, 1);
        assert_eq!(outcome.freed_bytes, 9);
        assert_eq!(outcome.skipped_items, 1);
        assert!(outcome.message().contains("skipped 1"));

        drop(locked_file);
    }

    #[test]
    fn file_root_is_rejected() {
        let test_directory = TestDirectory::new("file-root");
        let file_path = test_directory.path().join("not-a-directory.tmp");
        fs::write(&file_path, b"keep me").unwrap();

        let error = clean(&file_path).unwrap_err();

        assert_eq!(error, "Cleanup target exists but is not a directory.");
        assert!(file_path.exists());
    }

    #[test]
    fn linked_root_is_never_followed() {
        let target = TestDirectory::new("linked-target");
        let link_container = TestDirectory::new("linked-root");
        let linked_root = link_container.path().join("redirected-temp");
        let protected_file = target.path().join("must-remain.tmp");
        fs::write(&protected_file, b"keep me").unwrap();
        if symlink_dir(target.path(), &linked_root).is_err() {
            // Creating symlinks requires Developer Mode or the symlink privilege.
            return;
        }

        let error = clean(&linked_root).unwrap_err();

        assert!(!error.is_empty());
        assert!(protected_file.exists());
        let _ = fs::remove_dir(&linked_root);
    }

    #[test]
    fn opened_root_handle_cannot_be_redirected_by_a_path_swap() {
        let container = TestDirectory::new("root-swap");
        let outside = TestDirectory::new("root-swap-outside");
        let original = container.path().join("target");
        let renamed = container.path().join("renamed-target");
        fs::create_dir(&original).unwrap();
        let original_file = original.join("delete-me.tmp");
        let outside_file = outside.path().join("must-remain.tmp");
        fs::write(&original_file, b"remove me").unwrap();
        fs::write(&outside_file, b"keep me").unwrap();

        let root = secure_cleanup::open_root(&original).unwrap().unwrap();
        fs::rename(&original, &renamed).unwrap();
        if symlink_dir(outside.path(), &original).is_err() {
            return;
        }

        let outcome = secure_cleanup::clean_tree(root).unwrap();

        assert_eq!(outcome.deleted_files, 1);
        assert!(!renamed.join("delete-me.tmp").exists());
        assert!(outside_file.exists());
        let _ = fs::remove_dir(&original);
    }

    #[test]
    fn linked_child_is_skipped_without_touching_its_target() {
        let root = TestDirectory::new("linked-child");
        let outside = TestDirectory::new("linked-child-outside");
        let link = root.path().join("redirected-child");
        let removable_file = root.path().join("remove-me.tmp");
        let outside_file = outside.path().join("must-remain.tmp");
        fs::write(&removable_file, b"remove me").unwrap();
        fs::write(&outside_file, b"keep me").unwrap();
        if symlink_dir(outside.path(), &link).is_err() {
            // Creating symlinks requires Developer Mode or the symlink privilege.
            return;
        }

        let outcome = clean(root.path()).unwrap();

        assert_eq!(outcome.deleted_files, 1);
        assert_eq!(outcome.skipped_items, 1);
        assert!(!removable_file.exists());
        assert!(outside_file.exists());
        assert!(link.exists());
        let _ = fs::remove_dir(&link);
    }

    #[test]
    fn literal_special_character_path_is_cleaned() {
        let test_directory = TestDirectory::new("special-path");
        let special_directory = test_directory.path().join("O'Brien [cache]");
        let nested_directory = special_directory.join("nested");
        let deep_directory = nested_directory.join("deeper");
        fs::create_dir_all(&deep_directory).unwrap();
        fs::write(special_directory.join("one.tmp"), b"1234").unwrap();
        fs::write(deep_directory.join("two.tmp"), b"56789").unwrap();

        let outcome = clean(&special_directory).unwrap();

        assert_eq!(outcome.deleted_files, 2);
        assert_eq!(outcome.freed_bytes, 9);
        assert_eq!(outcome.skipped_items, 0);
        assert!(!special_directory.join("one.tmp").exists());
        assert!(!nested_directory.exists());
    }

    #[test]
    fn unknown_target_is_rejected_without_scanning() {
        let results = clean_targets(&["clean.not_real".to_string()]);

        assert_eq!(results.len(), 1);
        assert!(!results[0].success);
        assert_eq!(results[0].message, "Unknown cleanup target.");
    }

    #[test]
    fn cleanup_byte_format_is_readable() {
        assert_eq!(format_cleanup_bytes(0), "0 MB");
        assert_eq!(format_cleanup_bytes(512), "512 bytes");
        assert_eq!(format_cleanup_bytes(2048), "2 KB");
        assert_eq!(format_cleanup_bytes(3 * 1024 * 1024), "3 MB");
        assert_eq!(format_cleanup_bytes(1536 * 1024 * 1024), "1.5 GB");
    }
}
