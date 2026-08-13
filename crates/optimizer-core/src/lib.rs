pub mod storage;
pub mod support_logs;
pub mod types;

/// Resolve Windows inbox executables from the trusted system directory.
/// Elevated maintenance commands must not search the application directory.
#[cfg(target_os = "windows")]
pub fn windows_directory() -> std::path::PathBuf {
    use std::os::windows::ffi::OsStringExt;
    let mut buffer = vec![0u16; 32_768];
    let length = unsafe {
        windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW(
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        )
    } as usize;
    if length > 0 && length < buffer.len() {
        buffer.truncate(length);
        return std::ffi::OsString::from_wide(&buffer).into();
    }
    std::path::PathBuf::from(r"C:\Windows")
}

#[cfg(not(target_os = "windows"))]
pub fn windows_directory() -> std::path::PathBuf {
    std::path::PathBuf::from("/")
}

/// Resolve the machine's Program Files directory through the Windows Known
/// Folder API. Do not use the inherited `ProgramFiles` environment variable to
/// locate executables from an elevated process: a caller-controlled environment
/// can redirect it to a user-writable directory.
#[cfg(target_os = "windows")]
pub fn program_files_directory() -> Option<std::path::PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
    };

    let mut raw = std::ptr::null_mut();
    let status = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_ProgramFiles,
            KF_FLAG_DEFAULT as u32,
            std::ptr::null_mut(),
            &mut raw,
        )
    };
    if status < 0 || raw.is_null() {
        return None;
    }
    let path = unsafe {
        let length = (0..).take_while(|&index| *raw.add(index) != 0).count();
        let path = std::ffi::OsString::from_wide(std::slice::from_raw_parts(raw, length)).into();
        CoTaskMemFree(raw.cast());
        path
    };
    Some(path)
}

#[cfg(not(target_os = "windows"))]
pub fn program_files_directory() -> Option<std::path::PathBuf> {
    None
}

#[cfg(target_os = "windows")]
pub fn system_executable(program: &str) -> std::path::PathBuf {
    use std::path::Path;

    let path = Path::new(program);
    if path.components().count() != 1 {
        return path.to_path_buf();
    }
    let windows = windows_directory();
    if program.eq_ignore_ascii_case("powershell") || program.eq_ignore_ascii_case("powershell.exe")
    {
        return windows
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
    }
    let mut name = program.to_owned();
    if Path::new(&name).extension().is_none() {
        name.push_str(".exe");
    }
    windows.join("System32").join(name)
}

#[cfg(not(target_os = "windows"))]
pub fn system_executable(program: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(program)
}

pub fn silent_cmd(program: &str) -> std::process::Command {
    let mut cmd = std::process::Command::new(system_executable(program));
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    cmd
}

/// Decode output emitted by native console programs using the active OEM code
/// page. PowerShell output should keep using UTF-8 via [`PS_PRELUDE`].
#[cfg(target_os = "windows")]
pub fn decode_console_output(bytes: &[u8]) -> String {
    use windows_sys::Win32::Globalization::{GetOEMCP, MultiByteToWideChar};
    if bytes.is_empty() {
        return String::new();
    }
    let code_page = unsafe { GetOEMCP() };
    let needed = unsafe {
        MultiByteToWideChar(
            code_page,
            0,
            bytes.as_ptr(),
            bytes.len() as i32,
            std::ptr::null_mut(),
            0,
        )
    };
    if needed <= 0 {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let mut wide = vec![0u16; needed as usize];
    let written = unsafe {
        MultiByteToWideChar(
            code_page,
            0,
            bytes.as_ptr(),
            bytes.len() as i32,
            wide.as_mut_ptr(),
            needed,
        )
    };
    if written <= 0 {
        String::from_utf8_lossy(bytes).into_owned()
    } else {
        String::from_utf16_lossy(&wide[..written as usize])
    }
}

#[cfg(not(target_os = "windows"))]
pub fn decode_console_output(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Prelude prepended to every PowerShell `-Command` script so its stdout is
/// emitted as UTF-8 regardless of the machine's active code page. Without this,
/// non-English Windows (CP-1252, GBK, Shift-JIS, ...) and accented usernames
/// produce mojibake that breaks JSON/text parsing. PowerShell 5.1 safe.
pub const PS_PRELUDE: &str = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;$OutputEncoding=[System.Text.Encoding]::UTF8;";

/// Build a `powershell` command pre-seeded with `-NoProfile -NonInteractive
/// -Command`, with [`PS_PRELUDE`] prepended to `script` so output is UTF-8 on
/// any locale. Callers add `.output()`/`.spawn()` as before.
///
/// For the rare call site that needs extra flags before `-Command` (e.g.
/// `-ExecutionPolicy Bypass`), build the command manually and prepend
/// [`PS_PRELUDE`] to the script string instead.
pub fn powershell(script: &str) -> std::process::Command {
    let mut cmd = silent_cmd("powershell");
    let full = format!("{PS_PRELUDE}{script}");
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", &full]);
    cmd
}
