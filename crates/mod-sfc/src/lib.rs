use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub tool: String,
    pub success: bool,
    pub exit_code: i32,
    pub output: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminStatus {
    pub is_admin: bool,
    pub message: String,
}

#[cfg(target_os = "windows")]
pub fn check_admin() -> AdminStatus {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return AdminStatus {
            is_admin: false,
            message: "Could not inspect the process security token.".into(),
        };
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned = 0;
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    } != 0;
    unsafe { CloseHandle(token) };
    if !ok {
        AdminStatus {
            is_admin: false,
            message: "Could not inspect token elevation.".into(),
        }
    } else if elevation.TokenIsElevated != 0 {
        AdminStatus {
            is_admin: true,
            message: "Running with administrator privileges.".into(),
        }
    } else {
        AdminStatus {
            is_admin: false,
            message: "Administrator privileges are required for this repair.".into(),
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn check_admin() -> AdminStatus {
    AdminStatus {
        is_admin: true,
        message: "Admin check (stub -not on Windows).".to_string(),
    }
}

#[cfg(target_os = "windows")]
pub fn run_dism() -> ScanResult {
    let output = optimizer_core::silent_cmd("dism")
        .args(["/online", "/cleanup-image", "/restorehealth"])
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            let combined = if stderr.is_empty() {
                stdout.clone()
            } else {
                format!("{}\n{}", stdout, stderr)
            };
            let code = out.status.code().unwrap_or(-1);
            let summary = parse_dism_summary(&stdout, code);
            ScanResult {
                tool: "DISM".to_string(),
                success: out.status.success(),
                exit_code: code,
                output: combined,
                summary,
            }
        }
        Err(e) => ScanResult {
            tool: "DISM".to_string(),
            success: false,
            exit_code: -1,
            output: format!("Failed to run DISM: {}", e),
            summary: "DISM failed to start.".to_string(),
        },
    }
}

#[cfg(not(target_os = "windows"))]
pub fn run_dism() -> ScanResult {
    ScanResult {
        tool: "DISM".to_string(),
        success: true,
        exit_code: 0,
        output: "[stub] DISM /online /cleanup-image /restorehealth\n\nDeployment Image Servicing and Management tool\nVersion: 10.0.22621.1\n\nImage Version: 10.0.22631.2506\n\n[==========================100.0%==========================]\nThe restore operation completed successfully.\nThe component store is repairable.\n".to_string(),
        summary: "The component store is healthy. No repairs needed.".to_string(),
    }
}

#[cfg(target_os = "windows")]
pub fn run_sfc() -> ScanResult {
    let output = optimizer_core::silent_cmd("sfc")
        .args(["/scannow"])
        .output();

    match output {
        Ok(out) => {
            // sfc.exe writes its output as UTF-16LE; decoding as UTF-8 yields
            // NUL-interleaved garbage that breaks both parsing and display.
            let stdout = decode_utf16le(&out.stdout);
            let stderr = decode_utf16le(&out.stderr);
            let combined = if stderr.is_empty() {
                stdout.clone()
            } else {
                format!("{}\n{}", stdout, stderr)
            };
            let code = out.status.code().unwrap_or(-1);
            let summary = parse_sfc_summary(&stdout, code);
            ScanResult {
                tool: "SFC".to_string(),
                success: out.status.success(),
                exit_code: code,
                output: combined,
                summary,
            }
        }
        Err(e) => ScanResult {
            tool: "SFC".to_string(),
            success: false,
            exit_code: -1,
            output: format!("Failed to run SFC: {}", e),
            summary: "SFC failed to start.".to_string(),
        },
    }
}

#[cfg(not(target_os = "windows"))]
pub fn run_sfc() -> ScanResult {
    ScanResult {
        tool: "SFC".to_string(),
        success: true,
        exit_code: 0,
        output: "[stub] sfc /scannow\n\nBeginning system scan. This process will take some time.\n\nBeginning verification phase of system scan.\nVerification 100% complete.\n\nWindows Resource Protection did not find any integrity violations.\n".to_string(),
        summary: "No integrity violations found.".to_string(),
    }
}

#[cfg(target_os = "windows")]
fn decode_utf16le(bytes: &[u8]) -> String {
    // Heuristic: real UTF-16LE ASCII text has NUL bytes in the high half of each
    // unit. If we see that pattern, decode as UTF-16LE; otherwise fall back to UTF-8.
    let looks_utf16 = bytes.len() >= 2
        && bytes.len().is_multiple_of(2)
        && bytes
            .iter()
            .skip(1)
            .step_by(2)
            .take(16)
            .filter(|&&b| b == 0)
            .count()
            >= 2;
    if looks_utf16 {
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).to_string()
    }
}

#[cfg(target_os = "windows")]
fn parse_dism_summary(output: &str, exit_code: i32) -> String {
    let lower = output.to_lowercase();
    if lower.contains("the component store has been repaired") {
        "Corruption was found and successfully repaired.".to_string()
    } else if lower.contains("the restore operation completed successfully")
        || lower.contains("no component store corruption detected")
    {
        "Component store is healthy. No repairs needed.".to_string()
    } else if lower.contains("the source files could not be found") {
        "Corruption found but repair files are unavailable. Try running Windows Update first."
            .to_string()
    } else if exit_code != 0 {
        format!("DISM completed with errors (exit code {}).", exit_code)
    } else {
        "DISM scan completed.".to_string()
    }
}

#[cfg(target_os = "windows")]
fn parse_sfc_summary(output: &str, exit_code: i32) -> String {
    let lower = output.to_lowercase();
    if lower.contains("did not find any integrity violations") {
        "No integrity violations found.".to_string()
    } else if lower.contains("successfully repaired") {
        "Corrupted files were found and successfully repaired.".to_string()
    } else if lower.contains("found corrupt files but was unable to fix") {
        "Corrupted files found but could not be repaired. Run DISM first, then try SFC again."
            .to_string()
    } else if lower.contains("could not perform the requested operation") {
        "SFC could not run. Try booting into Safe Mode or running from recovery.".to_string()
    } else if exit_code != 0 {
        format!("SFC completed with errors (exit code {}).", exit_code)
    } else {
        "SFC scan completed.".to_string()
    }
}
