use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestorePoint {
    pub sequence_number: u64,
    pub description: String,
    pub restore_point_type: String,
    pub creation_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreStatus {
    pub enabled: bool,
    pub message: String,
}

#[cfg(target_os = "windows")]
pub fn get_restore_status() -> RestoreStatus {
    
    let output = optimizer_core::silent_cmd("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "try { $null = Get-ComputerRestorePoint -ErrorAction Stop; Write-Output 'enabled' } catch { if ($_.Exception.Message -match 'disabled') { Write-Output 'disabled' } else { Write-Output 'enabled' } }",
        ])
        .output();

    match output {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if text == "disabled" {
                RestoreStatus {
                    enabled: false,
                    message: "System Protection is disabled. Enable it in System Properties > System Protection.".to_string(),
                }
            } else {
                RestoreStatus {
                    enabled: true,
                    message: "System Protection is enabled.".to_string(),
                }
            }
        }
        Err(e) => RestoreStatus {
            enabled: false,
            message: format!("Failed to check status: {}", e),
        },
    }
}

#[cfg(not(target_os = "windows"))]
pub fn get_restore_status() -> RestoreStatus {
    RestoreStatus {
        enabled: true,
        message: "System Protection status (stub -not on Windows).".to_string(),
    }
}

#[cfg(target_os = "windows")]
pub fn list_restore_points() -> Vec<RestorePoint> {
    
    let output = optimizer_core::silent_cmd("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-ComputerRestorePoint | Select-Object SequenceNumber, Description, RestorePointType, @{N='CreationTime';E={$_.ConvertToDateTime($_.CreationTime).ToString('o')}} | ConvertTo-Json -Compress",
        ])
        .output();

    match output {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            let trimmed = text.trim();
            if trimmed.is_empty() {
                return Vec::new();
            }
            // PowerShell returns a single object (not array) when there's only one result
            if trimmed.starts_with('[') {
                serde_json::from_str(trimmed).unwrap_or_default()
            } else {
                match serde_json::from_str::<RestorePoint>(trimmed) {
                    Ok(point) => vec![point],
                    Err(_) => Vec::new(),
                }
            }
        }
        Err(_) => Vec::new(),
    }
}

#[cfg(not(target_os = "windows"))]
pub fn list_restore_points() -> Vec<RestorePoint> {
    vec![
        RestorePoint {
            sequence_number: 42,
            description: "Windows Update".to_string(),
            restore_point_type: "Windows Update".to_string(),
            creation_time: "2026-06-08T10:30:00-05:00".to_string(),
        },
        RestorePoint {
            sequence_number: 41,
            description: "Installed Cove Windows Toolkit".to_string(),
            restore_point_type: "Application Install".to_string(),
            creation_time: "2026-06-07T14:15:00-05:00".to_string(),
        },
        RestorePoint {
            sequence_number: 40,
            description: "System Checkpoint".to_string(),
            restore_point_type: "System Checkpoint".to_string(),
            creation_time: "2026-06-05T03:00:00-05:00".to_string(),
        },
    ]
}

#[cfg(target_os = "windows")]
pub fn create_restore_point(description: &str) -> Result<String, String> {
    
    let script = format!(
        "Checkpoint-Computer -Description '{}' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop",
        description.replace('\'', "''")
    );
    let output = optimizer_core::silent_cmd("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .map_err(|e| format!("Failed to run PowerShell: {}", e))?;

    if output.status.success() {
        Ok(format!("Restore point '{}' created successfully.", description))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("frequency") || stderr.contains("1400") {
            Err("Windows limits restore point creation to once every 24 hours. A restore point was already created recently.".to_string())
        } else if stderr.contains("disabled") || stderr.contains("ServiceDisabled") {
            Err("System Protection is disabled for this drive. Enable it in System Properties > System Protection, then try again.".to_string())
        } else {
            Err(format!("Failed to create restore point: {}", stderr.trim()))
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn create_restore_point(description: &str) -> Result<String, String> {
    Ok(format!(
        "[stub] Restore point '{}' would be created on Windows.",
        description
    ))
}

#[cfg(target_os = "windows")]
pub fn enable_system_protection() -> Result<String, String> {
    
    let output = optimizer_core::silent_cmd("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Enable-ComputerRestore -Drive $env:SystemDrive -ErrorAction Stop",
        ])
        .output()
        .map_err(|e| format!("Failed to run PowerShell: {}", e))?;

    if output.status.success() {
        Ok("System Protection enabled on the system drive.".to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Failed to enable System Protection: {}", stderr.trim()))
    }
}

#[cfg(not(target_os = "windows"))]
pub fn enable_system_protection() -> Result<String, String> {
    Ok("[stub] Would enable System Protection on Windows.".to_string())
}

#[cfg(target_os = "windows")]
pub fn launch_system_restore() -> Result<String, String> {
    
    optimizer_core::silent_cmd("rstrui.exe")
        .spawn()
        .map_err(|e| format!("Failed to launch System Restore: {}", e))?;
    Ok("System Restore wizard launched.".to_string())
}

#[cfg(not(target_os = "windows"))]
pub fn launch_system_restore() -> Result<String, String> {
    Ok("[stub] Would launch rstrui.exe on Windows.".to_string())
}
