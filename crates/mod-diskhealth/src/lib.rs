use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Serialize, Clone)]
pub struct DriveHealth {
    pub model: String,
    pub serial: String,
    pub interface_type: String,
    pub media_type: String,
    pub size_bytes: Option<u64>,
    pub status: String,
    pub temperature_c: Option<i32>,
    pub wear_percent: Option<f64>,
    pub read_errors: Option<u64>,
    pub write_errors: Option<u64>,
    pub power_on_hours: Option<u64>,
    pub trim_enabled: bool,
    pub trim_known: bool,
    pub health_rating: String,
}

#[derive(Serialize, Clone)]
pub struct DriveHealthReport {
    pub complete: bool,
    pub errors: Vec<String>,
    pub drives: Vec<DriveHealth>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LargeFile {
    pub path: String,
    pub name: String,
    pub extension: String,
    pub size_bytes: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DiskSpaceReport {
    pub drive: String,
    pub complete: bool,
    pub errors: Vec<String>,
    pub total_bytes: Option<u64>,
    pub free_bytes: Option<u64>,
    pub largest_files: Vec<LargeFile>,
}

#[derive(Serialize, Clone)]
pub struct ChkdskResult {
    pub success: bool,
    pub mode: String,
    pub scheduled_reboot: bool,
    pub message: String,
    pub output: String,
}

#[derive(Serialize, Clone)]
pub struct LastChkdskInfo {
    pub complete: bool,
    pub error: Option<String>,
    pub found: bool,
    pub timestamp: Option<String>,
    pub result_text: Option<String>,
    pub dirty_bit: bool,
    pub dirty_bit_known: bool,
}

pub fn system_drive() -> String {
    #[cfg(target_os = "windows")]
    {
        let value = optimizer_core::windows_directory()
            .to_string_lossy()
            .to_string();
        if let Some(letter) = valid_drive_letter(value.get(..2).unwrap_or("")) {
            return letter.to_string();
        }
    }
    "C".into()
}

// ---------------------------------------------------------------------------
// SMART / SSD health
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RawDriveHealthReport {
    complete: bool,
    #[serde(default)]
    errors: Vec<String>,
    #[serde(default)]
    drives: Vec<RawDriveHealth>,
}

#[derive(Deserialize)]
struct RawDriveHealth {
    #[serde(default)]
    model: String,
    #[serde(default)]
    serial: String,
    #[serde(default)]
    interface_type: String,
    #[serde(default)]
    media_type: String,
    size_bytes: Option<u64>,
    #[serde(default)]
    status: String,
    temperature_c: Option<i32>,
    wear_percent: Option<f64>,
    read_errors: Option<u64>,
    write_errors: Option<u64>,
    power_on_hours: Option<u64>,
}

#[cfg(target_os = "windows")]
pub fn collect_drive_health() -> DriveHealthReport {
    let ps = r#"
$errors = [System.Collections.Generic.List[string]]::new()
$result = [System.Collections.Generic.List[object]]::new()
try {
    $disks = @(Get-PhysicalDisk -ErrorAction Stop)
    foreach ($d in $disks) {
        try {
            $rel = $null
            try { $rel = $d | Get-StorageReliabilityCounter -ErrorAction Stop } catch {}
            $result.Add([pscustomobject]@{
                model = [string]$d.FriendlyName
                serial = [string]$d.SerialNumber
                interface_type = [string]$d.BusType
                media_type = [string]$d.MediaType
                size_bytes = if ($null -ne $d.Size) { [uint64]$d.Size } else { $null }
                status = [string]$d.HealthStatus
                temperature_c = if ($rel -and $null -ne $rel.Temperature) { [int]$rel.Temperature } else { $null }
                wear_percent = if ($rel -and $null -ne $rel.Wear) { [double]$rel.Wear } else { $null }
                read_errors = if ($rel -and $null -ne $rel.ReadErrorsTotal) { [uint64]$rel.ReadErrorsTotal } else { $null }
                write_errors = if ($rel -and $null -ne $rel.WriteErrorsTotal) { [uint64]$rel.WriteErrorsTotal } else { $null }
                power_on_hours = if ($rel -and $null -ne $rel.PowerOnHours) { [uint64]$rel.PowerOnHours } else { $null }
            })
        } catch { $errors.Add("$($d.FriendlyName): $($_.Exception.Message)") }
    }
} catch {
    $errors.Add($_.Exception.Message)
}
[pscustomobject]@{ complete = ($errors.Count -eq 0); errors = @($errors); drives = @($result) } | ConvertTo-Json -Compress -Depth 4
"#;

    let mut report = match optimizer_core::powershell(ps).output() {
        Ok(output) if output.status.success() => {
            match serde_json::from_slice::<RawDriveHealthReport>(&output.stdout) {
                Ok(raw) => DriveHealthReport {
                    complete: raw.complete,
                    errors: raw.errors,
                    drives: raw
                        .drives
                        .into_iter()
                        .map(|drive| {
                            let health_rating = compute_health_rating(
                                &drive.status,
                                drive.wear_percent,
                                drive.read_errors,
                                drive.write_errors,
                                drive.temperature_c,
                            );
                            DriveHealth {
                                model: drive.model,
                                serial: drive.serial,
                                interface_type: drive.interface_type,
                                media_type: drive.media_type,
                                size_bytes: drive.size_bytes,
                                status: drive.status,
                                temperature_c: drive.temperature_c,
                                wear_percent: drive.wear_percent,
                                read_errors: drive.read_errors,
                                write_errors: drive.write_errors,
                                power_on_hours: drive.power_on_hours,
                                trim_enabled: false,
                                trim_known: false,
                                health_rating,
                            }
                        })
                        .collect(),
                },
                Err(error) => DriveHealthReport {
                    complete: false,
                    errors: vec![format!("Could not parse physical-disk data: {error}")],
                    drives: Vec::new(),
                },
            }
        }
        Ok(output) => DriveHealthReport {
            complete: false,
            errors: vec![format!(
                "Physical-disk query failed: {}",
                optimizer_core::decode_console_output(&output.stderr).trim()
            )],
            drives: Vec::new(),
        },
        Err(error) => DriveHealthReport {
            complete: false,
            errors: vec![format!("Could not start physical-disk query: {error}")],
            drives: Vec::new(),
        },
    };

    // Check TRIM status
    if let Ok(o) = optimizer_core::silent_cmd("fsutil")
        .args(["behavior", "query", "DisableDeleteNotify"])
        .output()
    {
        let stdout = optimizer_core::decode_console_output(&o.stdout);
        let trim_enabled = stdout.contains("= 0");
        let trim_known = o.status.success() && (stdout.contains("= 0") || stdout.contains("= 1"));
        for drive in &mut report.drives {
            if drive.media_type.contains("SSD") || drive.interface_type.contains("NVMe") {
                drive.trim_enabled = trim_enabled;
                drive.trim_known = trim_known;
            }
        }
    }

    // No fabricated fallback: if the query returns nothing, report nothing.
    report
}

#[cfg(not(target_os = "windows"))]
pub fn collect_drive_health() -> DriveHealthReport {
    DriveHealthReport {
        complete: true,
        errors: Vec::new(),
        drives: stub_drives(),
    }
}

fn compute_health_rating(
    status: &str,
    wear: Option<f64>,
    read_err: Option<u64>,
    write_err: Option<u64>,
    temp: Option<i32>,
) -> String {
    if status.eq_ignore_ascii_case("Unknown") || status.is_empty() {
        return "Unknown".to_string();
    }
    if !status.eq_ignore_ascii_case("Healthy") {
        return "Critical".to_string();
    }
    if let Some(w) = wear {
        if w >= 90.0 {
            return "Critical".to_string();
        }
        if w >= 70.0 {
            return "Warning".to_string();
        }
    }
    let total_errors = read_err.unwrap_or(0).saturating_add(write_err.unwrap_or(0));
    if total_errors > 100 {
        return "Warning".to_string();
    }
    if let Some(t) = temp
        && t >= 70
    {
        return "Warning".to_string();
    }
    "Good".to_string()
}

// ---------------------------------------------------------------------------
// Disk space breakdown
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
pub fn get_largest_files(drive_letter: &str) -> DiskSpaceReport {
    let Some(letter) = valid_drive_letter(drive_letter) else {
        return DiskSpaceReport {
            drive: drive_letter.to_string(),
            complete: false,
            errors: vec!["Invalid drive. Select a local drive letter.".into()],
            total_bytes: None,
            free_bytes: None,
            largest_files: Vec::new(),
        };
    };
    let drive = format!("{letter}:");

    let ps = format!(
        r#"
$errors = [System.Collections.Generic.List[string]]::new()
$drive = Get-PSDrive -Name '{}' -ErrorAction SilentlyContinue
$deadline = [Diagnostics.Stopwatch]::StartNew()
$total = if ($drive) {{ [uint64]($drive.Used + $drive.Free) }} else {{ $null }}
$free = if ($drive) {{ [uint64]$drive.Free }} else {{ $null }}
if (-not $drive) {{ $errors.Add('The selected drive could not be queried.') }}
$top = @()
try {{
    Get-ChildItem -LiteralPath '{}\Users' -Recurse -File -Force -ErrorAction SilentlyContinue -ErrorVariable +scanErrors |
        ForEach-Object {{
            if ($deadline.Elapsed.TotalSeconds -gt 30) {{ throw 'Largest-file scan timed out after 30 seconds' }}
            $top = @($top + $_ | Sort-Object Length -Descending | Select-Object -First 5)
        }}
    foreach ($scanError in $scanErrors) {{ $errors.Add($scanError.Exception.Message) }}
}} catch {{ $errors.Add($_.Exception.Message) }}
$files = @($top | ForEach-Object {{ [pscustomobject]@{{
    path = $_.FullName
    name = $_.Name
    extension = $_.Extension.TrimStart('.').ToUpperInvariant()
    size_bytes = [uint64]$_.Length
}} }})
[pscustomobject]@{{
    drive = '{}:'
    complete = ($errors.Count -eq 0)
    errors = @($errors)
    total_bytes = $total
    free_bytes = $free
    largest_files = $files
}} | ConvertTo-Json -Compress -Depth 4
"#,
        drive.trim_end_matches(':'),
        drive,
        letter,
    );
    match optimizer_core::powershell(&ps).output() {
        Ok(output) if output.status.success() => serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| DiskSpaceReport {
                drive,
                complete: false,
                errors: vec![format!("Could not parse disk-space data: {error}")],
                total_bytes: None,
                free_bytes: None,
                largest_files: Vec::new(),
            }),
        Ok(output) => DiskSpaceReport {
            drive,
            complete: false,
            errors: vec![format!(
                "Disk-space query failed: {}",
                optimizer_core::decode_console_output(&output.stderr).trim()
            )],
            total_bytes: None,
            free_bytes: None,
            largest_files: Vec::new(),
        },
        Err(error) => DiskSpaceReport {
            drive,
            complete: false,
            errors: vec![format!("Could not start disk-space query: {error}")],
            total_bytes: None,
            free_bytes: None,
            largest_files: Vec::new(),
        },
    }
}

#[cfg(not(target_os = "windows"))]
pub fn get_largest_files(drive_letter: &str) -> DiskSpaceReport {
    stub_disk_space(drive_letter)
}

// ---------------------------------------------------------------------------
// chkdsk
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
pub fn run_chkdsk(mode: &str, drive: &str) -> ChkdskResult {
    let Some(letter) = valid_drive_letter(drive) else {
        return ChkdskResult {
            success: false,
            mode: mode.into(),
            scheduled_reboot: false,
            message: "Invalid drive. Select a local drive letter.".into(),
            output: String::new(),
        };
    };
    let drive_arg = format!("{letter}:");

    match mode {
        "scan" => {
            let output = optimizer_core::silent_cmd("chkdsk")
                .args([&drive_arg, "/scan"])
                .output();
            match output {
                Ok(o) => {
                    let stdout = optimizer_core::decode_console_output(&o.stdout);
                    let stderr = optimizer_core::decode_console_output(&o.stderr);
                    let combined = if stderr.is_empty() {
                        stdout.clone()
                    } else {
                        format!("{}\n{}", stdout, stderr)
                    };
                    let code = o.status.code().unwrap_or(3);
                    ChkdskResult {
                        success: (0..=2).contains(&code),
                        mode: "scan".into(),
                        scheduled_reboot: false,
                        message: match code {
                            0 => "Online scan completed; no errors were found.".into(),
                            1 => "Online scan completed; errors were found and fixed.".into(),
                            2 => {
                                "Online scan completed, but some cleanup was not performed.".into()
                            }
                            _ => {
                                "The disk could not be checked or errors could not be fixed.".into()
                            }
                        },
                        output: combined,
                    }
                }
                Err(e) => ChkdskResult {
                    success: false,
                    mode: "scan".into(),
                    scheduled_reboot: false,
                    message: format!("Failed to run chkdsk: {}", e),
                    output: String::new(),
                },
            }
        }
        "f" | "r" => {
            let recover = mode == "r";
            let script = format!(
                r#"
$ErrorActionPreference='Stop'
$disk=Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='{}'" -ErrorAction Stop
if (-not $disk) {{ throw 'Logical disk was not found' }}
$result=Invoke-CimMethod -InputObject $disk -MethodName Chkdsk -Arguments @{{
  FixErrors=$true; VigorousIndexCheck=$false; SkipFolderCycle=$false;
  ForceDismount=$false; RecoverBadSectors=${}; OKToRunAtBootUp=$true
}} -ErrorAction Stop
[string]$result.ReturnValue
"#,
                drive_arg,
                if recover { "true" } else { "false" }
            );
            let output = optimizer_core::powershell(&script).output();
            match output {
                Ok(o) => {
                    let stdout = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    let code = stdout
                        .lines()
                        .last()
                        .and_then(|line| line.trim().parse::<u32>().ok());
                    let needs_reboot = code == Some(1);
                    let success = matches!(code, Some(0 | 1));
                    ChkdskResult {
                        success,
                        mode: mode.into(),
                        scheduled_reboot: needs_reboot,
                        message: if needs_reboot {
                            format!("chkdsk /{} scheduled for next reboot.", mode)
                        } else if code == Some(0) {
                            format!("chkdsk /{} completed.", mode)
                        } else {
                            format!(
                                "chkdsk /{} failed (WMI result {}).",
                                mode,
                                code.map_or_else(|| "unknown".into(), |v| v.to_string())
                            )
                        },
                        output: stdout,
                    }
                }
                Err(e) => ChkdskResult {
                    success: false,
                    mode: mode.into(),
                    scheduled_reboot: false,
                    message: format!("Failed to run chkdsk: {}", e),
                    output: String::new(),
                },
            }
        }
        _ => ChkdskResult {
            success: false,
            mode: mode.into(),
            scheduled_reboot: false,
            message: format!("Unknown chkdsk mode: {}", mode),
            output: String::new(),
        },
    }
}

fn valid_drive_letter(value: &str) -> Option<char> {
    let bytes = value.trim().as_bytes();
    if !matches!(bytes.len(), 1 | 2)
        || !bytes[0].is_ascii_alphabetic()
        || (bytes.len() == 2 && bytes[1] != b':')
    {
        return None;
    }
    Some((bytes[0] as char).to_ascii_uppercase())
}

#[cfg(not(target_os = "windows"))]
pub fn run_chkdsk(mode: &str, _drive: &str) -> ChkdskResult {
    ChkdskResult {
        success: true,
        mode: mode.into(),
        scheduled_reboot: false,
        message: format!("[stub] Would run chkdsk /{}", mode),
        output: String::new(),
    }
}

// ---------------------------------------------------------------------------
// Last chkdsk result from Event Log
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
pub fn get_last_chkdsk() -> LastChkdskInfo {
    let ps = r#"
$errors=@()
try { $systemDrive=[IO.Path]::GetPathRoot([Environment]::SystemDirectory).TrimEnd('\'); $disk=Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$systemDrive'" -ErrorAction Stop; $dirty=[bool]$disk.VolumeDirty; $dirtyKnown=$true } catch { $dirty=$false; $dirtyKnown=$false; $errors+=$_.Exception.Message }
try {
    $evt = Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName=@('Wininit','Chkdsk'); Id=@(1001,26214)} -MaxEvents 20 -ErrorAction Stop | Sort-Object TimeCreated -Descending | Select-Object -First 1
    Write-Output "FOUND|$($evt.TimeCreated.ToString('o'))|$(($evt.Message -replace '[\r\n]+',' ').Trim())"
} catch {
    Write-Output 'NOTFOUND'; $errors+=$_.Exception.Message
}
Write-Output "DIRTY|$dirty|$dirtyKnown"
foreach($error in $errors) { Write-Output ('ERR|' + ($error -replace '[\r\n]+',' ')) }
"#;

    let mut info = LastChkdskInfo {
        complete: true,
        error: None,
        found: false,
        timestamp: None,
        result_text: None,
        dirty_bit: false,
        dirty_bit_known: false,
    };

    if let Ok(o) = optimizer_core::powershell(ps).output() {
        let stdout = String::from_utf8_lossy(&o.stdout);
        for line in stdout.lines() {
            if line.starts_with("FOUND|") {
                let parts: Vec<&str> = line.splitn(3, '|').collect();
                if parts.len() == 3 {
                    info.found = true;
                    info.timestamp = Some(parts[1].to_string());
                    info.result_text = Some(parts[2].to_string());
                }
            } else if line.starts_with("DIRTY|") {
                let parts: Vec<_> = line.split('|').collect();
                info.dirty_bit = parts.get(1).is_some_and(|v| v.eq_ignore_ascii_case("true"));
                info.dirty_bit_known = parts.get(2).is_some_and(|v| v.eq_ignore_ascii_case("true"));
            } else if let Some(error) = line.strip_prefix("ERR|") {
                info.complete = false;
                info.error = Some(error.to_string());
            }
        }
    }

    info
}

#[cfg(not(target_os = "windows"))]
pub fn get_last_chkdsk() -> LastChkdskInfo {
    LastChkdskInfo {
        complete: true,
        error: None,
        found: true,
        timestamp: Some("2026-06-01T03:15:00-05:00".into()),
        result_text: Some("Checking file system on C:. Windows has checked the file system and found no problems.".into()),
        dirty_bit: false,
        dirty_bit_known: true,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::valid_drive_letter;

    #[test]
    fn drive_letters_are_strictly_validated() {
        assert_eq!(valid_drive_letter("c"), Some('C'));
        assert_eq!(valid_drive_letter("Z:"), Some('Z'));
        assert_eq!(valid_drive_letter("C: & whoami"), None);
        assert_eq!(valid_drive_letter("C'; calc; #"), None);
        assert_eq!(valid_drive_letter("\\\\server\\share"), None);
    }
}

// ---------------------------------------------------------------------------
// Stubs
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "windows"))]
fn stub_drives() -> Vec<DriveHealth> {
    vec![
        DriveHealth {
            model: "Samsung SSD 980 PRO 1TB".into(),
            serial: "S6B1NJ0T123456".into(),
            interface_type: "NVMe".into(),
            media_type: "SSD".into(),
            size_bytes: Some(1_000_204_886_016),
            status: "Healthy".into(),
            temperature_c: Some(38),
            wear_percent: Some(3.0),
            read_errors: Some(0),
            write_errors: Some(0),
            power_on_hours: Some(8760),
            trim_enabled: true,
            trim_known: true,
            health_rating: "Good".into(),
        },
        DriveHealth {
            model: "WD Blue SN570 500GB".into(),
            serial: "WD-WX42A123456".into(),
            interface_type: "NVMe".into(),
            media_type: "SSD".into(),
            size_bytes: Some(500_107_862_016),
            status: "Healthy".into(),
            temperature_c: Some(35),
            wear_percent: Some(1.0),
            read_errors: Some(0),
            write_errors: Some(0),
            power_on_hours: Some(4380),
            trim_enabled: true,
            trim_known: true,
            health_rating: "Good".into(),
        },
    ]
}

#[cfg(not(target_os = "windows"))]
fn stub_disk_space(drive: &str) -> DiskSpaceReport {
    DiskSpaceReport {
        drive: drive.to_string(),
        complete: true,
        errors: Vec::new(),
        total_bytes: Some(500_000_000_000),
        free_bytes: Some(185_000_000_000),
        largest_files: vec![
            LargeFile {
                name: "Win11_23H2_English_x64.iso".into(),
                extension: "ISO".into(),
                path: format!(
                    "{}\\Users\\CS\\Downloads\\Win11_23H2_English_x64.iso",
                    drive
                ),
                size_bytes: 6_200_000_000,
            },
            LargeFile {
                name: "backup-2026-05.vhdx".into(),
                extension: "VHDX".into(),
                path: format!(
                    "{}\\Users\\CS\\Documents\\Backups\\backup-2026-05.vhdx",
                    drive
                ),
                size_bytes: 4_800_000_000,
            },
            LargeFile {
                name: "gameplay-recording.mp4".into(),
                extension: "MP4".into(),
                path: format!(
                    "{}\\Users\\CS\\Videos\\Captures\\gameplay-recording.mp4",
                    drive
                ),
                size_bytes: 3_100_000_000,
            },
            LargeFile {
                name: "node_modules.tar.gz".into(),
                extension: "GZ".into(),
                path: format!("{}\\Users\\CS\\Downloads\\node_modules.tar.gz", drive),
                size_bytes: 1_800_000_000,
            },
            LargeFile {
                name: "photoshop-scratch.tmp".into(),
                extension: "TMP".into(),
                path: format!(
                    "{}\\Users\\CS\\AppData\\Local\\Temp\\photoshop-scratch.tmp",
                    drive
                ),
                size_bytes: 950_000_000,
            },
        ],
    }
}
