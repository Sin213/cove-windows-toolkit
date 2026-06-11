use serde::Serialize;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Serialize, Clone)]
pub struct DriveHealth {
    pub model: String,
    pub serial: String,
    pub interface_type: String,
    pub media_type: String,
    pub size_bytes: u64,
    pub status: String,
    pub temperature_c: Option<i32>,
    pub wear_percent: Option<f64>,
    pub read_errors: Option<u64>,
    pub write_errors: Option<u64>,
    pub power_on_hours: Option<u64>,
    pub trim_enabled: bool,
    pub health_rating: String,
}

#[derive(Serialize, Clone)]
pub struct LargeFile {
    pub path: String,
    pub name: String,
    pub extension: String,
    pub size_bytes: u64,
}

#[derive(Serialize, Clone)]
pub struct DiskSpaceReport {
    pub drive: String,
    pub total_bytes: u64,
    pub free_bytes: u64,
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
    pub found: bool,
    pub timestamp: Option<String>,
    pub result_text: Option<String>,
    pub dirty_bit: bool,
}

// ---------------------------------------------------------------------------
// SMART / SSD health
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
pub fn collect_drive_health() -> Vec<DriveHealth> {
    

    let ps = r#"
$disks = Get-PhysicalDisk | Select-Object DeviceId, FriendlyName, SerialNumber, BusType, MediaType, Size, HealthStatus
foreach ($d in $disks) {
    $rel = $null
    try {
        $rel = $d | Get-StorageReliabilityCounter -ErrorAction Stop
    } catch {}
    $temp = if ($rel -and $rel.Temperature) { $rel.Temperature } else { 'NULL' }
    $wear = if ($rel -and $null -ne $rel.Wear) { $rel.Wear } else { 'NULL' }
    $readErr = if ($rel -and $null -ne $rel.ReadErrorsTotal) { $rel.ReadErrorsTotal } else { 'NULL' }
    $writeErr = if ($rel -and $null -ne $rel.WriteErrorsTotal) { $rel.WriteErrorsTotal } else { 'NULL' }
    $poh = if ($rel -and $null -ne $rel.PowerOnHours) { $rel.PowerOnHours } else { 'NULL' }
    Write-Output "$($d.FriendlyName)|$($d.SerialNumber)|$($d.BusType)|$($d.MediaType)|$($d.Size)|$($d.HealthStatus)|$temp|$wear|$readErr|$writeErr|$poh"
}
"#;

    let mut drives = Vec::new();

    if let Ok(o) = optimizer_core::silent_cmd("powershell").args(["-NoProfile", "-Command", ps]).output() {
        let stdout = String::from_utf8_lossy(&o.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() < 11 { continue; }
            let size: u64 = parts[4].trim().parse().unwrap_or(0);
            let temp = parse_opt_i32(parts[6]);
            let wear = parse_opt_f64(parts[7]);
            let read_err = parse_opt_u64(parts[8]);
            let write_err = parse_opt_u64(parts[9]);
            let poh = parse_opt_u64(parts[10]);
            let health_status = parts[5].trim().to_string();
            let media = parts[3].trim().to_string();
            let bus = parts[2].trim().to_string();

            let health_rating = compute_health_rating(&health_status, wear, read_err, write_err, temp);

            drives.push(DriveHealth {
                model: parts[0].trim().to_string(),
                serial: parts[1].trim().to_string(),
                interface_type: bus,
                media_type: media,
                size_bytes: size,
                status: health_status,
                temperature_c: temp,
                wear_percent: wear,
                read_errors: read_err,
                write_errors: write_err,
                power_on_hours: poh,
                trim_enabled: false,
                health_rating,
            });
        }
    }

    // Check TRIM status
    if let Ok(o) = optimizer_core::silent_cmd("fsutil").args(["behavior", "query", "DisableDeleteNotify"]).output() {
        let stdout = String::from_utf8_lossy(&o.stdout);
        let trim_enabled = stdout.contains("= 0");
        for drive in &mut drives {
            if drive.media_type.contains("SSD") || drive.interface_type.contains("NVMe") {
                drive.trim_enabled = trim_enabled;
            }
        }
    }

    // No fabricated fallback: if the query returns nothing, report nothing.
    drives
}

#[cfg(not(target_os = "windows"))]
pub fn collect_drive_health() -> Vec<DriveHealth> {
    stub_drives()
}

fn compute_health_rating(
    status: &str,
    wear: Option<f64>,
    read_err: Option<u64>,
    write_err: Option<u64>,
    temp: Option<i32>,
) -> String {
    if status != "Healthy" {
        return "Critical".to_string();
    }
    if let Some(w) = wear {
        if w >= 90.0 { return "Critical".to_string(); }
        if w >= 70.0 { return "Warning".to_string(); }
    }
    let total_errors = read_err.unwrap_or(0) + write_err.unwrap_or(0);
    if total_errors > 100 { return "Warning".to_string(); }
    if let Some(t) = temp && t >= 70 {
        return "Warning".to_string();
    }
    "Good".to_string()
}

// ---------------------------------------------------------------------------
// Disk space breakdown
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
pub fn get_largest_files(drive_letter: &str) -> DiskSpaceReport {
    

    let drive = if drive_letter.ends_with(':') {
        drive_letter.to_string()
    } else {
        format!("{}:", drive_letter)
    };

    let ps = format!(
        r#"
$drive = Get-PSDrive -Name '{}' -ErrorAction SilentlyContinue
$total = if ($drive) {{ $drive.Used + $drive.Free }} else {{ 0 }}
$free = if ($drive) {{ $drive.Free }} else {{ 0 }}
Write-Output "DRIVE|$total|$free"

Get-ChildItem -Path '{}\Users' -Recurse -File -Force -ErrorAction SilentlyContinue |
    Sort-Object Length -Descending |
    Select-Object -First 5 |
    ForEach-Object {{
        Write-Output "FILE|$($_.Name)|$($_.Extension)|$($_.FullName)|$($_.Length)"
    }}
"#,
        drive.trim_end_matches(':'),
        drive,
    );

    let mut report = DiskSpaceReport {
        drive: drive.clone(),
        total_bytes: 0,
        free_bytes: 0,
        largest_files: Vec::new(),
    };

    if let Ok(o) = optimizer_core::silent_cmd("powershell")
        .args(["-NoProfile", "-Command", &ps])
        .output()
    {
        let stdout = String::from_utf8_lossy(&o.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.splitn(5, '|').collect();
            if parts.len() < 3 { continue; }
            match parts[0] {
                "DRIVE" => {
                    report.total_bytes = parts[1].trim().parse().unwrap_or(0);
                    report.free_bytes = parts[2].trim().parse().unwrap_or(0);
                }
                "FILE" if parts.len() == 5 => {
                    let size: u64 = parts[4].trim().parse().unwrap_or(0);
                    report.largest_files.push(LargeFile {
                        name: parts[1].trim().to_string(),
                        extension: parts[2].trim().trim_start_matches('.').to_uppercase(),
                        path: parts[3].trim().to_string(),
                        size_bytes: size,
                    });
                }
                _ => {}
            }
        }
    }

    // No fabricated fallback: return whatever the real query produced.
    report
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
    

    let drive_arg = if drive.ends_with(':') {
        drive.to_string()
    } else {
        format!("{}:", drive)
    };

    match mode {
        "scan" => {
            let output = optimizer_core::silent_cmd("chkdsk")
                .args([&drive_arg, "/scan"])
                .output();
            match output {
                Ok(o) => {
                    let stdout = String::from_utf8_lossy(&o.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&o.stderr).to_string();
                    let combined = if stderr.is_empty() { stdout.clone() } else { format!("{}\n{}", stdout, stderr) };
                    ChkdskResult {
                        success: o.status.success(),
                        mode: "scan".into(),
                        scheduled_reboot: false,
                        message: if o.status.success() {
                            "Online scan completed.".into()
                        } else {
                            "Scan encountered issues.".into()
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
            let flag = format!("/{}", mode);
            let ps = format!(
                r#"echo Y | chkdsk {} {}"#,
                drive_arg, flag
            );
            let output = optimizer_core::silent_cmd("cmd")
                .args(["/C", &ps])
                .output();
            match output {
                Ok(o) => {
                    let stdout = String::from_utf8_lossy(&o.stdout).to_string();
                    let needs_reboot = stdout.contains("next time the system restarts")
                        || stdout.contains("scheduled")
                        || stdout.contains("dismount");
                    ChkdskResult {
                        success: true,
                        mode: mode.into(),
                        scheduled_reboot: needs_reboot,
                        message: if needs_reboot {
                            format!("chkdsk /{} scheduled for next reboot.", mode)
                        } else {
                            format!("chkdsk /{} completed.", mode)
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
# Check dirty bit on C:
$dirty = $false
try {
    $r = & fsutil dirty query C: 2>&1
    if ($r -match 'is dirty') { $dirty = $true }
} catch {}

# Last chkdsk result from Wininit event log
try {
    $evt = Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Wininit'; Id=1001} -MaxEvents 1 -ErrorAction Stop
    Write-Output "FOUND|$($evt.TimeCreated.ToString('o'))|$($evt.Message)"
} catch {
    try {
        $evt = Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='chkdsk'; Id=26214} -MaxEvents 1 -ErrorAction Stop
        Write-Output "FOUND|$($evt.TimeCreated.ToString('o'))|$($evt.Message)"
    } catch {
        Write-Output 'NOTFOUND'
    }
}
Write-Output "DIRTY|$dirty"
"#;

    let mut info = LastChkdskInfo {
        found: false,
        timestamp: None,
        result_text: None,
        dirty_bit: false,
    };

    if let Ok(o) = optimizer_core::silent_cmd("powershell").args(["-NoProfile", "-Command", ps]).output() {
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
                info.dirty_bit = line.contains("True");
            }
        }
    }

    info
}

#[cfg(not(target_os = "windows"))]
pub fn get_last_chkdsk() -> LastChkdskInfo {
    LastChkdskInfo {
        found: true,
        timestamp: Some("2026-06-01T03:15:00-05:00".into()),
        result_text: Some("Checking file system on C:. Windows has checked the file system and found no problems.".into()),
        dirty_bit: false,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_opt_i32(s: &str) -> Option<i32> {
    let t = s.trim();
    if t == "NULL" || t.is_empty() { None } else { t.parse().ok() }
}

fn parse_opt_f64(s: &str) -> Option<f64> {
    let t = s.trim();
    if t == "NULL" || t.is_empty() { None } else { t.parse().ok() }
}

fn parse_opt_u64(s: &str) -> Option<u64> {
    let t = s.trim();
    if t == "NULL" || t.is_empty() { None } else { t.parse().ok() }
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
            size_bytes: 1_000_204_886_016,
            status: "Healthy".into(),
            temperature_c: Some(38),
            wear_percent: Some(3.0),
            read_errors: Some(0),
            write_errors: Some(0),
            power_on_hours: Some(8760),
            trim_enabled: true,
            health_rating: "Good".into(),
        },
        DriveHealth {
            model: "WD Blue SN570 500GB".into(),
            serial: "WD-WX42A123456".into(),
            interface_type: "NVMe".into(),
            media_type: "SSD".into(),
            size_bytes: 500_107_862_016,
            status: "Healthy".into(),
            temperature_c: Some(35),
            wear_percent: Some(1.0),
            read_errors: Some(0),
            write_errors: Some(0),
            power_on_hours: Some(4380),
            trim_enabled: true,
            health_rating: "Good".into(),
        },
    ]
}

#[cfg(not(target_os = "windows"))]
fn stub_disk_space(drive: &str) -> DiskSpaceReport {
    DiskSpaceReport {
        drive: drive.to_string(),
        total_bytes: 500_000_000_000,
        free_bytes: 185_000_000_000,
        largest_files: vec![
            LargeFile { name: "Win11_23H2_English_x64.iso".into(), extension: "ISO".into(), path: format!("{}\\Users\\CS\\Downloads\\Win11_23H2_English_x64.iso", drive), size_bytes: 6_200_000_000 },
            LargeFile { name: "backup-2026-05.vhdx".into(), extension: "VHDX".into(), path: format!("{}\\Users\\CS\\Documents\\Backups\\backup-2026-05.vhdx", drive), size_bytes: 4_800_000_000 },
            LargeFile { name: "gameplay-recording.mp4".into(), extension: "MP4".into(), path: format!("{}\\Users\\CS\\Videos\\Captures\\gameplay-recording.mp4", drive), size_bytes: 3_100_000_000 },
            LargeFile { name: "node_modules.tar.gz".into(), extension: "GZ".into(), path: format!("{}\\Users\\CS\\Downloads\\node_modules.tar.gz", drive), size_bytes: 1_800_000_000 },
            LargeFile { name: "photoshop-scratch.tmp".into(), extension: "TMP".into(), path: format!("{}\\Users\\CS\\AppData\\Local\\Temp\\photoshop-scratch.tmp", drive), size_bytes: 950_000_000 },
        ],
    }
}
