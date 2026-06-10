use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct DefenderStatus {
    pub real_time_enabled: bool,
    pub definitions_age_days: u32,
    pub last_scan: String,
    pub last_scan_type: String,
}

#[derive(Serialize, Clone)]
pub struct HeuristicFinding {
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub category: String,
}

#[derive(Serialize)]
pub struct SecurityStatus {
    pub defender: DefenderStatus,
    pub heuristic_findings: Vec<HeuristicFinding>,
    pub scan_available: bool,
}

#[derive(Serialize)]
pub struct ScanResult {
    pub success: bool,
    pub threats_found: u32,
    pub message: String,
}

#[derive(Serialize)]
pub struct HeuristicResult {
    pub findings: Vec<HeuristicFinding>,
    pub scan_time_ms: u64,
}

#[cfg(target_os = "windows")]
pub fn get_defender_status() -> DefenderStatus {
    use std::process::Command;

    let ps = r#"
try {
    $s = Get-MpComputerStatus -ErrorAction Stop
    $age = ((Get-Date) - $s.AntivirusSignatureLastUpdated).Days
    $scanTime = if ($s.LastQuickScanEndTime) { $s.LastQuickScanEndTime.ToString('o') } else { 'Never' }
    $scanType = if ($s.LastQuickScanEndTime -gt $s.LastFullScanEndTime) { 'Quick' } else { 'Full' }
    Write-Output "$($s.RealTimeProtectionEnabled)|$age|$scanTime|$scanType"
} catch {
    Write-Output 'True|0|Unknown|Unknown'
}
"#;

    if let Ok(o) = Command::new("powershell").args(["-NoProfile", "-Command", ps]).output() {
        let stdout = String::from_utf8_lossy(&o.stdout).trim().to_string();
        let parts: Vec<&str> = stdout.split('|').collect();
        if parts.len() >= 4 {
            return DefenderStatus {
                real_time_enabled: parts[0].eq_ignore_ascii_case("true"),
                definitions_age_days: parts[1].parse().unwrap_or(0),
                last_scan: parts[2].to_string(),
                last_scan_type: parts[3].to_string(),
            };
        }
    }

    stub_defender()
}

#[cfg(not(target_os = "windows"))]
pub fn get_defender_status() -> DefenderStatus {
    stub_defender()
}

fn stub_defender() -> DefenderStatus {
    DefenderStatus {
        real_time_enabled: true,
        definitions_age_days: 1,
        last_scan: "2026-06-08T14:30:00Z".into(),
        last_scan_type: "Quick".into(),
    }
}

#[cfg(target_os = "windows")]
pub fn run_scan(scan_type: &str) -> ScanResult {
    use std::process::Command;

    let scan_flag = match scan_type {
        "quick" => "-ScanType 1",
        "full" => "-ScanType 2",
        _ => "-ScanType 1",
    };

    let mp_path = r"C:\Program Files\Windows Defender\MpCmdRun.exe";
    let args_str = format!("-Scan {}", scan_flag);
    let args: Vec<&str> = args_str.split_whitespace().collect();

    match Command::new(mp_path).args(&args).output() {
        Ok(o) => {
            let code = o.status.code().unwrap_or(-1);
            match code {
                0 => ScanResult { success: true, threats_found: 0, message: "No threats detected.".into() },
                2 => ScanResult { success: true, threats_found: 1, message: "Threats were found and handled.".into() },
                _ => ScanResult { success: false, threats_found: 0, message: format!("Scan exited with code {}", code) },
            }
        }
        Err(e) => ScanResult { success: false, threats_found: 0, message: format!("Failed to run scan: {}", e) },
    }
}

#[cfg(not(target_os = "windows"))]
pub fn run_scan(_scan_type: &str) -> ScanResult {
    ScanResult {
        success: true,
        threats_found: 0,
        message: "[stub] No threats detected.".into(),
    }
}

#[cfg(target_os = "windows")]
pub fn run_heuristics() -> HeuristicResult {
    use std::process::Command;
    use std::time::Instant;

    let start = Instant::now();
    let mut findings = Vec::new();

    // Check processes running from temp dirs
    let ps_procs = r#"
Get-Process | Where-Object { $_.Path -and ($_.Path -match '\\Temp\\|\\AppData\\Local\\Temp\\|\\Downloads\\') } |
    Select-Object Id, ProcessName, Path |
    ForEach-Object { Write-Output "$($_.Id)|$($_.ProcessName)|$($_.Path)" }
"#;
    if let Ok(o) = Command::new("powershell").args(["-NoProfile", "-Command", ps_procs]).output() {
        let stdout = String::from_utf8_lossy(&o.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.splitn(3, '|').collect();
            if parts.len() == 3 {
                findings.push(HeuristicFinding {
                    severity: "Warning".into(),
                    title: "Process running from temp directory".into(),
                    detail: format!("{} (PID {}) - {}", parts[1], parts[0], parts[2]),
                    category: "process".into(),
                });
            }
        }
    }

    // Check hosts file modification
    let hosts_path = r"C:\Windows\System32\drivers\etc\hosts";
    if let Ok(contents) = std::fs::read_to_string(hosts_path) {
        let extra_entries: Vec<&str> = contents.lines()
            .filter(|l| {
                let trimmed = l.trim();
                !trimmed.is_empty() && !trimmed.starts_with('#') && trimmed != "127.0.0.1       localhost" && trimmed != "::1             localhost"
            })
            .collect();
        if !extra_entries.is_empty() {
            findings.push(HeuristicFinding {
                severity: "Warning".into(),
                title: format!("Hosts file modified ({} extra entries)", extra_entries.len()),
                detail: extra_entries.iter().take(5).cloned().collect::<Vec<&str>>().join("; "),
                category: "integrity".into(),
            });
        }
    }

    // Check browser extension count
    let ps_ext = r#"
$count = @{}
$chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
if (Test-Path $chromePath) { $count['Chrome'] = (Get-ChildItem $chromePath -Directory -ErrorAction SilentlyContinue).Count }
$edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
if (Test-Path $edgePath) { $count['Edge'] = (Get-ChildItem $edgePath -Directory -ErrorAction SilentlyContinue).Count }
$total = ($count.Values | Measure-Object -Sum).Sum
$detail = ($count.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) -join ', '
Write-Output "$total|$detail"
"#;
    if let Ok(o) = Command::new("powershell").args(["-NoProfile", "-Command", ps_ext]).output() {
        let stdout = String::from_utf8_lossy(&o.stdout).trim().to_string();
        let parts: Vec<&str> = stdout.splitn(2, '|').collect();
        if parts.len() == 2 {
            let total: u32 = parts[0].parse().unwrap_or(0);
            if total > 0 {
                let sev = if total > 15 { "Warning" } else { "Info" };
                findings.push(HeuristicFinding {
                    severity: sev.into(),
                    title: format!("{} browser extensions installed", total),
                    detail: parts[1].to_string(),
                    category: "browser".into(),
                });
            }
        }
    }

    let elapsed = start.elapsed().as_millis() as u64;
    HeuristicResult { findings, scan_time_ms: elapsed }
}

#[cfg(not(target_os = "windows"))]
pub fn run_heuristics() -> HeuristicResult {
    HeuristicResult {
        findings: vec![
            HeuristicFinding {
                severity: "Warning".into(),
                title: "Unsigned process with network activity".into(),
                detail: "notepad++.exe (PID 4521) - unsigned, 2 active connections".into(),
                category: "process".into(),
            },
            HeuristicFinding {
                severity: "Info".into(),
                title: "22 browser extensions installed".into(),
                detail: "Chrome: 15, Edge: 7".into(),
                category: "browser".into(),
            },
        ],
        scan_time_ms: 3200,
    }
}
