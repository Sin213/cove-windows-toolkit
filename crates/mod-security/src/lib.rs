use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct DefenderStatus {
    pub real_time_enabled: bool,
    pub definitions_age_days: u32,
    pub last_scan: String,
    pub last_scan_type: String,
    /// False when the Defender query failed, so the UI shows "Unknown" instead of
    /// fabricating a reassuring "Protection ON / Up to date".
    pub known: bool,
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
    pub threats_found: Option<u32>,
    pub message: String,
}

#[derive(Serialize)]
pub struct HeuristicResult {
    pub complete: bool,
    pub errors: Vec<String>,
    pub findings: Vec<HeuristicFinding>,
    pub scan_time_ms: u64,
}

#[cfg(target_os = "windows")]
pub fn get_defender_status() -> DefenderStatus {
    let ps = r#"
try {
    $s = Get-MpComputerStatus -ErrorAction Stop
    $age = ((Get-Date) - $s.AntivirusSignatureLastUpdated).Days
    if ($age -lt 0) { throw 'Defender signature timestamp is in the future' }
    if (-not $s.LastQuickScanEndTime -and -not $s.LastFullScanEndTime) { $scanTime='Never'; $scanType='None' }
    elseif ($s.LastQuickScanEndTime -gt $s.LastFullScanEndTime) { $scanTime=$s.LastQuickScanEndTime.ToString('o'); $scanType='Quick' }
    else { $scanTime=$s.LastFullScanEndTime.ToString('o'); $scanType='Full' }
    Write-Output "OK|$($s.RealTimeProtectionEnabled)|$age|$scanTime|$scanType"
} catch {
    Write-Output 'ERR'
}
"#;

    if let Ok(o) = optimizer_core::powershell(ps).output() {
        let stdout = String::from_utf8_lossy(&o.stdout).trim().to_string();
        let parts: Vec<&str> = stdout.split('|').collect();
        if parts.len() >= 5 && parts[0] == "OK" {
            return DefenderStatus {
                real_time_enabled: parts[1].eq_ignore_ascii_case("true"),
                definitions_age_days: parts[2].parse().unwrap_or(0),
                last_scan: parts[3].to_string(),
                last_scan_type: parts[4].to_string(),
                known: true,
            };
        }
    }

    // No fabricated fallback: report an honest "unknown" status if the query failed.
    DefenderStatus {
        real_time_enabled: false,
        definitions_age_days: 0,
        last_scan: "Unknown".into(),
        last_scan_type: "Unknown".into(),
        known: false,
    }
}

#[cfg(not(target_os = "windows"))]
pub fn get_defender_status() -> DefenderStatus {
    DefenderStatus {
        real_time_enabled: false,
        definitions_age_days: 0,
        last_scan: "Unknown".into(),
        last_scan_type: "Unknown".into(),
        known: false,
    }
}

#[cfg(target_os = "windows")]
pub fn run_scan(scan_type: &str) -> ScanResult {
    let scan_flag = match scan_type {
        "quick" => "QuickScan",
        "full" => "FullScan",
        _ => {
            return ScanResult {
                success: false,
                threats_found: None,
                message: format!("Unknown scan type: {scan_type}"),
            };
        }
    };

    let ps = format!(
        "try {{ Start-MpScan -ScanType {} -ErrorAction Stop; Write-Output 'OK' }} catch {{ Write-Output \"FAIL|$($_.Exception.Message)\" }}",
        scan_flag
    );

    match optimizer_core::powershell(&ps).output() {
        Ok(o) => {
            let result = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if result == "OK" {
                ScanResult {
                    success: true,
                    threats_found: None,
                    message: format!(
                        "{} scan started. Threat results are not known until Defender finishes.",
                        scan_flag
                    ),
                }
            } else {
                let msg = result.strip_prefix("FAIL|").unwrap_or(&result);
                ScanResult {
                    success: false,
                    threats_found: None,
                    message: msg.to_string(),
                }
            }
        }
        Err(e) => ScanResult {
            success: false,
            threats_found: None,
            message: format!("Failed to start scan: {}", e),
        },
    }
}

#[cfg(not(target_os = "windows"))]
pub fn run_scan(_scan_type: &str) -> ScanResult {
    ScanResult {
        success: true,
        threats_found: None,
        message: "[stub] Scan started; results are unknown.".into(),
    }
}

#[cfg(target_os = "windows")]
pub fn run_heuristics() -> HeuristicResult {
    run_heuristics_with_progress(|_, _, _| {})
}

/// Runs the heuristic checks, invoking `progress(step, total, label)` before each
/// one so callers can show real step-by-step progress.
#[cfg(target_os = "windows")]
pub fn run_heuristics_with_progress<F: FnMut(u32, u32, &str)>(mut progress: F) -> HeuristicResult {
    use std::time::Instant;

    let total = 3u32;
    let start = Instant::now();
    let mut findings = Vec::new();
    let mut errors = Vec::new();

    // Check processes running from temp dirs
    progress(1, total, "Checking processes in temp/download folders…");
    let ps_procs = r#"
Get-Process | Where-Object { $_.Path -and ($_.Path -match '\\Temp\\|\\AppData\\Local\\Temp\\|\\Downloads\\') } |
    Select-Object Id, ProcessName, Path |
    ForEach-Object { Write-Output "$($_.Id)|$($_.ProcessName)|$($_.Path)" }
"#;
    if let Ok(o) = optimizer_core::powershell(ps_procs).output()
        && o.status.success()
    {
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
    } else {
        errors.push("Could not inspect running process paths.".into());
    }

    // Check hosts file modification
    progress(2, total, "Inspecting the hosts file…");
    let hosts_path = optimizer_core::windows_directory().join(r"System32\drivers\etc\hosts");
    if let Ok(bytes) = std::fs::read(&hosts_path) {
        let contents = if bytes.starts_with(&[0xFF, 0xFE]) {
            let words = bytes[2..]
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>();
            String::from_utf16_lossy(&words)
        } else if bytes.starts_with(&[0xFE, 0xFF]) {
            let words = bytes[2..]
                .chunks_exact(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>();
            String::from_utf16_lossy(&words)
        } else {
            String::from_utf8_lossy(&bytes).into_owned()
        };
        let extra_entries: Vec<&str> = contents
            .lines()
            .filter(|l| {
                let trimmed = l.trim();
                !trimmed.is_empty()
                    && !trimmed.starts_with('#')
                    && trimmed != "127.0.0.1       localhost"
                    && trimmed != "::1             localhost"
            })
            .collect();
        if !extra_entries.is_empty() {
            findings.push(HeuristicFinding {
                severity: "Warning".into(),
                title: format!(
                    "Hosts file modified ({} extra entries)",
                    extra_entries.len()
                ),
                detail: extra_entries
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<&str>>()
                    .join("; "),
                category: "integrity".into(),
            });
        }
    } else {
        errors.push(format!(
            "Could not read hosts file at {}.",
            hosts_path.display()
        ));
    }

    // Check browser extension count
    progress(3, total, "Counting browser extensions…");
    let ps_ext = r#"
$count = @{}
foreach ($browser in @(@('Chrome', "$env:LOCALAPPDATA\Google\Chrome\User Data"), @('Edge', "$env:LOCALAPPDATA\Microsoft\Edge\User Data"))) {
  if (Test-Path -LiteralPath $browser[1]) {
    $count[$browser[0]] = @(Get-ChildItem -LiteralPath $browser[1] -Directory -ErrorAction Stop | ForEach-Object {
      $ext = Join-Path $_.FullName 'Extensions'; if (Test-Path -LiteralPath $ext) { Get-ChildItem -LiteralPath $ext -Directory -ErrorAction Stop }
    }).Count
  }
}
$firefox = Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles'
if (Test-Path -LiteralPath $firefox) { $count['Firefox profiles'] = @(Get-ChildItem -LiteralPath $firefox -Directory -ErrorAction Stop | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'extensions.json') }).Count }
$total = ($count.Values | Measure-Object -Sum).Sum
$detail = ($count.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) -join ', '
Write-Output "$total|$detail"
"#;
    if let Ok(o) = optimizer_core::powershell(ps_ext).output()
        && o.status.success()
    {
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
    } else {
        errors.push("Could not enumerate browser profiles and extensions.".into());
    }

    progress(total, total, "Done");
    let elapsed = start.elapsed().as_millis() as u64;
    HeuristicResult {
        complete: errors.is_empty(),
        errors,
        findings,
        scan_time_ms: elapsed,
    }
}

#[cfg(not(target_os = "windows"))]
pub fn run_heuristics() -> HeuristicResult {
    HeuristicResult {
        complete: true,
        errors: Vec::new(),
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

#[cfg(not(target_os = "windows"))]
pub fn run_heuristics_with_progress<F: FnMut(u32, u32, &str)>(mut progress: F) -> HeuristicResult {
    progress(3, 3, "Done");
    run_heuristics()
}
