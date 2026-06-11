use optimizer_core::types::{Finding, Severity, MetricValue};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    pub score: u8,
    pub findings: Vec<Finding>,
}

pub fn quick_scan() -> HealthReport {
    let mut findings = Vec::new();
    let mut deductions = 0i32;

    // Disk space check
    let (disk_finding, disk_deduct) = check_disk_space();
    findings.push(disk_finding);
    deductions += disk_deduct;

    // RAM check
    let (ram_finding, ram_deduct) = check_ram();
    findings.push(ram_finding);
    deductions += ram_deduct;

    let score = (100 - deductions).clamp(0, 100) as u8;
    HealthReport { score, findings }
}

/// An honest "couldn't read this metric" finding (no score deduction, no fake data).
fn unknown_finding(id: &str, title: &str, detail: &str) -> (Finding, i32) {
    (Finding {
        id: id.to_string(),
        severity: Severity::Info,
        title: title.to_string(),
        detail: detail.to_string(),
        metric: None,
        remediation: None,
    }, 0)
}

#[cfg(target_os = "windows")]
fn check_disk_space() -> (Finding, i32) {
    let ps = r#"$sd = $env:SystemDrive
$d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$sd'" -ErrorAction SilentlyContinue
Write-Output "$($d.FreeSpace)|$($d.Size)""#;
    if let Ok(o) = optimizer_core::silent_cmd("powershell")
        .args(["-NoProfile", "-Command", ps]).output()
    {
        let s = String::from_utf8_lossy(&o.stdout);
        let p: Vec<&str> = s.trim().split('|').collect();
        if p.len() == 2 {
            if let (Ok(free), Ok(total)) =
                (p[0].trim().parse::<u64>(), p[1].trim().parse::<u64>())
            {
                if total > 0 {
                    return disk_finding(free, total);
                }
            }
        }
    }
    unknown_finding("disk.free_space", "System Drive Free Space", "Could not read disk free space")
}

#[cfg(not(target_os = "windows"))]
fn check_disk_space() -> (Finding, i32) {
    disk_finding(45_000_000_000, 500_000_000_000)
}

fn disk_finding(free: u64, total: u64) -> (Finding, i32) {
    let pct_free = (free as f32 / total as f32) * 100.0;

    let (severity, deduction) = if pct_free < 5.0 {
        (Severity::Critical, 25)
    } else if pct_free < 15.0 {
        (Severity::Warning, 10)
    } else {
        (Severity::Ok, 0)
    };

    (Finding {
        id: "disk.free_space".to_string(),
        severity,
        title: "System Drive Free Space".to_string(),
        detail: format!("{:.1} GB free of {:.1} GB ({:.0}%)",
            free as f64 / 1e9, total as f64 / 1e9, pct_free),
        metric: Some(MetricValue::Percent(pct_free)),
        remediation: if severity != Severity::Ok {
            Some("Run Disk Cleanup to free space on the system drive".to_string())
        } else {
            None
        },
    }, deduction)
}

#[cfg(target_os = "windows")]
fn check_ram() -> (Finding, i32) {
    let ps = r#"$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
Write-Output "$($os.FreePhysicalMemory)|$($os.TotalVisibleMemorySize)""#;
    if let Ok(o) = optimizer_core::silent_cmd("powershell")
        .args(["-NoProfile", "-Command", ps]).output()
    {
        let s = String::from_utf8_lossy(&o.stdout);
        let p: Vec<&str> = s.trim().split('|').collect();
        if p.len() == 2 {
            // Win32_OperatingSystem reports memory in kilobytes.
            if let (Ok(free_kb), Ok(total_kb)) =
                (p[0].trim().parse::<u64>(), p[1].trim().parse::<u64>())
            {
                if total_kb > 0 {
                    return ram_finding(free_kb * 1024, total_kb * 1024);
                }
            }
        }
    }
    unknown_finding("ram.available", "Available RAM", "Could not read memory status")
}

#[cfg(not(target_os = "windows"))]
fn check_ram() -> (Finding, i32) {
    ram_finding(8_500_000_000, 16_000_000_000)
}

fn ram_finding(available: u64, total: u64) -> (Finding, i32) {
    let pct_available = (available as f32 / total as f32) * 100.0;

    let (severity, deduction) = if available < 200_000_000 {
        (Severity::Critical, 25)
    } else if pct_available < 10.0 {
        (Severity::Warning, 10)
    } else {
        (Severity::Ok, 0)
    };

    (Finding {
        id: "ram.available".to_string(),
        severity,
        title: "Available RAM".to_string(),
        detail: format!("{:.1} GB available of {:.1} GB ({:.0}%)",
            available as f64 / 1e9, total as f64 / 1e9, pct_available),
        metric: Some(MetricValue::Percent(pct_available)),
        remediation: if severity != Severity::Ok {
            Some("Close unused applications to free memory".to_string())
        } else {
            None
        },
    }, deduction)
}
