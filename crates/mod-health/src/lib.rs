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

#[cfg(target_os = "windows")]
fn check_disk_space() -> (Finding, i32) {
    // TODO: Use GetDiskFreeSpaceExW
    stub_disk_check()
}

#[cfg(not(target_os = "windows"))]
fn check_disk_space() -> (Finding, i32) {
    stub_disk_check()
}

fn stub_disk_check() -> (Finding, i32) {
    let total: u64 = 500_000_000_000;
    let free: u64 = 45_000_000_000;
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
    // TODO: Use GlobalMemoryStatusEx
    stub_ram_check()
}

#[cfg(not(target_os = "windows"))]
fn check_ram() -> (Finding, i32) {
    stub_ram_check()
}

fn stub_ram_check() -> (Finding, i32) {
    let total: u64 = 16_000_000_000;
    let available: u64 = 8_500_000_000;
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
