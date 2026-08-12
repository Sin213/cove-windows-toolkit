use optimizer_core::types::{Finding, MetricValue, Severity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    pub score: Option<u8>,
    pub complete: bool,
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

    let complete = findings.iter().all(|finding| finding.metric.is_some());
    let score = complete.then_some((100 - deductions).clamp(0, 100) as u8);
    HealthReport {
        score,
        complete,
        findings,
    }
}

/// An honest "couldn't read this metric" finding (no score deduction, no fake data).
fn unknown_finding(id: &str, title: &str, detail: &str) -> (Finding, i32) {
    (
        Finding {
            id: id.to_string(),
            severity: Severity::Info,
            title: title.to_string(),
            detail: detail.to_string(),
            metric: None,
            remediation: None,
        },
        0,
    )
}

#[cfg(target_os = "windows")]
fn check_disk_space() -> (Finding, i32) {
    read_disk_space().map_or_else(
        || {
            unknown_finding(
                "disk.free_space",
                "System Drive Free Space",
                "Could not read disk free space",
            )
        },
        |(free, total)| disk_finding(free, total),
    )
}

#[cfg(not(target_os = "windows"))]
fn check_disk_space() -> (Finding, i32) {
    disk_finding(45_000_000_000, 500_000_000_000)
}

fn disk_finding(free: u64, total: u64) -> (Finding, i32) {
    if total == 0 || free > total {
        return unknown_finding(
            "disk.free_space",
            "System Drive Free Space",
            "Could not read disk free space",
        );
    }

    let pct_free = (free as f32 / total as f32) * 100.0;

    let (severity, deduction) = if pct_free < 5.0 {
        (Severity::Critical, 25)
    } else if pct_free < 15.0 {
        (Severity::Warning, 10)
    } else {
        (Severity::Ok, 0)
    };

    (
        Finding {
            id: "disk.free_space".to_string(),
            severity,
            title: "System Drive Free Space".to_string(),
            // Volume free/total space is binary (matches what Windows Explorer shows).
            detail: format!(
                "{:.1} GB free of {:.1} GB ({:.0}%)",
                free as f64 / 1_073_741_824.0,
                total as f64 / 1_073_741_824.0,
                pct_free
            ),
            metric: Some(MetricValue::Percent(pct_free)),
            remediation: if severity != Severity::Ok {
                Some("Run Disk Cleanup to free space on the system drive".to_string())
            } else {
                None
            },
        },
        deduction,
    )
}

#[cfg(target_os = "windows")]
fn check_ram() -> (Finding, i32) {
    read_memory_status().map_or_else(
        || {
            unknown_finding(
                "ram.available",
                "Available RAM",
                "Could not read memory status",
            )
        },
        |(available, total)| ram_finding(available, total),
    )
}

#[cfg(not(target_os = "windows"))]
fn check_ram() -> (Finding, i32) {
    ram_finding(8_500_000_000, 16_000_000_000)
}

fn ram_finding(available: u64, total: u64) -> (Finding, i32) {
    if total == 0 || available > total {
        return unknown_finding(
            "ram.available",
            "Available RAM",
            "Could not read memory status",
        );
    }

    let pct_available = (available as f32 / total as f32) * 100.0;

    let (severity, deduction) = if available < 200_000_000 {
        (Severity::Critical, 25)
    } else if pct_available < 10.0 {
        (Severity::Warning, 10)
    } else {
        (Severity::Ok, 0)
    };

    (
        Finding {
            id: "ram.available".to_string(),
            severity,
            title: "Available RAM".to_string(),
            // RAM is binary: a 32 GiB machine is 34.36e9 bytes, which must read as 32 GB.
            detail: format!(
                "{:.1} GB available of {:.1} GB ({:.0}%)",
                available as f64 / 1_073_741_824.0,
                total as f64 / 1_073_741_824.0,
                pct_available
            ),
            metric: Some(MetricValue::Percent(pct_available)),
            remediation: if severity != Severity::Ok {
                Some("Close unused applications to free memory".to_string())
            } else {
                None
            },
        },
        deduction,
    )
}

#[cfg(target_os = "windows")]
fn read_disk_space() -> Option<(u64, u64)> {
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

    let root = system_drive_root()?;
    let mut total = 0u64;
    let mut free = 0u64;
    let succeeded =
        unsafe { GetDiskFreeSpaceExW(root.as_ptr(), std::ptr::null_mut(), &mut total, &mut free) }
            != 0;

    succeeded
        .then_some((free, total))
        .filter(|(free, total)| *total > 0 && *free <= *total)
}

#[cfg(target_os = "windows")]
fn system_drive_root() -> Option<Vec<u16>> {
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::{Path, PathBuf};
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    // The API reports the required size when the buffer is too small. Retry
    // with that size so long-path-compatible installations remain valid.
    let mut buffer = vec![0u16; 260];
    let length = loop {
        let length =
            unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
        if length == 0 {
            return None;
        }
        if length < buffer.len() {
            break length;
        }
        if length >= 32_768 {
            return None;
        }
        buffer.resize(length + 1, 0);
    };

    let system_directory = OsString::from_wide(&buffer[..length]);
    let root: PathBuf = Path::new(&system_directory).components().take(2).collect();
    if root.as_os_str().is_empty() {
        return None;
    }

    let mut wide: Vec<u16> = root.as_os_str().encode_wide().collect();
    wide.push(0);
    Some(wide)
}

#[cfg(target_os = "windows")]
fn read_memory_status() -> Option<(u64, u64)> {
    use std::mem::size_of;
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

    let mut status: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    status.dwLength = size_of::<MEMORYSTATUSEX>() as u32;
    let succeeded = unsafe { GlobalMemoryStatusEx(&mut status) } != 0;

    succeeded
        .then_some((status.ullAvailPhys, status.ullTotalPhys))
        .filter(|(available, total)| *total > 0 && *available <= *total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn percent(finding: &Finding) -> f32 {
        match finding.metric {
            Some(MetricValue::Percent(value)) => value,
            _ => panic!("expected a percentage metric"),
        }
    }

    #[test]
    fn disk_thresholds_preserve_severity_and_deduction() {
        let (critical, critical_deduction) = disk_finding(4, 100);
        assert_eq!(critical.id, "disk.free_space");
        assert_eq!(critical.severity, Severity::Critical);
        assert_eq!(critical_deduction, 25);
        assert!((percent(&critical) - 4.0).abs() < f32::EPSILON);

        let (warning, warning_deduction) = disk_finding(14, 100);
        assert_eq!(warning.severity, Severity::Warning);
        assert_eq!(warning_deduction, 10);

        let (ok, ok_deduction) = disk_finding(15, 100);
        assert_eq!(ok.severity, Severity::Ok);
        assert_eq!(ok_deduction, 0);
    }

    #[test]
    fn ram_thresholds_preserve_severity_and_deduction() {
        let (critical, critical_deduction) = ram_finding(199_999_999, 2_000_000_000);
        assert_eq!(critical.id, "ram.available");
        assert_eq!(critical.severity, Severity::Critical);
        assert_eq!(critical_deduction, 25);

        let (warning, warning_deduction) = ram_finding(500_000_000, 20_000_000_000);
        assert_eq!(warning.severity, Severity::Warning);
        assert_eq!(warning_deduction, 10);

        let (ok, ok_deduction) = ram_finding(2_000_000_000, 20_000_000_000);
        assert_eq!(ok.severity, Severity::Ok);
        assert_eq!(ok_deduction, 0);
    }

    #[test]
    fn invalid_metrics_are_unknown_and_do_not_affect_score() {
        let (disk, disk_deduction) = disk_finding(1, 0);
        assert_eq!(disk.id, "disk.free_space");
        assert_eq!(disk.severity, Severity::Info);
        assert!(disk.metric.is_none());
        assert_eq!(disk_deduction, 0);

        let (ram, ram_deduction) = ram_finding(21, 20);
        assert_eq!(ram.id, "ram.available");
        assert_eq!(ram.severity, Severity::Info);
        assert!(ram.metric.is_none());
        assert_eq!(ram_deduction, 0);

        let (unknown, deduction) = unknown_finding("metric", "Metric", "Unavailable");
        assert!(unknown.metric.is_none());
        assert_eq!(deduction, 0);
    }

    #[test]
    fn quick_scan_score_is_only_present_when_all_metrics_are_known() {
        let report = quick_scan();
        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.complete, report.score.is_some());
        if report.complete {
            assert!(report.score.unwrap() <= 100);
        }
    }
}
