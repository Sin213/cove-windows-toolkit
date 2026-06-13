use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct DriverEntry {
    pub name: String,
    pub device: String,
    pub version: String,
    pub date: String,
    pub signed: bool,
    pub status: String,
}

#[derive(Serialize)]
pub struct DriverReport {
    pub total: usize,
    pub unsigned: usize,
    pub outdated: usize,
    pub problematic: Vec<DriverEntry>,
    pub healthy: Vec<DriverEntry>,
}

#[cfg(target_os = "windows")]
pub fn audit_drivers() -> DriverReport {
    let ps = r#"
Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
    Where-Object { $_.DeviceName -and $_.DriverVersion } |
    ForEach-Object {
        $signed = if ($_.IsSigned) { 'true' } else { 'false' }
        $date = if ($_.DriverDate) { $_.DriverDate.ToString('yyyy-MM-dd') } else { 'unknown' }
        $class = if ($_.DeviceClass) { $_.DeviceClass } else { 'Other' }
        Write-Output "$($_.DeviceName)|$class|$($_.DriverVersion)|$date|$signed"
    }
"#;

    let mut all_drivers = Vec::new();

    if let Ok(o) = optimizer_core::powershell(ps).output() {
        let stdout = String::from_utf8_lossy(&o.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() < 5 { continue; }
            let name = parts[0].trim().to_string();
            let device = parts[1].trim().to_string();
            let version = parts[2].trim().to_string();
            let date = parts[3].trim().to_string();
            let signed = parts[4].trim() == "true";

            let status = if !signed {
                "unsigned".to_string()
            } else {
                "ok".to_string()
            };

            all_drivers.push(DriverEntry { name, device, version, date, signed, status });
        }
    }

    let total = all_drivers.len();
    let unsigned = all_drivers.iter().filter(|d| d.status == "unsigned").count();

    let problematic: Vec<DriverEntry> = all_drivers.iter()
        .filter(|d| d.status == "unsigned")
        .cloned()
        .collect();

    let healthy: Vec<DriverEntry> = all_drivers.into_iter()
        .filter(|d| d.status == "ok")
        .take(10)
        .collect();

    DriverReport { total, unsigned, outdated: 0, problematic, healthy }
}

#[cfg(not(target_os = "windows"))]
pub fn audit_drivers() -> DriverReport {
    DriverReport { total: 0, unsigned: 0, outdated: 0, problematic: Vec::new(), healthy: Vec::new() }
}
