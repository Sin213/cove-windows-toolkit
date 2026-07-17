use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct DriverEntry {
    pub name: String,
    pub device: String,
    pub version: String,
    pub date: String,
    pub signed: Option<bool>,
    pub status: String,
}

#[derive(Serialize)]
pub struct DriverReport {
    pub complete: bool,
    pub error: Option<String>,
    pub total: usize,
    pub unsigned: usize,
    pub outdated: Option<usize>,
    pub problematic: Vec<DriverEntry>,
    pub healthy: Vec<DriverEntry>,
}

#[cfg(target_os = "windows")]
pub fn audit_drivers() -> DriverReport {
    let ps = r#"
$ErrorActionPreference='Stop'
try {
$items = @(Get-CimInstance Win32_PnPSignedDriver -ErrorAction Stop | ForEach-Object {
        $date = if ($_.DriverDate) { $_.DriverDate.ToString('yyyy-MM-dd') } else { 'unknown' }
        $class = if ($_.DeviceClass) { $_.DeviceClass } else { 'Other' }
        [pscustomobject]@{ name=if ($_.DeviceName) {$_.DeviceName} else {'Unknown device'}; device=$class; version=if ($_.DriverVersion) {$_.DriverVersion} else {'Unknown'}; date=$date; signed=$_.IsSigned }
    })
@{complete=$true; error=$null; items=$items} | ConvertTo-Json -Depth 4 -Compress
} catch { @{complete=$false; error=$_.Exception.Message; items=@()} | ConvertTo-Json -Depth 4 -Compress }
"#;

    let mut all_drivers = Vec::new();

    let mut complete = false;
    let mut error = None;
    if let Ok(o) = optimizer_core::powershell(ps).output()
        && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&o.stdout)
    {
        complete = value
            .get("complete")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        error = value
            .get("error")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        for item in value
            .get("items")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            let name = item
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown device")
                .to_string();
            let device = item
                .get("device")
                .and_then(|v| v.as_str())
                .unwrap_or("Other")
                .to_string();
            let version = item
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string();
            let date = item
                .get("date")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let signed = item.get("signed").and_then(|v| v.as_bool());
            let status = if signed == Some(false) {
                "unsigned".to_string()
            } else if signed.is_none() {
                "unknown".to_string()
            } else {
                "ok".to_string()
            };

            all_drivers.push(DriverEntry {
                name,
                device,
                version,
                date,
                signed,
                status,
            });
        }
    }

    let total = all_drivers.len();
    let unsigned = all_drivers
        .iter()
        .filter(|d| d.signed == Some(false))
        .count();

    let problematic: Vec<DriverEntry> = all_drivers
        .iter()
        .filter(|d| d.status != "ok")
        .cloned()
        .collect();

    let healthy: Vec<DriverEntry> = all_drivers
        .into_iter()
        .filter(|d| d.status == "ok")
        .take(10)
        .collect();

    DriverReport {
        complete,
        error,
        total,
        unsigned,
        outdated: None,
        problematic,
        healthy,
    }
}

#[cfg(not(target_os = "windows"))]
pub fn audit_drivers() -> DriverReport {
    DriverReport {
        complete: false,
        error: Some("Driver inventory is unavailable on this platform.".into()),
        total: 0,
        unsigned: 0,
        outdated: None,
        problematic: Vec::new(),
        healthy: Vec::new(),
    }
}
