pub mod identity;
pub mod pnputil;

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

// ---------------------------------------------------------------------------
// Additive driver identity inventory (read-only)
// ---------------------------------------------------------------------------

/// Enumerate device identity through the read-only PnPUtil `/enum-devices`
/// family and return a fidelity-aware report. The legacy [`audit_drivers`]
/// export shape is intentionally unchanged.
pub fn scan_device_identity() -> identity::DriverIdentityReport {
    let machine = machine_context();
    match run_enum_devices() {
        Ok(parsed) => {
            let degraded = parsed.degraded;
            let devices = parsed.devices;
            tracing::info!(
                target: "cove::drivers",
                devices = devices.len(),
                degraded,
                "driver identity scan completed"
            );
            identity::DriverIdentityReport {
                complete: parsed.complete,
                degraded,
                error: None,
                machine,
                devices,
            }
        }
        Err(error) => {
            tracing::warn!(
                target: "cove::drivers",
                category = %error,
                "driver identity scan failed"
            );
            identity::DriverIdentityReport {
                complete: false,
                degraded: false,
                error: Some(error.to_string()),
                machine,
                devices: Vec::new(),
            }
        }
    }
}

/// Resolve and run the read-only PnPUtil enumeration, then hand its decoded
/// output to the pure parser. No writes, no device mutation, no networking.
#[cfg(target_os = "windows")]
fn run_enum_devices() -> Result<pnputil::ParsedEnumeration, pnputil::PnputilParseError> {
    tracing::info!(target: "cove::drivers", "driver identity scan started");

    // Full modern-host enumeration.
    let output = optimizer_core::silent_cmd("pnputil")
        .args([
            "/enum-devices",
            "/connected",
            "/deviceids",
            "/drivers",
            "/properties",
        ])
        .output()
        .map_err(|error| {
            pnputil::PnputilParseError::Malformed(format!("could not start pnputil: {error}"))
        })?;

    if !output.status.success() {
        // Some hosts reject `/drivers` and/or `/properties`. First try the
        // `/deviceids` form, which preserves ordered hardware/compatible IDs.
        let identity_fallback = optimizer_core::silent_cmd("pnputil")
            .args(["/enum-devices", "/connected", "/deviceids"])
            .output()
            .map_err(|error| {
                pnputil::PnputilParseError::Malformed(format!(
                    "could not start pnputil identity fallback: {error}"
                ))
            })?;
        if identity_fallback.status.success() {
            let text = optimizer_core::decode_console_output(&identity_fallback.stdout);
            return pnputil::parse_enum_devices(&text, pnputil::EnumMode::IdentityOnly);
        }

        // Finally, the bare `/enum-devices /connected` form predates those
        // switches and still returns a reduced (degraded) identity inventory on
        // very old Windows hosts.
        let degraded_fallback = optimizer_core::silent_cmd("pnputil")
            .args(["/enum-devices", "/connected"])
            .output()
            .map_err(|error| {
                pnputil::PnputilParseError::Malformed(format!(
                    "could not start pnputil degraded fallback: {error}"
                ))
            })?;
        if !degraded_fallback.status.success() {
            return Err(pnputil::PnputilParseError::Malformed(
                "pnputil enumeration failed".into(),
            ));
        }
        let text = optimizer_core::decode_console_output(&degraded_fallback.stdout);
        return pnputil::parse_enum_devices(&text, pnputil::EnumMode::Degraded);
    }

    let text = optimizer_core::decode_console_output(&output.stdout);
    pnputil::parse_enum_devices(&text, pnputil::EnumMode::Full)
}

#[cfg(not(target_os = "windows"))]
fn run_enum_devices() -> Result<pnputil::ParsedEnumeration, pnputil::PnputilParseError> {
    Err(pnputil::PnputilParseError::Malformed(
        "driver identity inventory is unavailable on this platform".into(),
    ))
}

#[cfg(target_os = "windows")]
fn machine_context() -> identity::MachineContext {
    use windows_sys::Win32::System::SystemInformation::{
        GetNativeSystemInfo, PROCESSOR_ARCHITECTURE_AMD64, PROCESSOR_ARCHITECTURE_ARM64,
        PROCESSOR_ARCHITECTURE_INTEL, SYSTEM_INFO,
    };
    use windows_sys::Wdk::System::SystemServices::RtlGetVersion;

    let arch = {
        let mut info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
        unsafe { GetNativeSystemInfo(&mut info) };
        match unsafe { info.Anonymous.Anonymous.wProcessorArchitecture } {
            PROCESSOR_ARCHITECTURE_AMD64 => "x64".to_string(),
            PROCESSOR_ARCHITECTURE_ARM64 => "arm64".to_string(),
            PROCESSOR_ARCHITECTURE_INTEL => "x86".to_string(),
            other => format!("unknown({other})"),
        }
    };

    let mut version = unsafe { std::mem::zeroed::<windows_sys::Win32::System::SystemInformation::OSVERSIONINFOW>() };
    version.dwOSVersionInfoSize =
        std::mem::size_of::<windows_sys::Win32::System::SystemInformation::OSVERSIONINFOW>() as u32;
    let status = unsafe { RtlGetVersion(&mut version) };
    let (os_version, os_build) = if status == 0 {
        (
            format!("{}.{}", version.dwMajorVersion, version.dwMinorVersion),
            version.dwBuildNumber.to_string(),
        )
    } else {
        (
            std::env::consts::OS.to_string(),
            "unknown".to_string(),
        )
    };

    identity::MachineContext {
        arch,
        os_build,
        os_version,
    }
}

#[cfg(not(target_os = "windows"))]
fn machine_context() -> identity::MachineContext {
    identity::MachineContext {
        arch: std::env::consts::ARCH.to_string(),
        os_build: "unknown".to_string(),
        os_version: std::env::consts::OS.to_string(),
    }
}
