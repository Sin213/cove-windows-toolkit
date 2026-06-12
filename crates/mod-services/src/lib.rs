use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct ServiceTweak {
    pub id: String,
    pub name: String,
    pub service: String,
    pub description: String,
    pub tier: String,
    pub current: String,
    pub optimized: String,
    pub impact: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Serialize)]
pub struct ServicesTweaks {
    pub conservative: Vec<ServiceTweak>,
    pub advanced: Vec<ServiceTweak>,
}

#[cfg(target_os = "windows")]
pub fn get_tweaks() -> ServicesTweaks {
    let conservative_defs = vec![
        ("svc.wsearch", "Windows Search", "WSearch", "Indexing service -uses RAM and disk I/O", "green", "Manual", "Search works but first query is slower", None),
        ("svc.sysmain", "SysMain (Superfetch)", "SysMain", "Prefetch service -irrelevant on SSDs", "green", "Manual", "Frees RAM and reduces disk I/O on SSDs", None),
        ("svc.diagtrack", "DiagTrack", "DiagTrack", "Connected User Experiences and Telemetry", "green", "Manual", "Stops telemetry data upload", None),
        ("svc.spooler", "Print Spooler", "Spooler", "Manages print jobs", "green", "Manual", "Set Manual only if no printer detected", None),
        ("svc.xbox_auth", "Xbox Live Auth Manager", "XblAuthManager", "Xbox Live authentication", "green", "Disabled", "No effect unless Xbox app is actively used", None),
        ("svc.xbox_save", "Xbox Live Game Save", "XblGameSave", "Xbox cloud saves", "green", "Disabled", "No cloud save sync for Xbox games", None),
        ("svc.fax", "Fax", "Fax", "Fax service", "green", "Disabled", "No fax capability", None),
    ];

    let advanced_defs = vec![
        ("svc.wuauserv", "Windows Update", "wuauserv", "Manages Windows Updates", "red", "Disabled", "No security patches while disabled", Some("Your system will not receive security patches. Re-enable monthly.")),
        ("svc.windefend", "Windows Defender", "WinDefend", "Real-time antivirus protection", "red", "Disabled", "No AV protection", Some("Only disable if using a third-party antivirus")),
    ];

    ServicesTweaks {
        conservative: conservative_defs.into_iter().map(|d| build_service_tweak(d)).collect(),
        advanced: advanced_defs.into_iter().map(|d| build_service_tweak(d)).collect(),
    }
}

#[cfg(not(target_os = "windows"))]
pub fn get_tweaks() -> ServicesTweaks {
    ServicesTweaks { conservative: Vec::new(), advanced: Vec::new() }
}

#[cfg(target_os = "windows")]
fn build_service_tweak(def: (&str, &str, &str, &str, &str, &str, &str, Option<&str>)) -> ServiceTweak {
    let (id, name, service, desc, tier, optimized, impact, warning) = def;
    let current = query_service_start_type(service);
    ServiceTweak {
        id: id.into(),
        name: name.into(),
        service: service.into(),
        description: desc.into(),
        tier: tier.into(),
        current,
        optimized: optimized.into(),
        impact: impact.into(),
        warning: warning.map(|s| s.into()),
    }
}

#[cfg(target_os = "windows")]
fn query_service_start_type(service: &str) -> String {
    

    let ps = format!(
        "try {{ $s = Get-Service '{}' -ErrorAction Stop; $st = (Get-WmiObject Win32_Service -Filter \"Name='{}'\").StartMode; if ($st -eq 'Auto') {{ $st = 'Automatic' }}; Write-Output $st }} catch {{ Write-Output 'NotFound' }}",
        service, service
    );

    if let Ok(o) = optimizer_core::silent_cmd("powershell").args(["-NoProfile", "-Command", &ps]).output() {
        let result = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if !result.is_empty() { return result; }
    }
    "Unknown".into()
}

#[cfg(target_os = "windows")]
pub fn apply_change(service: &str, start_type: &str) -> Result<String, String> {
    

    let ps = format!(
        "Set-Service -Name '{}' -StartupType '{}' -ErrorAction Stop; Write-Output 'OK'",
        service, start_type
    );
    let o = optimizer_core::silent_cmd("powershell").args(["-NoProfile", "-Command", &ps]).output()
        .map_err(|e| e.to_string())?;
    let result = String::from_utf8_lossy(&o.stdout).trim().to_string();
    if result == "OK" {
        Ok(format!("Service '{}' set to {}", service, start_type))
    } else {
        Err(String::from_utf8_lossy(&o.stderr).trim().to_string())
    }
}

#[cfg(not(target_os = "windows"))]
pub fn apply_change(_service: &str, _start_type: &str) -> Result<String, String> {
    Ok("[stub] Service changed".into())
}
