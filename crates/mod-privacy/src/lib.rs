use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct PrivacyTweak {
    pub id: String,
    pub name: String,
    pub description: String,
    pub tier: String,
    pub path: String,
    pub value_name: String,
    pub current: String,
    pub optimized: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Serialize)]
pub struct PrivacyTweaks {
    pub basic: Vec<PrivacyTweak>,
    pub standard: Vec<PrivacyTweak>,
    pub advanced: Vec<PrivacyTweak>,
}

#[cfg(target_os = "windows")]
pub fn get_tweaks() -> PrivacyTweaks {
    let basic_defs = vec![
        ("privacy.advertising_id", "Disable Advertising ID", "Stop apps from using your advertising ID", "green",
         "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo", "Enabled", "0", None),
        ("privacy.typing_telemetry", "Disable Typing Telemetry", "Stop sending typing data to Microsoft", "green",
         "HKCU\\Software\\Microsoft\\Input\\TIPC", "Enabled", "0", None),
        ("privacy.web_search", "Disable Web Search in Start", "Stop Start menu from searching the web", "green",
         "HKCU\\Software\\Policies\\Microsoft\\Windows\\Explorer", "DisableSearchBoxSuggestions", "1", None),
        ("privacy.feedback", "Disable Feedback Notifications", "Stop Windows from asking for feedback", "green",
         "HKCU\\Software\\Microsoft\\Siuf\\Rules", "NumberOfSIUFInPeriod", "0", None),
        ("privacy.tips", "Disable Tips and Suggestions", "Stop suggested content notifications", "green",
         "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager", "SubscribedContent-338389Enabled", "0", None),
        ("privacy.lockscreen_ads", "Disable Lock Screen Ads", "Remove rotating ads from lock screen", "green",
         "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager", "RotatingLockScreenOverlayEnabled", "0", None),
    ];

    let standard_defs = vec![
        ("privacy.telemetry_level", "Minimize Telemetry", "Reduce Windows telemetry to minimum level", "yellow",
         "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection", "AllowTelemetry", "0",
         Some("On Home/Pro editions, reduces to Security level but cannot fully disable")),
        ("privacy.diagtrack", "Disable DiagTrack Service", "Stop the Connected User Experiences and Telemetry service", "yellow",
         "Service: DiagTrack", "StartType", "Disabled",
         Some("Breaks Windows Insider and Feedback Hub")),
        ("privacy.cortana", "Disable Cortana", "Turn off Cortana completely", "yellow",
         "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search", "AllowCortana", "0",
         Some("Disables Cortana entirely")),
        ("privacy.background_apps", "Disable Background Apps", "Prevent apps from running in background", "green",
         "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\BackgroundAccessApplications", "GlobalUserDisabled", "1",
         Some("Mail/Calendar won't sync in background")),
    ];

    let advanced_defs = vec![
        ("privacy.camera_deny", "Block Camera Access", "Deny all apps access to camera", "red",
         "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy", "LetAppsAccessCamera", "2",
         Some("No app can use your camera until you re-enable this")),
        ("privacy.microphone_deny", "Block Microphone Access", "Deny all apps access to microphone", "red",
         "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy", "LetAppsAccessMicrophone", "2",
         Some("No app can use your microphone until you re-enable this")),
    ];

    PrivacyTweaks {
        basic: basic_defs.into_iter().map(build_tweak).collect(),
        standard: standard_defs.into_iter().map(build_tweak).collect(),
        advanced: advanced_defs.into_iter().map(build_tweak).collect(),
    }
}

#[cfg(not(target_os = "windows"))]
pub fn get_tweaks() -> PrivacyTweaks {
    PrivacyTweaks { basic: Vec::new(), standard: Vec::new(), advanced: Vec::new() }
}

type TweakDef<'a> = (&'a str, &'a str, &'a str, &'a str, &'a str, &'a str, &'a str, Option<&'a str>);

fn build_tweak(def: TweakDef) -> PrivacyTweak {
    let (id, name, desc, tier, path, value_name, optimized, warning) = def;
    let current = if path.starts_with("Service:") {
        #[cfg(target_os = "windows")]
        { query_service(path.trim_start_matches("Service: ").trim()) }
        #[cfg(not(target_os = "windows"))]
        { "Unknown".to_string() }
    } else {
        read_reg(path, value_name)
    };
    PrivacyTweak {
        id: id.into(),
        name: name.into(),
        description: desc.into(),
        tier: tier.into(),
        path: path.into(),
        value_name: value_name.into(),
        current,
        optimized: optimized.into(),
        warning: warning.map(|s| s.into()),
    }
}

#[cfg(target_os = "windows")]
fn read_reg(path: &str, name: &str) -> String {
    use std::process::Command;

    let ps = format!(
        "try {{ $v = (Get-ItemProperty -Path 'Registry::{}' -Name '{}' -ErrorAction Stop).'{}'; Write-Output $v }} catch {{ Write-Output 'NotSet' }}",
        path, name, name
    );
    if let Ok(o) = Command::new("powershell").args(["-NoProfile", "-Command", &ps]).output() {
        let val = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if !val.is_empty() { return val; }
    }
    "NotSet".into()
}

#[cfg(not(target_os = "windows"))]
fn read_reg(_path: &str, _name: &str) -> String {
    "NotSet".into()
}

#[cfg(target_os = "windows")]
fn query_service(service: &str) -> String {
    use std::process::Command;
    let ps = format!(
        "try {{ (Get-WmiObject Win32_Service -Filter \"Name='{}'\").StartMode }} catch {{ 'Unknown' }}",
        service
    );
    if let Ok(o) = Command::new("powershell").args(["-NoProfile", "-Command", &ps]).output() {
        return String::from_utf8_lossy(&o.stdout).trim().to_string();
    }
    "Unknown".into()
}
