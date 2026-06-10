use optimizer_core::types::SafetyTier;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisualTweak {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub safety_tier: SafetyTier,
    pub registry_path: String,
    pub registry_name: String,
    pub current_value: Option<String>,
    pub optimized_value: String,
}

pub fn get_tweaks() -> Vec<VisualTweak> {
    let definitions = vec![
        ("visual.transparency", "Disable Transparency", "Turn off window transparency effects to reduce GPU load",
         "Visual Effects", "Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
         "EnableTransparency", "0"),
        ("visual.animations", "Disable Minimize/Maximize Animations", "Remove window animation effects",
         "Visual Effects", "Control Panel\\Desktop\\WindowMetrics",
         "MinAnimate", "0"),
        ("visual.taskbar_anim", "Disable Taskbar Animations", "Stop taskbar button animations",
         "Visual Effects", "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
         "TaskbarAnimations", "0"),
        ("visual.peek", "Disable Aero Peek", "Turn off desktop peek on taskbar hover",
         "Visual Effects", "Software\\Microsoft\\Windows\\DWM",
         "EnableAeroPeek", "0"),
        ("visual.shadows", "Disable Icon Shadows", "Remove text shadows under desktop icons",
         "Visual Effects", "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
         "ListviewShadow", "0"),
        ("visual.smooth_scroll", "Disable Smooth Scrolling", "Turn off smooth scrolling in lists",
         "Visual Effects", "Control Panel\\Desktop",
         "SmoothScroll", "0"),
    ];

    definitions.into_iter().map(|(id, name, desc, cat, path, reg_name, opt_val)| {
        let current = read_registry_value(path, reg_name);
        VisualTweak {
            id: id.to_string(),
            name: name.to_string(),
            description: desc.to_string(),
            category: cat.to_string(),
            safety_tier: SafetyTier::Green,
            registry_path: format!("HKCU\\{}", path),
            registry_name: reg_name.to_string(),
            current_value: current,
            optimized_value: opt_val.to_string(),
        }
    }).collect()
}

#[cfg(target_os = "windows")]
fn read_registry_value(path: &str, name: &str) -> Option<String> {
    
    let full_path = format!("HKCU\\{}", path);
    let ps = format!(
        "try {{ $v = (Get-ItemProperty -Path 'Registry::{}' -Name '{}' -ErrorAction Stop).'{}'; Write-Output $v }} catch {{ Write-Output 'NOTFOUND' }}",
        full_path, name, name
    );
    if let Ok(o) = optimizer_core::silent_cmd("powershell").args(["-NoProfile", "-Command", &ps]).output() {
        let val = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if val != "NOTFOUND" && !val.is_empty() { return Some(val); }
    }
    None
}

#[cfg(not(target_os = "windows"))]
fn read_registry_value(_path: &str, _name: &str) -> Option<String> {
    Some("1".to_string())
}

#[cfg(target_os = "windows")]
pub fn apply_tweak(path: &str, name: &str, value: &str) -> Result<String, String> {
    
    let ps = format!(
        "try {{ Set-ItemProperty -Path 'Registry::{}' -Name '{}' -Value {} -Type DWord -Force -ErrorAction Stop; Write-Output 'OK' }} catch {{ New-Item -Path 'Registry::{}' -Force -ErrorAction SilentlyContinue | Out-Null; Set-ItemProperty -Path 'Registry::{}' -Name '{}' -Value {} -Type DWord -Force; Write-Output 'OK' }}",
        path, name, value, path, path, name, value
    );
    let o = optimizer_core::silent_cmd("powershell").args(["-NoProfile", "-Command", &ps]).output()
        .map_err(|e| e.to_string())?;
    if String::from_utf8_lossy(&o.stdout).trim() == "OK" {
        Ok(format!("Applied: {} = {}", name, value))
    } else {
        Err(String::from_utf8_lossy(&o.stderr).trim().to_string())
    }
}

#[cfg(not(target_os = "windows"))]
pub fn apply_tweak(_path: &str, _name: &str, _value: &str) -> Result<String, String> {
    Ok("[stub] Applied".into())
}
