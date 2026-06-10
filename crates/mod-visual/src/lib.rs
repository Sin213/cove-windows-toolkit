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
fn read_registry_value(_path: &str, _name: &str) -> Option<String> {
    None // TODO: implement with winreg
}

#[cfg(not(target_os = "windows"))]
fn read_registry_value(_path: &str, _name: &str) -> Option<String> {
    Some("1".to_string()) // Mock: pretend everything is at default (enabled)
}
