use optimizer_core::types::SafetyTier;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceTweak {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub safety_tier: SafetyTier,
    pub registry_path: String,
    pub registry_name: String,
    pub current_value: Option<String>,
    pub optimized_value: String,
    pub warning: Option<String>,
}

pub fn get_tweaks() -> Vec<PerformanceTweak> {
    let definitions: Vec<(&str, &str, &str, &str, SafetyTier, &str, &str, &str, Option<&str>)> = vec![
        (
            "perf.ntfs_last_access",
            "Disable NTFS Last Access Timestamp",
            "Skip updating the last-access time on every file read — reduces disk I/O, especially on HDDs",
            "Filesystem",
            SafetyTier::Yellow,
            "SYSTEM\\CurrentControlSet\\Control\\FileSystem",
            "NtfsDisableLastAccessUpdate",
            "80000003",
            None,
        ),
        (
            "perf.ntfs_8dot3",
            "Disable 8.3 Short Name Creation",
            "Stop generating legacy DOS-compatible short filenames — speeds up directory operations",
            "Filesystem",
            SafetyTier::Yellow,
            "SYSTEM\\CurrentControlSet\\Control\\FileSystem",
            "NtfsDisable8dot3NameCreation",
            "1",
            Some("Very old 16-bit programs may not find files without 8.3 names"),
        ),
        (
            "perf.prefetch",
            "Disable Prefetcher",
            "Turn off the prefetch cache — unnecessary on SSDs where random reads are fast",
            "Memory",
            SafetyTier::Yellow,
            "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters",
            "EnablePrefetcher",
            "0",
            Some("First launch of apps may be slightly slower without prefetch data"),
        ),
        (
            "perf.superfetch",
            "Disable Superfetch (SysMain)",
            "Stop preloading frequently used apps into RAM — frees memory on low-RAM machines and reduces disk I/O on SSDs",
            "Memory",
            SafetyTier::Yellow,
            "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters",
            "EnableSuperfetch",
            "0",
            None,
        ),
        (
            "perf.priority_separation",
            "Boost Foreground App Priority",
            "Give the active window more CPU time — makes the desktop feel snappier",
            "CPU",
            SafetyTier::Yellow,
            "SYSTEM\\CurrentControlSet\\Control\\PriorityControl",
            "Win32PrioritySeparation",
            "38",
            None,
        ),
        (
            "perf.game_bar",
            "Disable Game Bar",
            "Turn off the Xbox Game Bar overlay — saves background resources on non-gaming machines",
            "Gaming",
            SafetyTier::Green,
            "Software\\Microsoft\\GameBar",
            "AutoGameModeEnabled",
            "0",
            None,
        ),
        (
            "perf.game_dvr",
            "Disable Game DVR",
            "Stop background game recording — reclaims GPU and disk bandwidth",
            "Gaming",
            SafetyTier::Green,
            "System\\GameConfigStore",
            "GameDVR_Enabled",
            "0",
            None,
        ),
        (
            "perf.fast_startup",
            "Disable Fast Startup",
            "Turn off hybrid shutdown — ensures a clean boot every time, avoids stale driver state",
            "Boot",
            SafetyTier::Yellow,
            "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power",
            "HiberbootEnabled",
            "0",
            Some("Cold boot will take a few seconds longer without hybrid shutdown"),
        ),
    ];

    definitions
        .into_iter()
        .map(|(id, name, desc, cat, tier, path, reg_name, opt_val, warning)| {
            let is_hklm = path.starts_with("SYSTEM\\") || path.starts_with("SOFTWARE\\");
            let hive = if is_hklm { "HKLM" } else { "HKCU" };
            let current = read_registry_value(path, reg_name);
            PerformanceTweak {
                id: id.to_string(),
                name: name.to_string(),
                description: desc.to_string(),
                category: cat.to_string(),
                safety_tier: tier,
                registry_path: format!("{}\\{}", hive, path),
                registry_name: reg_name.to_string(),
                current_value: current,
                optimized_value: opt_val.to_string(),
                warning: warning.map(|s| s.to_string()),
            }
        })
        .collect()
}

#[cfg(target_os = "windows")]
fn read_registry_value(_path: &str, _name: &str) -> Option<String> {
    None // TODO: implement with winreg
}

#[cfg(not(target_os = "windows"))]
fn read_registry_value(_path: &str, _name: &str) -> Option<String> {
    Some("1".to_string())
}
