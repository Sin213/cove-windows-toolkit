use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledProgram {
    pub name: String,
    pub publisher: String,
    pub version: String,
    pub install_date: String,
    pub size_bytes: u64,
    pub uninstall_string: String,
    pub quiet_uninstall_string: String,
    pub install_location: String,
    pub registry_key: String,
    pub is_system: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Leftover {
    pub path: String,
    pub category: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub leftovers: Vec<Leftover>,
    pub total_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UninstallResult {
    pub success: bool,
    pub message: String,
    pub output: String,
}

#[cfg(target_os = "windows")]
pub fn list_programs() -> Vec<InstalledProgram> {
    let json = run_ps(include_str!("list_programs.ps1"));
    serde_json::from_str(&json).unwrap_or_default()
}

#[cfg(not(target_os = "windows"))]
pub fn list_programs() -> Vec<InstalledProgram> {
    stub_programs()
}

#[cfg(target_os = "windows")]
pub fn run_uninstall(uninstall_string: &str, quiet_string: &str) -> UninstallResult {
    

    let cmd = if !quiet_string.is_empty() { quiet_string } else { uninstall_string };
    if cmd.is_empty() {
        return UninstallResult {
            success: false,
            message: "No uninstall command available.".into(),
            output: String::new(),
        };
    }

    let output = optimizer_core::silent_cmd("cmd")
        .args(["/C", cmd])
        .output();

    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).to_string();
            let stderr = String::from_utf8_lossy(&o.stderr).to_string();
            let text = if stderr.is_empty() { stdout } else { format!("{}\n{}", stdout, stderr) };
            UninstallResult {
                success: o.status.success(),
                message: if o.status.success() { "Uninstall completed.".into() } else { "Uninstall may have failed or requires user interaction.".into() },
                output: text,
            }
        }
        Err(e) => UninstallResult {
            success: false,
            message: format!("Failed to run uninstaller: {}", e),
            output: String::new(),
        },
    }
}

#[cfg(not(target_os = "windows"))]
pub fn run_uninstall(_uninstall_string: &str, _quiet_string: &str) -> UninstallResult {
    UninstallResult {
        success: true,
        message: "[stub] Uninstall would run on Windows.".into(),
        output: String::new(),
    }
}

#[cfg(target_os = "windows")]
pub fn scan_leftovers(name: &str, publisher: &str, install_location: &str, registry_key: &str) -> ScanResult {
    let script = format!(
        r#"$name = '{}'; $publisher = '{}'; $installLoc = '{}'; $regKey = '{}';{}"#,
        name.replace('\'', "''"),
        publisher.replace('\'', "''"),
        install_location.replace('\'', "''"),
        registry_key.replace('\'', "''"),
        include_str!("scan_leftovers.ps1")
    );
    let json = run_ps(&script);
    serde_json::from_str(&json).unwrap_or(ScanResult { leftovers: Vec::new(), total_size_bytes: 0 })
}

#[cfg(not(target_os = "windows"))]
pub fn scan_leftovers(name: &str, _publisher: &str, _install_location: &str, _registry_key: &str) -> ScanResult {
    ScanResult {
        leftovers: vec![
            Leftover { path: format!("C:\\ProgramData\\{}", name), category: "Folder".into(), size_bytes: 15_728_640 },
            Leftover { path: format!("C:\\Users\\User\\AppData\\Local\\{}", name), category: "Folder".into(), size_bytes: 8_388_608 },
            Leftover { path: format!("C:\\Users\\User\\AppData\\Roaming\\{}", name), category: "Folder".into(), size_bytes: 2_097_152 },
            Leftover { path: format!("HKCU\\Software\\{}", name), category: "Registry".into(), size_bytes: 0 },
            Leftover { path: format!("HKLM\\SOFTWARE\\{}", name), category: "Registry".into(), size_bytes: 0 },
        ],
        total_size_bytes: 26_214_400,
    }
}

#[cfg(target_os = "windows")]
pub fn remove_leftovers(paths: &[String]) -> Vec<(String, bool, String)> {
    paths.iter().map(|p| {
        if p.starts_with("HK") {
            let result = optimizer_core::silent_cmd("powershell")
                .args(["-NoProfile", "-Command", &format!("Remove-Item -Path 'Registry::{}' -Recurse -Force -ErrorAction Stop", p.replace('\'', "''"))])
                .output();
            match result {
                Ok(o) if o.status.success() => (p.clone(), true, "Removed".into()),
                Ok(o) => (p.clone(), false, String::from_utf8_lossy(&o.stderr).trim().to_string()),
                Err(e) => (p.clone(), false, e.to_string()),
            }
        } else {
            let result = optimizer_core::silent_cmd("powershell")
                .args(["-NoProfile", "-Command", &format!("Remove-Item -Path '{}' -Recurse -Force -ErrorAction Stop", p.replace('\'', "''"))])
                .output();
            match result {
                Ok(o) if o.status.success() => (p.clone(), true, "Removed".into()),
                Ok(o) => (p.clone(), false, String::from_utf8_lossy(&o.stderr).trim().to_string()),
                Err(e) => (p.clone(), false, e.to_string()),
            }
        }
    }).collect()
}

#[cfg(not(target_os = "windows"))]
pub fn remove_leftovers(paths: &[String]) -> Vec<(String, bool, String)> {
    paths.iter().map(|p| (p.clone(), true, "[stub] Would remove".into())).collect()
}

#[cfg(target_os = "windows")]
fn run_ps(script: &str) -> String {
    
    match optimizer_core::silent_cmd("powershell").args(["-NoProfile", "-Command", script]).output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        Err(_) => "[]".to_string(),
    }
}

#[allow(dead_code)]
fn stub_programs() -> Vec<InstalledProgram> {
    vec![
        InstalledProgram { name: "SignalRGB".into(), publisher: "WhirlwindFX".into(), version: "2.2.40".into(), install_date: "2026-05-15".into(), size_bytes: 524_288_000, uninstall_string: r#""C:\Program Files\SignalRGB\unins000.exe""#.into(), quiet_uninstall_string: r#""C:\Program Files\SignalRGB\unins000.exe" /VERYSILENT"#.into(), install_location: r"C:\Program Files\SignalRGB".into(), registry_key: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SignalRGB_is1".into(), is_system: false },
        InstalledProgram { name: "Google Chrome".into(), publisher: "Google LLC".into(), version: "125.0.6422.142".into(), install_date: "2026-06-01".into(), size_bytes: 268_435_456, uninstall_string: String::new(), quiet_uninstall_string: String::new(), install_location: r"C:\Program Files\Google\Chrome".into(), registry_key: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome".into(), is_system: false },
        InstalledProgram { name: "Discord".into(), publisher: "Discord Inc.".into(), version: "1.0.9035".into(), install_date: "2026-05-20".into(), size_bytes: 314_572_800, uninstall_string: String::new(), quiet_uninstall_string: String::new(), install_location: String::new(), registry_key: r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Discord".into(), is_system: false },
        InstalledProgram { name: "Steam".into(), publisher: "Valve Corporation".into(), version: "2.10.91.91".into(), install_date: "2026-04-10".into(), size_bytes: 734_003_200, uninstall_string: String::new(), quiet_uninstall_string: String::new(), install_location: r"C:\Program Files (x86)\Steam".into(), registry_key: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Steam".into(), is_system: false },
        InstalledProgram { name: "Microsoft Visual C++ 2015-2022 Redistributable (x64)".into(), publisher: "Microsoft Corporation".into(), version: "14.38.33135".into(), install_date: "2026-01-15".into(), size_bytes: 25_165_824, uninstall_string: String::new(), quiet_uninstall_string: String::new(), install_location: String::new(), registry_key: String::new(), is_system: true },
        InstalledProgram { name: "7-Zip 24.08 (x64)".into(), publisher: "Igor Pavlov".into(), version: "24.08".into(), install_date: "2026-03-20".into(), size_bytes: 5_242_880, uninstall_string: String::new(), quiet_uninstall_string: String::new(), install_location: r"C:\Program Files\7-Zip".into(), registry_key: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\7-Zip".into(), is_system: false },
    ]
}
