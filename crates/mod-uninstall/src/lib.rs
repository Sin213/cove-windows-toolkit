use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledProgram {
    #[serde(default)]
    pub id: String,
    pub name: String,
    pub publisher: String,
    pub version: String,
    pub install_date: String,
    pub size_bytes: u64,
    #[serde(skip_serializing)]
    pub uninstall_string: String,
    #[serde(skip_serializing)]
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
    let mut programs: Vec<InstalledProgram> = serde_json::from_str(&json).unwrap_or_default();
    assign_program_ids(&mut programs);
    programs
}

#[cfg(not(target_os = "windows"))]
pub fn list_programs() -> Vec<InstalledProgram> {
    let mut programs = stub_programs();
    assign_program_ids(&mut programs);
    programs
}

fn assign_program_ids(programs: &mut [InstalledProgram]) {
    use std::hash::{DefaultHasher, Hash, Hasher};
    for program in programs {
        let mut hasher = DefaultHasher::new();
        program.registry_key.hash(&mut hasher);
        program.name.hash(&mut hasher);
        program.publisher.hash(&mut hasher);
        program.version.hash(&mut hasher);
        program.install_location.hash(&mut hasher);
        program.id = format!("program-{:016x}", hasher.finish());
    }
}

#[cfg(target_os = "windows")]
pub fn run_uninstall(uninstall_string: &str, quiet_string: &str) -> UninstallResult {
    let cmd = if !quiet_string.is_empty() {
        quiet_string
    } else {
        uninstall_string
    };
    if cmd.is_empty() {
        return UninstallResult {
            success: false,
            message: "No uninstall command available.".into(),
            output: String::new(),
        };
    }

    let argv = match split_windows_command_line(cmd) {
        Ok(argv) if !argv.is_empty() => argv,
        Ok(_) => return uninstall_error("The registered uninstall command is empty."),
        Err(e) => return uninstall_error(&e),
    };
    let executable = std::path::Path::new(&argv[0]);
    let is_msiexec = executable
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| {
            n.eq_ignore_ascii_case("msiexec") || n.eq_ignore_ascii_case("msiexec.exe")
        });
    if (!executable.is_absolute() && !is_msiexec)
        || executable
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("cmd") || e.eq_ignore_ascii_case("bat"))
    {
        return uninstall_error("Refused an unsafe registered uninstall command.");
    }

    let output = optimizer_core::silent_cmd(&argv[0].to_string_lossy())
        .args(&argv[1..])
        .output();

    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).to_string();
            let stderr = String::from_utf8_lossy(&o.stderr).to_string();
            let text = if stderr.is_empty() {
                stdout
            } else {
                format!("{}\n{}", stdout, stderr)
            };
            UninstallResult {
                success: o.status.success(),
                message: if o.status.success() {
                    "Uninstall completed.".into()
                } else {
                    "Uninstall may have failed or requires user interaction.".into()
                },
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

fn uninstall_error(message: &str) -> UninstallResult {
    UninstallResult {
        success: false,
        message: message.to_string(),
        output: String::new(),
    }
}

#[cfg(target_os = "windows")]
fn split_windows_command_line(command: &str) -> Result<Vec<std::ffi::OsString>, String> {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::UI::Shell::CommandLineToArgvW;

    let mut wide: Vec<u16> = std::ffi::OsStr::new(command)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut argc = 0;
    let argv = unsafe { CommandLineToArgvW(wide.as_mut_ptr(), &mut argc) };
    if argv.is_null() {
        return Err("Windows could not parse the registered uninstall command.".into());
    }
    let result = unsafe {
        let pointers = std::slice::from_raw_parts(argv, argc as usize);
        pointers
            .iter()
            .map(|&ptr| {
                let len = (0..).take_while(|&i| *ptr.add(i) != 0).count();
                std::ffi::OsString::from_wide(std::slice::from_raw_parts(ptr, len))
            })
            .collect()
    };
    unsafe { LocalFree(argv.cast()) };
    Ok(result)
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
pub fn scan_leftovers(
    name: &str,
    publisher: &str,
    install_location: &str,
    registry_key: &str,
) -> ScanResult {
    let script = format!(
        r#"$name = '{}'; $publisher = '{}'; $installLoc = '{}'; $regKey = '{}';{}"#,
        name.replace('\'', "''"),
        publisher.replace('\'', "''"),
        install_location.replace('\'', "''"),
        registry_key.replace('\'', "''"),
        include_str!("scan_leftovers.ps1")
    );
    let json = run_ps(&script);
    let mut result: ScanResult = serde_json::from_str(&json).unwrap_or(ScanResult {
        leftovers: Vec::new(),
        total_size_bytes: 0,
    });
    // Destructive service/task/registry cleanup requires ownership evidence we
    // do not currently have.  Only direct, exact-name application folders are
    // offered until those resource types have a native identity model.
    result.leftovers.retain(|item| item.category == "Folder");
    result.total_size_bytes = result.leftovers.iter().map(|item| item.size_bytes).sum();
    result
}

#[cfg(not(target_os = "windows"))]
pub fn scan_leftovers(
    name: &str,
    _publisher: &str,
    _install_location: &str,
    _registry_key: &str,
) -> ScanResult {
    ScanResult {
        leftovers: vec![
            Leftover {
                path: format!("C:\\ProgramData\\{}", name),
                category: "Folder".into(),
                size_bytes: 15_728_640,
            },
            Leftover {
                path: format!("C:\\Users\\User\\AppData\\Local\\{}", name),
                category: "Folder".into(),
                size_bytes: 8_388_608,
            },
            Leftover {
                path: format!("C:\\Users\\User\\AppData\\Roaming\\{}", name),
                category: "Folder".into(),
                size_bytes: 2_097_152,
            },
            Leftover {
                path: format!("HKCU\\Software\\{}", name),
                category: "Registry".into(),
                size_bytes: 0,
            },
            Leftover {
                path: format!("HKLM\\SOFTWARE\\{}", name),
                category: "Registry".into(),
                size_bytes: 0,
            },
        ],
        total_size_bytes: 26_214_400,
    }
}

#[cfg(target_os = "windows")]
fn remove_verified_folder(path: &str) -> (bool, String) {
    let target = match std::fs::canonicalize(path) {
        Ok(path) => path,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return (true, "Already removed".into());
        }
        Err(e) => return (false, format!("Could not resolve folder: {e}")),
    };
    let Some(parent) = target.parent() else {
        return (false, "Refused: folder has no parent.".into());
    };

    let mut allowed_parents = Vec::new();
    for key in [
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramData",
        "LOCALAPPDATA",
        "APPDATA",
        "TEMP",
    ] {
        if let Some(value) = std::env::var_os(key) {
            let root = std::path::PathBuf::from(value);
            if let Ok(root) = std::fs::canonicalize(&root) {
                allowed_parents.push(root.clone());
                if key == "LOCALAPPDATA" {
                    if let Ok(programs) = std::fs::canonicalize(root.join("Programs")) {
                        allowed_parents.push(programs);
                    }
                    if let Ok(low) = std::fs::canonicalize(root.join("Low")) {
                        allowed_parents.push(low);
                    }
                }
            }
        }
    }
    let parent = match std::fs::canonicalize(parent) {
        Ok(parent) => parent,
        Err(e) => return (false, format!("Could not resolve parent folder: {e}")),
    };
    if !allowed_parents.iter().any(|root| root == &parent) {
        return (
            false,
            "Refused: folder is outside approved application-data roots.".into(),
        );
    }

    match std::fs::remove_dir_all(&target) {
        Ok(()) => (true, "Removed".into()),
        Err(e) => (false, format!("Removal failed: {e}")),
    }
}

#[cfg(target_os = "windows")]
pub fn remove_leftovers(paths: &[String]) -> Vec<(String, bool, String)> {
    paths
        .iter()
        .map(|p| {
            if p.starts_with("HK") || p.starts_with("Service: ") || p.starts_with("Task: ") {
                return (
                    p.clone(),
                    false,
                    "Refused: this resource has no verified application ownership.".to_string(),
                );
            }
            let (ok, msg) = remove_verified_folder(p);
            (p.clone(), ok, msg)
        })
        .collect()
}

#[cfg(not(target_os = "windows"))]
pub fn remove_leftovers(paths: &[String]) -> Vec<(String, bool, String)> {
    paths
        .iter()
        .map(|p| (p.clone(), true, "[stub] Would remove".into()))
        .collect()
}

#[cfg(target_os = "windows")]
fn run_ps(script: &str) -> String {
    match optimizer_core::powershell(script).output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        Err(_) => "[]".to_string(),
    }
}

#[allow(dead_code)]
fn stub_programs() -> Vec<InstalledProgram> {
    vec![
        InstalledProgram {
            id: String::new(),
            name: "SignalRGB".into(),
            publisher: "WhirlwindFX".into(),
            version: "2.2.40".into(),
            install_date: "2026-05-15".into(),
            size_bytes: 524_288_000,
            uninstall_string: r#""C:\Program Files\SignalRGB\unins000.exe""#.into(),
            quiet_uninstall_string: r#""C:\Program Files\SignalRGB\unins000.exe" /VERYSILENT"#
                .into(),
            install_location: r"C:\Program Files\SignalRGB".into(),
            registry_key: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SignalRGB_is1"
                .into(),
            is_system: false,
        },
        InstalledProgram {
            id: String::new(),
            name: "Google Chrome".into(),
            publisher: "Google LLC".into(),
            version: "125.0.6422.142".into(),
            install_date: "2026-06-01".into(),
            size_bytes: 268_435_456,
            uninstall_string: String::new(),
            quiet_uninstall_string: String::new(),
            install_location: r"C:\Program Files\Google\Chrome".into(),
            registry_key: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome"
                .into(),
            is_system: false,
        },
        InstalledProgram {
            id: String::new(),
            name: "Discord".into(),
            publisher: "Discord Inc.".into(),
            version: "1.0.9035".into(),
            install_date: "2026-05-20".into(),
            size_bytes: 314_572_800,
            uninstall_string: String::new(),
            quiet_uninstall_string: String::new(),
            install_location: String::new(),
            registry_key: r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Discord"
                .into(),
            is_system: false,
        },
        InstalledProgram {
            id: String::new(),
            name: "Steam".into(),
            publisher: "Valve Corporation".into(),
            version: "2.10.91.91".into(),
            install_date: "2026-04-10".into(),
            size_bytes: 734_003_200,
            uninstall_string: String::new(),
            quiet_uninstall_string: String::new(),
            install_location: r"C:\Program Files (x86)\Steam".into(),
            registry_key: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Steam".into(),
            is_system: false,
        },
        InstalledProgram {
            id: String::new(),
            name: "Microsoft Visual C++ 2015-2022 Redistributable (x64)".into(),
            publisher: "Microsoft Corporation".into(),
            version: "14.38.33135".into(),
            install_date: "2026-01-15".into(),
            size_bytes: 25_165_824,
            uninstall_string: String::new(),
            quiet_uninstall_string: String::new(),
            install_location: String::new(),
            registry_key: String::new(),
            is_system: true,
        },
        InstalledProgram {
            id: String::new(),
            name: "7-Zip 24.08 (x64)".into(),
            publisher: "Igor Pavlov".into(),
            version: "24.08".into(),
            install_date: "2026-03-20".into(),
            size_bytes: 5_242_880,
            uninstall_string: String::new(),
            quiet_uninstall_string: String::new(),
            install_location: r"C:\Program Files\7-Zip".into(),
            registry_key: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\7-Zip".into(),
            is_system: false,
        },
    ]
}
