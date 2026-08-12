use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(default)]
    pub can_uninstall: bool,
    #[serde(default)]
    pub uninstall_reason: String,
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
    list_programs_checked().unwrap_or_default()
}

#[cfg(target_os = "windows")]
pub fn list_programs_checked() -> Result<Vec<InstalledProgram>, String> {
    let json = run_ps_checked(include_str!("list_programs.ps1"))?;
    if json.trim().is_empty() {
        return Ok(Vec::new());
    }
    let value: serde_json::Value = serde_json::from_str(&json)
        .map_err(|error| format!("Could not parse installed-program inventory: {error}"))?;
    let mut programs = if value.is_array() {
        serde_json::from_value(value)
            .map_err(|error| format!("Could not parse installed-program inventory: {error}"))?
    } else {
        vec![
            serde_json::from_value(value)
                .map_err(|error| format!("Could not parse installed-program inventory: {error}"))?,
        ]
    };
    assign_program_ids(&mut programs);
    Ok(programs)
}

#[cfg(not(target_os = "windows"))]
pub fn list_programs() -> Vec<InstalledProgram> {
    let mut programs = stub_programs();
    assign_program_ids(&mut programs);
    programs
}

#[cfg(not(target_os = "windows"))]
pub fn list_programs_checked() -> Result<Vec<InstalledProgram>, String> {
    Ok(list_programs())
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
        let capability = uninstall_capability(program);
        program.can_uninstall = capability.can_uninstall;
        program.uninstall_reason = capability.reason;
    }
}

struct UninstallCapability {
    can_uninstall: bool,
    reason: String,
}

fn uninstall_capability(program: &InstalledProgram) -> UninstallCapability {
    match trusted_msi_product_code(program) {
        Ok(_) => UninstallCapability {
            can_uninstall: true,
            reason: "Machine-wide Windows Installer package.".into(),
        },
        Err(reason) => UninstallCapability {
            can_uninstall: false,
            reason,
        },
    }
}

/// Re-read the registry inventory and require every cached field to remain
/// identical. In particular, the stable display id deliberately does not hash
/// the uninstall command, so this equality check catches a command replaced
/// after the UI was populated.
pub fn revalidate_program(expected: &InstalledProgram) -> Result<InstalledProgram, String> {
    let programs = list_programs_checked()?;
    let mut matches = programs
        .into_iter()
        .filter(|program| program.id == expected.id);
    let current = matches.next().ok_or_else(|| {
        "The selected program is no longer registered. Refresh the list.".to_string()
    })?;
    if matches.next().is_some() {
        return Err("The selected program registration is ambiguous. Refresh the list.".into());
    }
    if &current != expected {
        return Err(
            "The selected program registration changed after it was listed. Refresh and review it before uninstalling."
                .into(),
        );
    }
    Ok(current)
}

#[cfg(target_os = "windows")]
pub fn run_uninstall(program: &InstalledProgram) -> UninstallResult {
    let current = match revalidate_program(program) {
        Ok(current) => current,
        Err(reason) => return uninstall_error(&reason),
    };
    if !current.can_uninstall {
        return uninstall_error(&current.uninstall_reason);
    }
    let product_code = match trusted_msi_product_code(&current) {
        Ok(product_code) => product_code,
        Err(reason) => return uninstall_error(&reason),
    };

    // Never execute the registry's executable path in this always-elevated
    // process. The only enabled policy is an HKLM MSI product registration, and
    // even then we invoke Windows' trusted System32 copy with normalized args.
    let output = optimizer_core::silent_cmd("msiexec")
        .args(["/x", &product_code])
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
            let exit_code = o.status.code();
            let success = o.status.success() || matches!(exit_code, Some(1641 | 3010));
            UninstallResult {
                success,
                message: match exit_code {
                    Some(1641) => "Uninstall completed and Windows initiated a restart.".into(),
                    Some(3010) => "Uninstall completed. A restart is required.".into(),
                    _ if success => "Uninstall completed.".into(),
                    Some(code) => format!("Windows Installer reported failure (exit code {code})."),
                    None => "Windows Installer ended without an exit code.".into(),
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

fn trusted_msi_product_code(program: &InstalledProgram) -> Result<String, String> {
    if !is_machine_registry_key(&program.registry_key) {
        return Err(
            "Cove will not run per-user or user-writable uninstall commands while elevated. Use Windows Settings for this program."
                .into(),
        );
    }
    let product_code = program
        .registry_key
        .rsplit('\\')
        .next()
        .and_then(normalize_product_code)
        .ok_or_else(|| {
            "This elevated build only runs machine-wide Windows Installer product-code uninstallers. Use Windows Settings for this program."
                .to_string()
        })?;
    let registered_as_msi = [&program.quiet_uninstall_string, &program.uninstall_string]
        .into_iter()
        .filter(|command| !command.trim().is_empty())
        .any(|command| command_references_product(command, &product_code));
    if !registered_as_msi {
        return Err(
            "The registered uninstall command is not a matching Windows Installer product-code command, so Cove refused to run it elevated."
                .into(),
        );
    }
    Ok(product_code)
}

fn is_machine_registry_key(registry_key: &str) -> bool {
    registry_key
        .get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("HKLM\\"))
}

fn normalize_product_code(value: &str) -> Option<String> {
    let value = value.trim();
    let bytes = value.as_bytes();
    if bytes.len() != 38
        || bytes.first() != Some(&b'{')
        || bytes.last() != Some(&b'}')
        || ![9, 14, 19, 24]
            .into_iter()
            .all(|index| bytes[index] == b'-')
        || !bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 0 | 37) && matches!(*byte, b'{' | b'}')
                || matches!(index, 9 | 14 | 19 | 24) && *byte == b'-'
                || !matches!(index, 0 | 9 | 14 | 19 | 24 | 37) && byte.is_ascii_hexdigit()
        })
    {
        return None;
    }
    Some(value.to_ascii_uppercase())
}

fn command_references_product(command: &str, product_code: &str) -> bool {
    let Some(argv) = split_command_for_policy(command) else {
        return false;
    };
    let Some(executable) = argv.first() else {
        return false;
    };
    let is_msiexec = std::path::Path::new(executable)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name.eq_ignore_ascii_case("msiexec") || name.eq_ignore_ascii_case("msiexec.exe")
        });
    if !is_msiexec {
        return false;
    }
    let args = &argv[1..];
    args.iter().enumerate().any(|(index, arg)| {
        if arg.eq_ignore_ascii_case("/i") || arg.eq_ignore_ascii_case("/x") {
            return args
                .get(index + 1)
                .and_then(|next| normalize_product_code(next))
                .is_some_and(|code| code == product_code);
        }
        arg.get(..2)
            .filter(|prefix| prefix.eq_ignore_ascii_case("/i") || prefix.eq_ignore_ascii_case("/x"))
            .and_then(|_| arg.get(2..))
            .and_then(normalize_product_code)
            .is_some_and(|code| code == product_code)
    })
}

fn split_command_for_policy(command: &str) -> Option<Vec<String>> {
    #[cfg(target_os = "windows")]
    {
        split_windows_command_line(command).ok().map(|parts| {
            parts
                .into_iter()
                .map(|part| part.to_string_lossy().into_owned())
                .collect()
        })
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Inventory stubs and policy unit tests only use simple MSI command
        // forms. Windows uses CommandLineToArgvW above for the authoritative
        // parsing before execution.
        let parts: Vec<String> = command
            .split_whitespace()
            .map(|part| part.trim_matches('"').to_string())
            .collect();
        (!parts.is_empty()).then_some(parts)
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
pub fn run_uninstall(_program: &InstalledProgram) -> UninstallResult {
    UninstallResult {
        success: true,
        message: "[stub] Uninstall would run on Windows.".into(),
        output: String::new(),
    }
}

#[cfg(target_os = "windows")]
pub fn scan_leftovers(
    _name: &str,
    _publisher: &str,
    install_location: &str,
    registry_key: &str,
) -> ScanResult {
    let candidate = validate_install_location_candidate(install_location, registry_key)
        .ok()
        .map(|(path, size_bytes)| Leftover {
            path: path.to_string_lossy().into_owned(),
            category: "Folder".into(),
            size_bytes,
        });
    ScanResult {
        total_size_bytes: candidate.as_ref().map_or(0, |item| item.size_bytes),
        leftovers: candidate.into_iter().collect(),
    }
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
fn validate_install_location_candidate(
    install_location: &str,
    registry_key: &str,
) -> Result<(std::path::PathBuf, u64), String> {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const GENERIC_OR_SHARED: &[&str] = &[
        "amd",
        "common",
        "common files",
        "google",
        "intel",
        "microsoft",
        "nvidia",
        "package cache",
        "program files",
        "program files (x86)",
        "realtek",
        "windows",
        "windows defender",
        "windowsapps",
    ];

    if !is_machine_registry_key(registry_key) || install_location.trim().is_empty() {
        return Err("Only nonempty HKLM install locations can be considered.".into());
    }
    let path = std::path::PathBuf::from(install_location.trim());
    if !path.is_absolute() {
        return Err("The registered install location is not absolute.".into());
    }
    if path.components().any(|component| {
        matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )
    }) {
        return Err("The registered install location contains a relative path component.".into());
    }
    let leaf = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| "The registered install location is a filesystem root.".to_string())?;
    if GENERIC_OR_SHARED
        .iter()
        .any(|generic| leaf.eq_ignore_ascii_case(generic))
    {
        return Err("The registered install location is a generic or shared folder.".into());
    }

    // `symlink_metadata(target)` detects a reparse point at the final component,
    // but Windows still follows reparse points in earlier components. Inspect
    // every existing ancestor as well as every descendant before offering it.
    for ancestor in path.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|error| {
            format!("Could not validate the registered install location: {error}")
        })?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err("The registered install location traverses a reparse point.".into());
        }
    }

    let mut total = 0u64;
    let mut pending = vec![path.clone()];
    let mut visited = 0usize;
    while let Some(current) = pending.pop() {
        visited = visited.saturating_add(1);
        if visited > 1_000_000 {
            return Err("The registered install location is too large to validate safely.".into());
        }
        let metadata = std::fs::symlink_metadata(&current).map_err(|error| {
            format!("Could not validate the registered install location: {error}")
        })?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err("The registered install location contains a reparse point.".into());
        }
        if metadata.is_dir() {
            for entry in std::fs::read_dir(&current).map_err(|error| {
                format!("Could not inspect the registered install location: {error}")
            })? {
                pending.push(
                    entry
                        .map_err(|error| {
                            format!("Could not inspect the registered install location: {error}")
                        })?
                        .path(),
                );
            }
        } else {
            total = total.saturating_add(metadata.len());
        }
    }
    Ok((path, total))
}

#[cfg(target_os = "windows")]
pub fn remove_leftovers(paths: &[String]) -> Vec<(String, bool, String)> {
    paths
        .iter()
        .map(|path| {
            (
                path.clone(),
                false,
                "Automatic leftover deletion is disabled in this release because folder ownership cannot be proven race-free. Remove the reviewed folder manually if appropriate."
                    .to_string(),
            )
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
fn run_ps_checked(script: &str) -> Result<String, String> {
    let output = optimizer_core::powershell(script)
        .output()
        .map_err(|error| format!("Could not start the installed-program query: {error}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if detail.is_empty() {
            "The installed-program query failed.".into()
        } else {
            format!("The installed-program query failed: {detail}")
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
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
            can_uninstall: false,
            uninstall_reason: String::new(),
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
            can_uninstall: false,
            uninstall_reason: String::new(),
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
            can_uninstall: false,
            uninstall_reason: String::new(),
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
            can_uninstall: false,
            uninstall_reason: String::new(),
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
            can_uninstall: false,
            uninstall_reason: String::new(),
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
            can_uninstall: false,
            uninstall_reason: String::new(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRODUCT: &str = "{00112233-4455-6677-8899-AABBCCDDEEFF}";

    fn program(registry_key: &str, command: &str) -> InstalledProgram {
        InstalledProgram {
            id: "test".into(),
            name: "Test Product".into(),
            publisher: "Test".into(),
            version: "1".into(),
            install_date: String::new(),
            size_bytes: 0,
            uninstall_string: command.into(),
            quiet_uninstall_string: String::new(),
            install_location: r"C:\Program Files\Test Product".into(),
            registry_key: registry_key.into(),
            is_system: false,
            can_uninstall: false,
            uninstall_reason: String::new(),
        }
    }

    #[test]
    fn product_code_validation_is_strict_and_normalized() {
        assert_eq!(
            normalize_product_code(&PRODUCT.to_ascii_lowercase()).as_deref(),
            Some(PRODUCT)
        );
        assert!(normalize_product_code("{00112233-4455-6677-8899-AABBCCDDEEFG}").is_none());
        assert!(normalize_product_code("00112233-4455-6677-8899-AABBCCDDEEFF").is_none());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn elevated_uninstall_policy_accepts_only_matching_hklm_msi() {
        let allowed = program(
            &format!(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{PRODUCT}"),
            &format!("MsiExec.exe /I{PRODUCT}"),
        );
        assert_eq!(trusted_msi_product_code(&allowed).as_deref(), Ok(PRODUCT));

        let per_user = program(
            &format!(r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{PRODUCT}"),
            &format!("MsiExec.exe /X {PRODUCT}"),
        );
        assert!(trusted_msi_product_code(&per_user).is_err());

        let arbitrary_exe = program(
            &format!(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{PRODUCT}"),
            r"C:\Users\Alice\AppData\Local\evil.exe",
        );
        assert!(trusted_msi_product_code(&arbitrary_exe).is_err());

        let other_product = program(
            &format!(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{PRODUCT}"),
            "MsiExec.exe /X{11111111-2222-3333-4444-555555555555}",
        );
        assert!(trusted_msi_product_code(&other_product).is_err());
    }

    #[test]
    fn inventory_capability_explains_unsupported_programs() {
        let per_user = program(
            &format!(r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{PRODUCT}"),
            &format!("MsiExec.exe /X {PRODUCT}"),
        );
        let capability = uninstall_capability(&per_user);
        assert!(!capability.can_uninstall);
        assert!(capability.reason.contains("per-user"));

        let non_msi = program(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Example",
            r"C:\Program Files\Example\uninstall.exe",
        );
        let capability = uninstall_capability(&non_msi);
        assert!(!capability.can_uninstall);
        assert!(capability.reason.contains("Windows Installer"));
    }

    #[test]
    fn installed_program_inventory_script_fails_closed() {
        let script = include_str!("list_programs.ps1");
        assert!(script.contains("$ErrorActionPreference = 'Stop'"));
        assert!(script.contains("required = $true"));
        assert!(script.contains("Get-ChildItem -LiteralPath $root.path -ErrorAction Stop"));
        assert!(script.contains("Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction Stop"));
        assert!(!script.contains("-ErrorAction SilentlyContinue"));
    }
}
