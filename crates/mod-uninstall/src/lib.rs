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
fn run_removal(script: &str) -> (bool, String) {
    match optimizer_core::silent_cmd("powershell")
        .args(["-NoProfile", "-Command", script]).output()
    {
        Ok(o) if o.status.success() => (true, "Removed".into()),
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            let msg = err.lines()
                .map(str::trim)
                .find(|s| !s.is_empty())
                .unwrap_or("Removal failed")
                .to_string();
            (false, msg)
        }
        Err(e) => (false, e.to_string()),
    }
}

/// Hard denylist so the remover can never delete a core Windows component, even
/// if the scanner regresses or a path is passed directly.
#[cfg(target_os = "windows")]
fn is_protected_leftover(p: &str) -> bool {
    if let Some(svc) = p.strip_prefix("Service: ") {
        let name = svc.split(" (").next().unwrap_or(svc).trim().to_lowercase();
        const PROT: &[&str] = &[
            "windefend", "wdnissvc", "mdcoresvc", "sense", "wscsvc", "securityhealthservice",
            "wdfilter", "wdboot", "webthreatdefsvc", "mpssvc", "wuauserv", "bits", "cryptsvc",
            "trustedinstaller", "msiserver", "winmgmt", "eventlog", "schedule", "dnscache", "nsi",
            "dcomlaunch", "rpcss", "lanmanserver", "lanmanworkstation", "wlansvc", "dhcp", "dot3svc",
            "winhttpautoproxysvc", "sysmain", "spooler", "samss", "netlogon", "gpsvc", "profsvc",
        ];
        return PROT.contains(&name.as_str());
    }
    let norm = p.trim_end_matches('\\').to_lowercase();
    if p.starts_with("HK") {
        const PROT_REG: &[&str] = &[
            "hklm\\software\\microsoft", "hklm\\software\\wow6432node\\microsoft",
            "hkcu\\software\\microsoft", "hklm\\software\\windows",
            "hklm\\software\\wow6432node\\windows", "hklm\\software\\policies",
            "hkcu\\software\\policies", "hklm\\software\\classes", "hkcu\\software\\classes",
        ];
        return PROT_REG.contains(&norm.as_str());
    }
    let env = |k: &str| std::env::var(k).unwrap_or_default().to_lowercase();
    let (pf, pd, lad, ad, sysroot) = (
        env("ProgramFiles"), env("ProgramData"), env("LOCALAPPDATA"), env("APPDATA"), env("SystemRoot"),
    );
    let protected = [
        format!("{}\\microsoft", pd),
        format!("{}\\microsoft", lad),
        format!("{}\\microsoft", ad),
        format!("{}\\common files", pf),
        format!("{}\\windows defender", pf),
        format!("{}\\windowsapps", pf),
        format!("{}\\package cache", pd),
        format!("{}\\packages", lad),
        sysroot,
    ];
    protected.iter().any(|d| !d.is_empty() && norm == d.trim_end_matches('\\'))
}

/// Delete a file/folder. After killing any process running from inside it, try a
/// normal recursive delete; if something is locked (e.g. a shell-extension DLL
/// loaded by Explorer), schedule it for deletion on the next reboot.
#[cfg(target_os = "windows")]
fn remove_file_or_folder(quoted: &str) -> (bool, String) {
    let script = format!(
        r#"$t = '{0}'
Get-Process -ErrorAction SilentlyContinue | Where-Object {{ $_.Path -and $_.Path.StartsWith($t, [System.StringComparison]::OrdinalIgnoreCase) }} | Stop-Process -Force -ErrorAction SilentlyContinue
try {{
    Remove-Item -LiteralPath $t -Recurse -Force -ErrorAction Stop
    Write-Output 'OK'
}} catch {{
    try {{
        $sig = '[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool MoveFileEx(string a, string b, int f);'
        $api = Add-Type -MemberDefinition $sig -Name MFE -Namespace CoveWin32 -PassThru
        $DELAY = 4
        if (Test-Path -LiteralPath $t -PathType Container) {{
            Get-ChildItem -LiteralPath $t -Recurse -Force -File -ErrorAction SilentlyContinue | Sort-Object {{ $_.FullName.Length }} -Descending | ForEach-Object {{ [void]$api::MoveFileEx($_.FullName, $null, $DELAY) }}
            Get-ChildItem -LiteralPath $t -Recurse -Force -Directory -ErrorAction SilentlyContinue | Sort-Object {{ $_.FullName.Length }} -Descending | ForEach-Object {{ [void]$api::MoveFileEx($_.FullName, $null, $DELAY) }}
        }}
        [void]$api::MoveFileEx($t, $null, $DELAY)
        Write-Output 'SCHEDULED'
    }} catch {{
        Write-Output ('ERR|' + $_.Exception.Message)
    }}
}}"#,
        quoted
    );
    match optimizer_core::silent_cmd("powershell").args(["-NoProfile", "-Command", &script]).output() {
        Ok(o) => {
            let out = String::from_utf8_lossy(&o.stdout);
            let last = out.lines().map(str::trim).filter(|s| !s.is_empty()).last().unwrap_or("");
            if last == "OK" {
                (true, "Removed".into())
            } else if last == "SCHEDULED" {
                (true, "In use — will be removed after you restart Windows.".into())
            } else if let Some(m) = last.strip_prefix("ERR|") {
                (false, m.to_string())
            } else {
                let err = String::from_utf8_lossy(&o.stderr);
                let msg = err.lines().map(str::trim).find(|s| !s.is_empty()).unwrap_or("Removal failed").to_string();
                (false, msg)
            }
        }
        Err(e) => (false, e.to_string()),
    }
}

#[cfg(target_os = "windows")]
pub fn remove_leftovers(paths: &[String]) -> Vec<(String, bool, String)> {
    paths.iter().map(|p| {
        // Final backstop: refuse to touch protected Windows components even if the
        // scanner (or a caller) hands us one.
        if is_protected_leftover(p) {
            return (p.clone(), false, "Refused: this is a protected Windows component.".to_string());
        }
        let q = p.replace('\'', "''");
        let (ok, msg) = if let Some(svc) = p.strip_prefix("Service: ") {
            // Encoded as "Service: <ServiceName> (<DisplayName>)" - stop then delete by name.
            let name = svc.split(" (").next().unwrap_or(svc).trim().replace('\'', "''");
            run_removal(&format!(
                "Stop-Service -Name '{0}' -Force -ErrorAction SilentlyContinue; \
                 $r = sc.exe delete '{0}'; \
                 if ($LASTEXITCODE -ne 0) {{ Write-Error \"sc delete failed: $r\" }}",
                name
            ))
        } else if let Some(task) = p.strip_prefix("Task: ") {
            // Encoded as "Task: <TaskPath><TaskName>"; split on the final backslash.
            let full = task.trim();
            let (tp, tn) = match full.rfind('\\') {
                Some(i) => (&full[..=i], &full[i + 1..]),
                None => ("\\", full),
            };
            run_removal(&format!(
                "Unregister-ScheduledTask -TaskName '{}' -TaskPath '{}' -Confirm:$false -ErrorAction Stop",
                tn.replace('\'', "''"), tp.replace('\'', "''")
            ))
        } else if p.starts_with("HK") {
            run_removal(&format!(
                "Remove-Item -Path 'Registry::{}' -Recurse -Force -ErrorAction Stop", q
            ))
        } else {
            // File/folder: remove now, or schedule locked files for reboot.
            remove_file_or_folder(&q)
        };
        (p.clone(), ok, msg)
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
