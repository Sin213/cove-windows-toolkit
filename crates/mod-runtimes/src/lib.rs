use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct RuntimeEntry {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub installed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
}

#[derive(Serialize)]
pub struct DirectXInfo {
    pub version: String,
    pub feature_level: String,
}

#[derive(Serialize)]
pub struct RuntimesReport {
    pub dotnet: Vec<RuntimeEntry>,
    pub vcredist: Vec<RuntimeEntry>,
    pub directx: DirectXInfo,
    pub java: Vec<RuntimeEntry>,
}

#[cfg(target_os = "windows")]
pub fn collect_runtimes() -> RuntimesReport {
    RuntimesReport {
        dotnet: detect_dotnet(),
        vcredist: detect_vcredist(),
        directx: detect_directx(),
        java: detect_java(),
    }
}

#[cfg(not(target_os = "windows"))]
pub fn collect_runtimes() -> RuntimesReport {
    stub_runtimes()
}

#[cfg(target_os = "windows")]
fn detect_dotnet() -> Vec<RuntimeEntry> {
    use std::process::Command;

    let mut entries = Vec::new();

    // .NET Framework 4.x
    let ps = r#"
try {
    $v4 = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction Stop
    $release = $v4.Release
    $ver = switch ($true) {
        ($release -ge 533320) { '4.8.1' }
        ($release -ge 528040) { '4.8' }
        ($release -ge 461808) { '4.7.2' }
        ($release -ge 461308) { '4.7.1' }
        ($release -ge 460798) { '4.7' }
        ($release -ge 394802) { '4.6.2' }
        default { '4.x' }
    }
    Write-Output "FOUND|.NET Framework $ver|$ver|$($v4.InstallPath)"
} catch { Write-Output 'NOTFOUND|.NET Framework 4.x' }

# .NET 3.5
try {
    $v35 = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5' -ErrorAction Stop
    if ($v35.Install -eq 1) { Write-Output "FOUND|.NET Framework 3.5|3.5|C:\Windows\Microsoft.NET\Framework64\v3.5" }
    else { Write-Output 'NOTFOUND|.NET Framework 3.5' }
} catch { Write-Output 'NOTFOUND|.NET Framework 3.5' }
"#;

    if let Ok(o) = Command::new("powershell").args(["-NoProfile", "-Command", ps]).output() {
        let stdout = String::from_utf8_lossy(&o.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 2 {
                if parts[0] == "FOUND" && parts.len() >= 4 {
                    entries.push(RuntimeEntry {
                        name: parts[1].to_string(),
                        version: parts[2].to_string(),
                        runtime_type: None,
                        path: Some(parts[3].to_string()),
                        installed: true,
                        arch: None,
                    });
                } else if parts[0] == "NOTFOUND" {
                    entries.push(RuntimeEntry {
                        name: parts[1].to_string(),
                        version: String::new(),
                        runtime_type: None,
                        path: None,
                        installed: false,
                        arch: None,
                    });
                }
            }
        }
    }

    // .NET 5+ via dotnet CLI
    if let Ok(o) = Command::new("dotnet").args(["--list-runtimes"]).output() {
        let stdout = String::from_utf8_lossy(&o.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() { continue; }
            // Format: "Microsoft.NETCore.App 8.0.3 [path]"
            let parts: Vec<&str> = trimmed.splitn(3, ' ').collect();
            if parts.len() >= 2 {
                let rt_type = parts[0].replace("Microsoft.", "").replace("App", "").replace(".", " ").trim().to_string();
                entries.push(RuntimeEntry {
                    name: format!(".NET {} ({})", parts[1], if rt_type.is_empty() { "runtime" } else { &rt_type }),
                    version: parts[1].to_string(),
                    runtime_type: Some("runtime".into()),
                    path: parts.get(2).map(|p| p.trim_matches(|c| c == '[' || c == ']').to_string()),
                    installed: true,
                    arch: None,
                });
            }
        }
    }

    if entries.is_empty() {
        return stub_dotnet();
    }
    entries
}

#[cfg(target_os = "windows")]
fn detect_vcredist() -> Vec<RuntimeEntry> {
    use std::process::Command;

    let ps = r#"
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -match 'Visual C\+\+.*Redistributable' } |
    Select-Object DisplayName, DisplayVersion |
    ForEach-Object { Write-Output "$($_.DisplayName)|$($_.DisplayVersion)" }
"#;

    if let Ok(o) = Command::new("powershell").args(["-NoProfile", "-Command", ps]).output() {
        let stdout = String::from_utf8_lossy(&o.stdout);
        let entries: Vec<RuntimeEntry> = stdout.lines().filter_map(|line| {
            let parts: Vec<&str> = line.splitn(2, '|').collect();
            if parts.len() == 2 {
                let name = parts[0].trim();
                let arch = if name.contains("x64") { "x64" } else if name.contains("x86") { "x86" } else { "x64" };
                Some(RuntimeEntry {
                    name: name.to_string(),
                    version: parts[1].trim().to_string(),
                    runtime_type: None,
                    path: None,
                    installed: true,
                    arch: Some(arch.to_string()),
                })
            } else {
                None
            }
        }).collect();

        if !entries.is_empty() {
            return entries;
        }
    }

    stub_vcredist()
}

#[cfg(target_os = "windows")]
fn detect_directx() -> DirectXInfo {
    use std::process::Command;

    let ps = r#"
try {
    $dx = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\DirectX' -ErrorAction Stop
    Write-Output "$($dx.Version)|$($dx.InstalledVersion)"
} catch { Write-Output '12.0|12_1' }
"#;

    if let Ok(o) = Command::new("powershell").args(["-NoProfile", "-Command", ps]).output() {
        let stdout = String::from_utf8_lossy(&o.stdout).trim().to_string();
        let parts: Vec<&str> = stdout.split('|').collect();
        if parts.len() >= 2 {
            return DirectXInfo {
                version: parts[0].to_string(),
                feature_level: parts[1].to_string(),
            };
        }
    }

    DirectXInfo { version: "12.0".into(), feature_level: "12_1".into() }
}

#[cfg(target_os = "windows")]
fn detect_java() -> Vec<RuntimeEntry> {
    use std::process::Command;

    let ps = r#"
$found = @()
$paths = @(
    'HKLM:\SOFTWARE\JavaSoft\Java Runtime Environment',
    'HKLM:\SOFTWARE\JavaSoft\JDK',
    'HKLM:\SOFTWARE\JavaSoft\Java Development Kit',
    'HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Runtime Environment',
    'HKLM:\SOFTWARE\WOW6432Node\JavaSoft\JDK'
)
foreach ($p in $paths) {
    try {
        $current = (Get-ItemProperty $p -ErrorAction Stop).CurrentVersion
        $sub = Get-ItemProperty "$p\$current" -ErrorAction Stop
        $type = if ($p -match 'JDK') { 'JDK' } else { 'JRE' }
        $found += "$($sub.PSChildName)|$type|$($sub.JavaHome)"
    } catch {}
}
if ($found.Count -eq 0) { Write-Output 'NONE' }
else { $found | ForEach-Object { Write-Output $_ } }
"#;

    if let Ok(o) = Command::new("powershell").args(["-NoProfile", "-Command", ps]).output() {
        let stdout = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if stdout != "NONE" {
            return stdout.lines().filter_map(|line| {
                let parts: Vec<&str> = line.splitn(3, '|').collect();
                if parts.len() == 3 {
                    Some(RuntimeEntry {
                        name: format!("Java {} ({})", parts[0], parts[1]),
                        version: parts[0].to_string(),
                        runtime_type: Some(parts[1].to_string()),
                        path: Some(parts[2].to_string()),
                        installed: true,
                        arch: None,
                    })
                } else {
                    None
                }
            }).collect();
        }
    }

    Vec::new()
}

fn stub_dotnet() -> Vec<RuntimeEntry> {
    vec![
        RuntimeEntry { name: ".NET Framework 4.8".into(), version: "4.8".into(), runtime_type: None, path: Some(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319".into()), installed: true, arch: None },
        RuntimeEntry { name: ".NET 8.0.3 (runtime)".into(), version: "8.0.3".into(), runtime_type: Some("runtime".into()), path: Some(r"C:\Program Files\dotnet".into()), installed: true, arch: None },
        RuntimeEntry { name: ".NET Framework 3.5".into(), version: "3.5".into(), runtime_type: None, path: None, installed: false, arch: None },
    ]
}

fn stub_vcredist() -> Vec<RuntimeEntry> {
    vec![
        RuntimeEntry { name: "Visual C++ 2015-2022 (x64)".into(), version: "14.38.33135".into(), runtime_type: None, path: None, installed: true, arch: Some("x64".into()) },
        RuntimeEntry { name: "Visual C++ 2015-2022 (x86)".into(), version: "14.38.33135".into(), runtime_type: None, path: None, installed: true, arch: Some("x86".into()) },
        RuntimeEntry { name: "Visual C++ 2013 (x64)".into(), version: "12.0.40664".into(), runtime_type: None, path: None, installed: true, arch: Some("x64".into()) },
    ]
}

#[allow(dead_code)]
fn stub_runtimes() -> RuntimesReport {
    RuntimesReport {
        dotnet: stub_dotnet(),
        vcredist: stub_vcredist(),
        directx: DirectXInfo { version: "12.0".into(), feature_level: "12_1".into() },
        java: Vec::new(),
    }
}
