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
    pub outdated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_url: Option<String>,
}

#[derive(Serialize)]
pub struct DirectXInfo {
    pub version: String,
    pub feature_level: String,
    pub download_url: String,
}

#[derive(Serialize)]
pub struct RuntimesReport {
    pub dotnet: Vec<RuntimeEntry>,
    pub vcredist: Vec<RuntimeEntry>,
    pub directx: DirectXInfo,
    pub java: Vec<RuntimeEntry>,
    pub coverage: RuntimeCoverage,
}

#[derive(Serialize)]
pub struct RuntimeCoverage {
    pub dotnet: ProbeState,
    pub vcredist: ProbeState,
    pub directx: ProbeState,
    pub java: ProbeState,
}

#[derive(Serialize)]
pub struct ProbeState {
    pub complete: bool,
    pub errors: Vec<String>,
}

impl ProbeState {
    fn from_errors(errors: Vec<String>) -> Self {
        Self {
            complete: errors.is_empty(),
            errors,
        }
    }
}

#[cfg(target_os = "windows")]
pub fn collect_runtimes() -> RuntimesReport {
    let (dotnet, dotnet_state) = detect_dotnet();
    let (vcredist, vcredist_state) = detect_vcredist();
    let (directx, directx_state) = detect_directx();
    let (java, java_state) = detect_java();
    RuntimesReport {
        dotnet,
        vcredist,
        directx,
        java,
        coverage: RuntimeCoverage {
            dotnet: dotnet_state,
            vcredist: vcredist_state,
            directx: directx_state,
            java: java_state,
        },
    }
}

#[cfg(not(target_os = "windows"))]
pub fn collect_runtimes() -> RuntimesReport {
    stub_runtimes()
}

#[cfg(target_os = "windows")]
fn detect_dotnet() -> (Vec<RuntimeEntry>, ProbeState) {
    let mut entries = Vec::new();
    let mut errors = Vec::new();

    // .NET Framework 4.x
    let ps = r#"
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full') { try {
    $v4 = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction Stop
    $release = $v4.Release
    $ver = switch ($true) {
        ($release -ge 533320) { '4.8.1'; break }
        ($release -ge 528040) { '4.8'; break }
        ($release -ge 461808) { '4.7.2'; break }
        ($release -ge 461308) { '4.7.1'; break }
        ($release -ge 460798) { '4.7'; break }
        ($release -ge 394802) { '4.6.2'; break }
        default { '4.x' }
    }
    Write-Output "FOUND|.NET Framework $ver|$ver|$($v4.InstallPath)"
} catch { Write-Output ('ERROR|.NET Framework 4.x|' + $_.Exception.Message) } }
else { Write-Output 'NOTFOUND|.NET Framework 4.x' }

# .NET 3.5
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5') { try {
    $v35 = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5' -ErrorAction Stop
    if ($v35.Install -eq 1) { Write-Output "FOUND|.NET Framework 3.5|3.5|C:\Windows\Microsoft.NET\Framework64\v3.5" }
    else { Write-Output 'NOTFOUND|.NET Framework 3.5' }
} catch { Write-Output ('ERROR|.NET Framework 3.5|' + $_.Exception.Message) } }
else { Write-Output 'NOTFOUND|.NET Framework 3.5' }
"#;

    match optimizer_core::powershell(ps).output() {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split('|').collect();
                if parts.len() >= 2 {
                    if parts[0] == "FOUND" && parts.len() >= 4 {
                        let ver = parts[2].to_string();
                        let outdated = is_dotnet_fw_outdated(&ver);
                        entries.push(RuntimeEntry {
                            name: parts[1].to_string(),
                            version: ver,
                            runtime_type: None,
                            path: Some(parts[3].to_string()),
                            installed: true,
                            arch: None,
                            outdated,
                            download_url: if outdated {
                                Some(DOTNET_FW_URL.into())
                            } else {
                                None
                            },
                        });
                    } else if parts[0] == "NOTFOUND" {
                        let name = parts[1].to_string();
                        let url = if name.contains("3.5") {
                            DOTNET_FW35_URL
                        } else {
                            DOTNET_FW_URL
                        };
                        entries.push(RuntimeEntry {
                            name,
                            version: String::new(),
                            runtime_type: None,
                            path: None,
                            installed: false,
                            arch: None,
                            outdated: false,
                            download_url: Some(url.into()),
                        });
                    } else if parts[0] == "ERROR" {
                        errors.push(
                            parts
                                .get(2)
                                .copied()
                                .unwrap_or(".NET registry query failed")
                                .to_string(),
                        );
                    } else {
                        errors.push(format!("Unrecognized .NET probe record: {line}"));
                    }
                }
            }
        }
        Ok(o) => errors.push(format!(
            ".NET registry query failed: {}",
            optimizer_core::decode_console_output(&o.stderr).trim()
        )),
        Err(error) => errors.push(format!("Could not start .NET registry query: {error}")),
    }

    // .NET 5+ via dotnet CLI
    let dotnet = std::env::var_os("ProgramFiles")
        .map(std::path::PathBuf::from)
        .map(|path| path.join("dotnet").join("dotnet.exe"));
    if let Some(dotnet) = dotnet
        && dotnet.is_file()
    {
        match optimizer_core::silent_cmd(&dotnet.to_string_lossy())
            .args(["--list-runtimes"])
            .output()
        {
            Ok(o) if o.status.success() => {
                for line in optimizer_core::decode_console_output(&o.stdout).lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    // Format: "Microsoft.NETCore.App 8.0.3 [path]"
                    let parts: Vec<&str> = trimmed.splitn(3, ' ').collect();
                    if parts.len() >= 2 {
                        let rt_type = parts[0]
                            .replace("Microsoft.", "")
                            .replace("App", "")
                            .replace(".", " ")
                            .trim()
                            .to_string();
                        let ver = parts[1].to_string();
                        let (outdated, url) = dotnet_core_status(&ver);
                        entries.push(RuntimeEntry {
                            name: format!(
                                ".NET {} ({})",
                                ver,
                                if rt_type.is_empty() {
                                    "runtime"
                                } else {
                                    &rt_type
                                }
                            ),
                            version: ver,
                            runtime_type: Some("runtime".into()),
                            path: parts
                                .get(2)
                                .map(|p| p.trim_matches(|c| c == '[' || c == ']').to_string()),
                            installed: true,
                            arch: None,
                            outdated,
                            download_url: url,
                        });
                    }
                }
            }
            Ok(o) => errors.push(format!(
                ".NET runtime query failed: {}",
                optimizer_core::decode_console_output(&o.stderr).trim()
            )),
            Err(error) => errors.push(format!("Could not start dotnet.exe: {error}")),
        }
    }

    // No fabricated fallback: report only what was actually detected.
    (entries, ProbeState::from_errors(errors))
}

#[cfg(target_os = "windows")]
fn detect_vcredist() -> (Vec<RuntimeEntry>, ProbeState) {
    let ps = r#"
$ErrorActionPreference = 'Stop'
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction Stop |
    Where-Object { $_.DisplayName -match 'Visual C\+\+.*Redistributable' } |
    Select-Object DisplayName, DisplayVersion |
    ForEach-Object { Write-Output "$($_.DisplayName)|$($_.DisplayVersion)" }
"#;

    match optimizer_core::powershell(ps).output() {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let mut errors = Vec::new();
            let entries: Vec<RuntimeEntry> = stdout
                .lines()
                .filter_map(|line| {
                    let parts: Vec<&str> = line.splitn(2, '|').collect();
                    if parts.len() == 2 {
                        let name = parts[0].trim();
                        let ver = parts[1].trim().to_string();
                        let arch = if name.contains("x64") {
                            "x64"
                        } else if name.contains("x86") {
                            "x86"
                        } else {
                            "Unknown"
                        };
                        let outdated = is_vcredist_outdated(&ver);
                        let url = if arch == "x86" {
                            VCREDIST_X86_URL
                        } else {
                            VCREDIST_X64_URL
                        };
                        Some(RuntimeEntry {
                            name: name.to_string(),
                            version: ver,
                            runtime_type: None,
                            path: None,
                            installed: true,
                            arch: Some(arch.to_string()),
                            outdated,
                            download_url: if outdated { Some(url.into()) } else { None },
                        })
                    } else {
                        errors.push(format!("Could not parse Visual C++ runtime record: {line}"));
                        None
                    }
                })
                .collect();

            (entries, ProbeState::from_errors(errors))
        }
        Ok(o) => (
            Vec::new(),
            ProbeState::from_errors(vec![format!(
                "Visual C++ runtime query failed: {}",
                optimizer_core::decode_console_output(&o.stderr).trim()
            )]),
        ),
        Err(error) => (
            Vec::new(),
            ProbeState::from_errors(vec![format!(
                "Could not start Visual C++ runtime query: {error}"
            )]),
        ),
    }
}

#[cfg(target_os = "windows")]
fn detect_directx() -> (DirectXInfo, ProbeState) {
    // The legacy HKLM\...\DirectX values (Version string / InstalledVersion
    // REG_BINARY) are meaningless on modern Windows. Use dxdiag, which reports
    // the real DirectX version and the GPU's supported feature levels.
    let ps = r#"
$tmp = [IO.Path]::Combine([IO.Path]::GetTempPath(), ([IO.Path]::GetRandomFileName() + '.xml'))
# Do NOT use -Wait: dxdiag can hang indefinitely on VMs / GPU-less or policy-
# restricted machines, which would block the whole scan. Launch async, poll for
# the output file up to 15s, then force-kill dxdiag if it is still running.
$dxdiag = Join-Path $env:SystemRoot 'System32\dxdiag.exe'
$p = Start-Process -FilePath $dxdiag -ArgumentList "/x `"$tmp`"" -WindowStyle Hidden -PassThru
$n = 0
while ((-not (Test-Path $tmp)) -or ((Get-Item -LiteralPath $tmp -ErrorAction SilentlyContinue).Length -eq 0)) {
    if ($n -ge 30) { break }
    Start-Sleep -Milliseconds 500; $n++
}
if ($p -and -not $p.HasExited) { try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {} }
try {
    [xml]$x = Get-Content $tmp -Raw -ErrorAction Stop
    $ver = ($x.DxDiag.SystemInformation.DirectXVersion -replace 'DirectX\s*','').Trim()
    $dev = $x.DxDiag.DisplayDevices.DisplayDevice
    if ($dev -is [System.Array]) { $dev = $dev[0] }
    $fl = (($dev.FeatureLevels -split ',')[0]).Trim()
    if (-not $ver) { $ver = 'Unknown' }
    if (-not $fl) { $fl = 'Unknown' }
    Write-Output "$ver|$fl"
} catch { Write-Output ('ERROR|' + $_.Exception.Message) }
finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
"#;

    if let Ok(o) = optimizer_core::powershell(ps).output() {
        let stdout = String::from_utf8_lossy(&o.stdout).trim().to_string();
        let parts: Vec<&str> = stdout.split('|').collect();
        if parts.len() >= 2 && !parts[0].is_empty() {
            if parts[0] != "ERROR" && parts[0] != "Unknown" && parts[1] != "Unknown" {
                return (
                    DirectXInfo {
                        version: parts[0].to_string(),
                        feature_level: parts[1].to_string(),
                        download_url: DIRECTX_URL.into(),
                    },
                    ProbeState::from_errors(Vec::new()),
                );
            }
            let error = if parts[0] == "ERROR" {
                parts[1].to_string()
            } else {
                "dxdiag did not report a DirectX version and feature level".into()
            };
            return (
                DirectXInfo {
                    version: "Unknown".into(),
                    feature_level: "Unknown".into(),
                    download_url: DIRECTX_URL.into(),
                },
                ProbeState::from_errors(vec![error]),
            );
        }
    }

    (
        DirectXInfo {
            version: "Unknown".into(),
            feature_level: "Unknown".into(),
            download_url: DIRECTX_URL.into(),
        },
        ProbeState::from_errors(vec!["DirectX query failed or returned invalid data".into()]),
    )
}

#[cfg(target_os = "windows")]
fn detect_java() -> (Vec<RuntimeEntry>, ProbeState) {
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
        if (Test-Path -LiteralPath $p -ErrorAction Stop) {
            foreach ($key in Get-ChildItem -LiteralPath $p -ErrorAction Stop) {
                $sub = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
                $type = if ($p -match 'JDK') { 'JDK' } else { 'JRE' }
                if ($sub.JavaHome) { $found += "$($key.PSChildName)|$type|$($sub.JavaHome)" }
            }
        }
    } catch { Write-Output ('ERROR|' + $p + '|' + $_.Exception.Message) }
}
if ($found.Count -eq 0) { Write-Output 'NONE' }
else { $found | ForEach-Object { Write-Output $_ } }
"#;

    match optimizer_core::powershell(ps).output() {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout).trim().to_string();
            let mut errors = Vec::new();
            let entries = stdout
                .lines()
                .filter_map(|line| {
                    if line == "NONE" {
                        return None;
                    }
                    let parts: Vec<&str> = line.splitn(3, '|').collect();
                    if parts.first() == Some(&"ERROR") {
                        errors.push(
                            parts
                                .get(2)
                                .copied()
                                .unwrap_or("Java registry query failed")
                                .to_string(),
                        );
                        return None;
                    }
                    if parts.len() == 3 {
                        let ver = parts[0].to_string();
                        let outdated = is_java_outdated(&ver);
                        Some(RuntimeEntry {
                            name: format!("Java {} ({})", ver, parts[1]),
                            version: ver,
                            runtime_type: Some(parts[1].to_string()),
                            path: Some(parts[2].to_string()),
                            installed: true,
                            arch: None,
                            outdated,
                            download_url: if outdated {
                                Some(JAVA_URL.into())
                            } else {
                                None
                            },
                        })
                    } else {
                        errors.push(format!("Could not parse Java runtime record: {line}"));
                        None
                    }
                })
                .collect();
            (entries, ProbeState::from_errors(errors))
        }
        Ok(o) => (
            Vec::new(),
            ProbeState::from_errors(vec![format!(
                "Java runtime query failed: {}",
                optimizer_core::decode_console_output(&o.stderr).trim()
            )]),
        ),
        Err(error) => (
            Vec::new(),
            ProbeState::from_errors(vec![format!("Could not start Java runtime query: {error}")]),
        ),
    }
}

#[cfg(not(target_os = "windows"))]
fn stub_dotnet() -> Vec<RuntimeEntry> {
    vec![
        RuntimeEntry {
            name: ".NET Framework 4.8".into(),
            version: "4.8".into(),
            runtime_type: None,
            path: Some(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319".into()),
            installed: true,
            arch: None,
            outdated: true,
            download_url: Some(DOTNET_FW_URL.into()),
        },
        RuntimeEntry {
            name: ".NET 8.0.3 (runtime)".into(),
            version: "8.0.3".into(),
            runtime_type: Some("runtime".into()),
            path: Some(r"C:\Program Files\dotnet".into()),
            installed: true,
            arch: None,
            outdated: false,
            download_url: None,
        },
        RuntimeEntry {
            name: ".NET Framework 3.5".into(),
            version: "3.5".into(),
            runtime_type: None,
            path: None,
            installed: false,
            arch: None,
            outdated: false,
            download_url: Some(DOTNET_FW35_URL.into()),
        },
    ]
}

#[cfg(not(target_os = "windows"))]
fn stub_vcredist() -> Vec<RuntimeEntry> {
    vec![
        RuntimeEntry {
            name: "Visual C++ 2015-2022 (x64)".into(),
            version: "14.38.33135".into(),
            runtime_type: None,
            path: None,
            installed: true,
            arch: Some("x64".into()),
            outdated: true,
            download_url: Some(VCREDIST_X64_URL.into()),
        },
        RuntimeEntry {
            name: "Visual C++ 2015-2022 (x86)".into(),
            version: "14.38.33135".into(),
            runtime_type: None,
            path: None,
            installed: true,
            arch: Some("x86".into()),
            outdated: true,
            download_url: Some(VCREDIST_X86_URL.into()),
        },
        RuntimeEntry {
            name: "Visual C++ 2013 (x64)".into(),
            version: "12.0.40664".into(),
            runtime_type: None,
            path: None,
            installed: true,
            arch: Some("x64".into()),
            outdated: false,
            download_url: None,
        },
    ]
}

#[cfg(not(target_os = "windows"))]
fn stub_runtimes() -> RuntimesReport {
    RuntimesReport {
        dotnet: stub_dotnet(),
        vcredist: stub_vcredist(),
        directx: DirectXInfo {
            version: "12.0".into(),
            feature_level: "12_1".into(),
            download_url: DIRECTX_URL.into(),
        },
        java: Vec::new(),
        coverage: RuntimeCoverage {
            dotnet: ProbeState::from_errors(Vec::new()),
            vcredist: ProbeState::from_errors(Vec::new()),
            directx: ProbeState::from_errors(Vec::new()),
            java: ProbeState::from_errors(Vec::new()),
        },
    }
}

// ---------------------------------------------------------------------------
// Download URLs and version checks
// ---------------------------------------------------------------------------

const DOTNET_FW_URL: &str = "https://dotnet.microsoft.com/download/dotnet-framework/net481";
const DOTNET_FW35_URL: &str = "https://dotnet.microsoft.com/download/dotnet-framework/net35-sp1";
const DOTNET8_URL: &str = "https://dotnet.microsoft.com/download/dotnet/8.0";
const DOTNET10_URL: &str = "https://dotnet.microsoft.com/download/dotnet/10.0";
const VCREDIST_X64_URL: &str = "https://aka.ms/vs/17/release/vc_redist.x64.exe";
const VCREDIST_X86_URL: &str = "https://aka.ms/vs/17/release/vc_redist.x86.exe";
const DIRECTX_URL: &str = "https://www.microsoft.com/en-us/download/details.aspx?id=35";
const JAVA_URL: &str = "https://adoptium.net/";

fn is_dotnet_fw_outdated(version: &str) -> bool {
    let mut parts = version
        .split('.')
        .filter_map(|part| part.parse::<u32>().ok());
    let parsed = (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    );
    parsed < (4, 6, 2)
}

fn dotnet_core_status(version: &str) -> (bool, Option<String>) {
    let major: u32 = version
        .split('.')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let patch = version
        .split('.')
        .nth(2)
        .and_then(|part| part.split('-').next())
        .and_then(|part| part.parse::<u32>().ok())
        .unwrap_or(0);
    match major {
        5..=7 => (true, Some(DOTNET10_URL.into())),
        8 => (patch < 28, (patch < 28).then(|| DOTNET10_URL.into())),
        9 => (patch < 17, (patch < 17).then(|| DOTNET10_URL.into())),
        10 => (patch < 9, (patch < 9).then(|| DOTNET10_URL.into())),
        // Very old or unknown
        _ if major < 5 => (true, Some(DOTNET8_URL.into())),
        _ => (false, None),
    }
}

fn is_vcredist_outdated(version: &str) -> bool {
    // 14.40+ is current (2015-2022 latest)
    let parts: Vec<u32> = version.split('.').filter_map(|s| s.parse().ok()).collect();
    if parts.len() >= 2 && parts[0] == 14 {
        return parts[1] < 40;
    }
    false
}

fn is_java_outdated(version: &str) -> bool {
    let major: u32 = version
        .split('.')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    major > 0 && !matches!(major, 8 | 11 | 17 | 21 | 25 | 26)
}

#[cfg(test)]
mod tests {
    use super::{dotnet_core_status, is_dotnet_fw_outdated, is_java_outdated};

    #[test]
    fn runtime_lifecycle_table_rejects_eol_channels_and_old_patches() {
        assert!(dotnet_core_status("6.0.36").0);
        assert!(dotnet_core_status("8.0.27").0);
        assert!(!dotnet_core_status("8.0.28").0);
        assert!(dotnet_core_status("10.0.8").0);
        assert!(!dotnet_core_status("10.0.9").0);
        assert!(is_java_outdated("24"));
        assert!(!is_java_outdated("25"));
        assert!(is_dotnet_fw_outdated("4.6.1"));
        assert!(!is_dotnet_fw_outdated("4.8"));
    }
}
