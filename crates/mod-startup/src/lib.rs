use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct StartupItem {
    pub id: String,
    pub name: String,
    pub path: String,
    pub command: String,
    pub impact: String,
    pub enabled: bool,
}

#[cfg(target_os = "windows")]
pub fn list_items() -> Vec<StartupItem> {
    

    let ps = r#"
# HKCU Run
$hkcuRun = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
if (Test-Path $hkcuRun) {
    $props = Get-ItemProperty $hkcuRun -ErrorAction SilentlyContinue
    $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
        Write-Output "ITEM|$($_.Name)|$hkcuRun|$($_.Value)|true"
    }
}

# HKLM Run
$hklmRun = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
if (Test-Path $hklmRun) {
    $props = Get-ItemProperty $hklmRun -ErrorAction SilentlyContinue
    $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
        Write-Output "ITEM|$($_.Name)|$hklmRun|$($_.Value)|true"
    }
}

# Startup folder
$startupFolder = [Environment]::GetFolderPath('Startup')
if (Test-Path $startupFolder) {
    Get-ChildItem $startupFolder -File -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "ITEM|$($_.BaseName)|Shell:Startup|$($_.FullName)|true"
    }
}

# Disabled items from Task Manager startup (Autoruns via WMI)
try {
    Get-CimInstance Win32_StartupCommand -ErrorAction Stop | ForEach-Object {
        # Skip items already found above
        Write-Output "WMI|$($_.Name)|$($_.Location)|$($_.Command)"
    }
} catch {}
"#;

    let mut items = Vec::new();
    let mut seen = std::collections::HashSet::new();

    if let Ok(o) = optimizer_core::silent_cmd("powershell").args(["-NoProfile", "-Command", ps]).output() {
        let stdout = String::from_utf8_lossy(&o.stdout);
        for line in stdout.lines() {
            if line.starts_with("ITEM|") {
                let p: Vec<&str> = line.splitn(5, '|').collect();
                if p.len() >= 5 {
                    let name = p[1].trim().to_string();
                    if seen.contains(&name) { continue; }
                    seen.insert(name.clone());
                    let cmd = p[3].trim().to_string();
                    let impact = estimate_impact(&name, &cmd);
                    items.push(StartupItem {
                        id: format!("startup.{}", name.to_lowercase().replace(' ', "_")),
                        name,
                        path: p[2].trim().to_string(),
                        command: cmd,
                        impact,
                        enabled: p[4].trim() == "true",
                    });
                }
            }
        }
    }

    items
}

#[cfg(not(target_os = "windows"))]
pub fn list_items() -> Vec<StartupItem> {
    Vec::new()
}

fn estimate_impact(name: &str, _cmd: &str) -> String {
    let n = name.to_lowercase();
    if n.contains("security") || n.contains("defender") || n.contains("antivirus") {
        return "Low".into();
    }
    if n.contains("steam") || n.contains("discord") || n.contains("teams") || n.contains("onedrive") || n.contains("spotify") {
        return "High".into();
    }
    "Medium".into()
}

#[cfg(target_os = "windows")]
pub fn toggle(name: &str, enabled: bool) -> Result<String, String> {
    

    let action = if enabled { "enable" } else { "disable" };
    let ps = format!(
        r#"
$paths = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run')
$found = $false
foreach ($p in $paths) {{
    try {{
        $val = (Get-ItemProperty $p -Name '{}' -ErrorAction Stop).'{}'
        if ($val) {{
            if ('{}' -eq 'disable') {{
                # Move to a disabled subkey
                $disabledPath = $p -replace 'Run$','Run_Disabled'
                if (-not (Test-Path $disabledPath)) {{ New-Item $disabledPath -Force | Out-Null }}
                Set-ItemProperty -Path $disabledPath -Name '{}' -Value $val
                Remove-ItemProperty -Path $p -Name '{}' -Force
            }}
            $found = $true
            break
        }}
    }} catch {{}}
}}
# Check disabled keys for re-enable
if (-not $found -and '{}' -eq 'enable') {{
    foreach ($p in $paths) {{
        $disabledPath = $p -replace 'Run$','Run_Disabled'
        try {{
            $val = (Get-ItemProperty $disabledPath -Name '{}' -ErrorAction Stop).'{}'
            if ($val) {{
                Set-ItemProperty -Path ($p) -Name '{}' -Value $val
                Remove-ItemProperty -Path $disabledPath -Name '{}' -Force
                $found = $true
                break
            }}
        }} catch {{}}
    }}
}}
if ($found) {{ Write-Output 'OK' }} else {{ Write-Output 'NOTFOUND' }}
"#,
        name, name, action, name, name, action, name, name, name, name
    );

    let o = optimizer_core::silent_cmd("powershell").args(["-NoProfile", "-Command", &ps]).output()
        .map_err(|e| e.to_string())?;
    let result = String::from_utf8_lossy(&o.stdout).trim().to_string();
    if result == "OK" {
        Ok(format!("Startup item '{}' {}", name, if enabled { "enabled" } else { "disabled" }))
    } else {
        Err(format!("Startup item '{}' not found", name))
    }
}

#[cfg(not(target_os = "windows"))]
pub fn toggle(_name: &str, _enabled: bool) -> Result<String, String> {
    Ok("[stub] Toggled".into())
}
