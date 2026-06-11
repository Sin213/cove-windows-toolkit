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
# Registry Run keys (enabled) and our Run_Disabled keys (disabled)
$runPairs = @(
    @{ Enabled='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'; Disabled='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run_Disabled' },
    @{ Enabled='HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'; Disabled='HKLM:\Software\Microsoft\Windows\CurrentVersion\Run_Disabled' }
)
foreach ($pair in $runPairs) {
    if (Test-Path $pair.Enabled) {
        $props = Get-ItemProperty $pair.Enabled -ErrorAction SilentlyContinue
        $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            Write-Output "ITEM|$($_.Name)|$($pair.Enabled)|$($_.Value)|true"
        }
    }
    if (Test-Path $pair.Disabled) {
        $props = Get-ItemProperty $pair.Disabled -ErrorAction SilentlyContinue
        $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            Write-Output "ITEM|$($_.Name)|$($pair.Disabled)|$($_.Value)|false"
        }
    }
}

# Startup folder (enabled) and its Disabled subfolder (disabled)
$startupFolder = [Environment]::GetFolderPath('Startup')
if (Test-Path $startupFolder) {
    Get-ChildItem $startupFolder -File -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "ITEM|$($_.BaseName)|Shell:Startup|$($_.FullName)|true"
    }
    $disabledFolder = Join-Path $startupFolder 'Disabled'
    if (Test-Path $disabledFolder) {
        Get-ChildItem $disabledFolder -File -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Output "ITEM|$($_.BaseName)|Shell:Startup\Disabled|$($_.FullName)|false"
        }
    }
}
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
    // Inject name/action as PS variables once (avoids brittle positional format
    // substitution and lets the body be a plain raw string).
    let prefix = format!(
        "$name = '{}'\n$action = '{}'\n",
        name.replace('\'', "''"),
        action
    );
    let body = r#"
$paths = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run')
$found = $false

# Registry Run keys
foreach ($p in $paths) {
    try {
        $val = (Get-ItemProperty $p -Name $name -ErrorAction Stop).$name
        if ($val) {
            if ($action -eq 'disable') {
                $disabledPath = $p -replace 'Run$','Run_Disabled'
                if (-not (Test-Path $disabledPath)) { New-Item $disabledPath -Force | Out-Null }
                Set-ItemProperty -Path $disabledPath -Name $name -Value $val
                Remove-ItemProperty -Path $p -Name $name -Force
            }
            $found = $true
            break
        }
    } catch {}
}
if (-not $found -and $action -eq 'enable') {
    foreach ($p in $paths) {
        $disabledPath = $p -replace 'Run$','Run_Disabled'
        try {
            $val = (Get-ItemProperty $disabledPath -Name $name -ErrorAction Stop).$name
            if ($val) {
                Set-ItemProperty -Path $p -Name $name -Value $val
                Remove-ItemProperty -Path $disabledPath -Name $name -Force
                $found = $true
                break
            }
        } catch {}
    }
}

# Startup folder (.lnk/.exe) items - disable by moving to a Disabled subfolder
if (-not $found) {
    $startupFolder = [Environment]::GetFolderPath('Startup')
    $disabledFolder = Join-Path $startupFolder 'Disabled'
    if ($action -eq 'disable') {
        $file = Get-ChildItem $startupFolder -File -ErrorAction SilentlyContinue | Where-Object { $_.BaseName -eq $name } | Select-Object -First 1
        if ($file) {
            if (-not (Test-Path $disabledFolder)) { New-Item $disabledFolder -ItemType Directory -Force | Out-Null }
            Move-Item $file.FullName -Destination $disabledFolder -Force
            $found = $true
        }
    } else {
        if (Test-Path $disabledFolder) {
            $file = Get-ChildItem $disabledFolder -File -ErrorAction SilentlyContinue | Where-Object { $_.BaseName -eq $name } | Select-Object -First 1
            if ($file) {
                Move-Item $file.FullName -Destination $startupFolder -Force
                $found = $true
            }
        }
    }
}

if ($found) { Write-Output 'OK' } else { Write-Output 'NOTFOUND' }
"#;
    let ps = format!("{}{}", prefix, body);

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
