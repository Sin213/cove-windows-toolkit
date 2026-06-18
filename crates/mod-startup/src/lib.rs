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
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$enabledKeys = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run')
$disabledKeys = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run_Disabled','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run_Disabled')
$startupFolder = [Environment]::GetFolderPath('Startup')

# Emit ENABLED sources first so the Rust first-seen dedup prefers the enabled
# entry when the same name exists enabled in one hive and disabled in another.
foreach ($k in $enabledKeys) {
    if (Test-Path $k) {
        (Get-ItemProperty $k -ErrorAction SilentlyContinue).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            Write-Output "ITEM|$($_.Name)|$k|$($_.Value)|true"
        }
    }
}
if (Test-Path $startupFolder) {
    Get-ChildItem $startupFolder -File -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "ITEM|$($_.BaseName)|Shell:Startup|$($_.FullName)|true"
    }
}

# Then disabled sources.
foreach ($k in $disabledKeys) {
    if (Test-Path $k) {
        (Get-ItemProperty $k -ErrorAction SilentlyContinue).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            Write-Output "ITEM|$($_.Name)|$k|$($_.Value)|false"
        }
    }
}
$disabledFolder = Join-Path $startupFolder 'Disabled'
if (Test-Path $disabledFolder) {
    Get-ChildItem $disabledFolder -File -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "ITEM|$($_.BaseName)|Shell:Startup\Disabled|$($_.FullName)|false"
    }
}
"#;

    let mut items = Vec::new();
    let mut seen = std::collections::HashSet::new();

    if let Ok(o) = optimizer_core::powershell(ps).output() {
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

# Copy a Run value between keys preserving its original value kind (REG_SZ vs
# REG_EXPAND_SZ). Reading the raw value with DoNotExpandEnvironmentNames keeps
# %VAR% tokens intact so a disable->enable round-trip doesn't break entries that
# rely on environment expansion at boot.
function Copy-RunValue($src, $dst, $valueName) {
    $key = Get-Item $src
    $kind = $key.GetValueKind($valueName)
    $raw = $key.GetValue($valueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if (-not (Test-Path $dst)) { New-Item $dst -Force | Out-Null }
    New-ItemProperty -Path $dst -Name $valueName -Value $raw -PropertyType $kind -Force | Out-Null
}

# Registry Run keys
foreach ($p in $paths) {
    try {
        $val = (Get-ItemProperty $p -Name $name -ErrorAction Stop).$name
        if ($val) {
            if ($action -eq 'disable') {
                $disabledPath = $p -replace 'Run$','Run_Disabled'
                Copy-RunValue $p $disabledPath $name
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
                Copy-RunValue $disabledPath $p $name
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

    let o = optimizer_core::powershell(&ps).output()
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
