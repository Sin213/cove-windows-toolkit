use serde::{Deserialize, Serialize};

#[derive(Serialize, Clone)]
pub struct StartupItem {
    pub id: String,
    pub name: String,
    pub path: String,
    pub command: String,
    pub impact: String,
    pub enabled: bool,
    pub can_toggle: bool,
    pub toggle_reason: String,
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
                    if seen.contains(&name) {
                        continue;
                    }
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
                        can_toggle: p[2].trim().starts_with("HK"),
                        toggle_reason: if p[2].trim().starts_with("HK") {
                            String::new()
                        } else {
                            elevated_file_toggle_reason().into()
                        },
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
    if n.contains("steam")
        || n.contains("discord")
        || n.contains("teams")
        || n.contains("onedrive")
        || n.contains("spotify")
    {
        return "High".into();
    }
    "Medium".into()
}

#[cfg(target_os = "windows")]
pub fn toggle(name: &str, enabled: bool) -> Result<String, String> {
    let mut matches = list_items_v2()?
        .into_iter()
        .filter(|item| item.name.eq_ignore_ascii_case(name));
    let item = matches
        .next()
        .ok_or_else(|| format!("Startup item '{name}' not found"))?;
    if matches.next().is_some() {
        return Err(format!(
            "More than one startup item is named '{name}'. Refresh and select the source-specific item."
        ));
    }
    toggle_by_id(&item.id, enabled)
}

#[cfg(not(target_os = "windows"))]
pub fn toggle(_name: &str, _enabled: bool) -> Result<String, String> {
    Ok("[stub] Toggled".into())
}

/// Structured startup inventory with stable source-aware identities. This is
/// the API used by the application; the legacy line protocol above remains only
/// for compatibility with older callers.
#[cfg(target_os = "windows")]
pub fn list_items_v2() -> Result<Vec<StartupItem>, String> {
    #[derive(Deserialize)]
    struct Envelope {
        items: Vec<RawStartupItem>,
    }
    #[derive(Deserialize)]
    struct RawStartupItem {
        name: String,
        path: String,
        command: String,
        enabled: bool,
    }

    let script = r#"
$ErrorActionPreference = 'Stop'
$items = @()
$enabled = @(
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)
$disabled = @($enabled | ForEach-Object { $_ -replace 'Run$','Run_Disabled' })
foreach ($entry in @(@($enabled,$true), @($disabled,$false))) {
  $paths = $entry[0]; $isEnabled = $entry[1]
  foreach ($path in $paths) {
    if (-not (Test-Path -LiteralPath $path)) { continue }
    $key = Get-Item -LiteralPath $path -ErrorAction Stop
    foreach ($name in $key.GetValueNames()) {
      $value = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
      $items += [pscustomobject]@{ name=$name; path=$path; command=[string]$value; enabled=[bool]$isEnabled }
    }
  }
}
foreach ($folder in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
  if (-not $folder) { continue }
  foreach ($file in Get-ChildItem -LiteralPath $folder -File -ErrorAction SilentlyContinue) {
    $items += [pscustomobject]@{ name=$file.BaseName; path=$file.FullName; command=$file.FullName; enabled=$true }
  }
  $off = Join-Path $folder 'Disabled'
  foreach ($file in Get-ChildItem -LiteralPath $off -File -ErrorAction SilentlyContinue) {
    $items += [pscustomobject]@{ name=$file.BaseName; path=$file.FullName; command=$file.FullName; enabled=$false }
  }
}
@{ items=@($items) } | ConvertTo-Json -Depth 4 -Compress
"#;
    let output = optimizer_core::powershell(script)
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    let envelope: Envelope = serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())?;
    Ok(envelope
        .items
        .into_iter()
        .map(|raw| {
            let can_toggle = is_registry_startup_path(&raw.path);
            StartupItem {
                id: startup_id(&raw.path, &raw.name),
                impact: estimate_impact(&raw.name, &raw.command),
                name: raw.name,
                path: raw.path,
                command: raw.command,
                enabled: raw.enabled,
                can_toggle,
                toggle_reason: if can_toggle {
                    String::new()
                } else {
                    elevated_file_toggle_reason().into()
                },
            }
        })
        .collect())
}

#[cfg(not(target_os = "windows"))]
pub fn list_items_v2() -> Result<Vec<StartupItem>, String> {
    Ok(Vec::new())
}

fn startup_id(path: &str, name: &str) -> String {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    path.to_ascii_lowercase().hash(&mut hasher);
    name.to_ascii_lowercase().hash(&mut hasher);
    format!("startup.{:016x}", hasher.finish())
}

#[cfg(target_os = "windows")]
pub fn toggle_by_id(id: &str, enabled: bool) -> Result<String, String> {
    let item = list_items_v2()?
        .into_iter()
        .find(|item| item.id == id)
        .ok_or_else(|| "Startup item selection expired; refresh the list.".to_string())?;
    if item.enabled == enabled {
        return Ok(format!(
            "Startup item '{}' was already {}.",
            item.name,
            if enabled { "enabled" } else { "disabled" }
        ));
    }
    if !item.can_toggle || !is_registry_startup_path(&item.path) {
        return Err(elevated_file_toggle_reason().into());
    }
    let destination_path = registry_destination_path(&item.path, enabled)
        .ok_or_else(|| "The startup registry source is not an approved Run key.".to_string())?;
    let script = registry_move_script(&item.path, &destination_path, &item.name);
    let output = optimizer_core::powershell(&script)
        .output()
        .map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok(format!(
            "Startup item '{}' {}.",
            item.name,
            if enabled { "enabled" } else { "disabled" }
        ))
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

fn registry_move_script(source: &str, destination: &str, name: &str) -> String {
    let quote = |value: &str| value.replace('\'', "''");
    format!(
        r#"
$ErrorActionPreference='Stop'; $src='{source}'; $dst='{destination}'; $name='{name}'
$key=Get-Item -LiteralPath $src -ErrorAction Stop
$kind=$key.GetValueKind($name)
$raw=$key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
if (Test-Path -LiteralPath $dst) {{
  $destinationKey=Get-Item -LiteralPath $dst -ErrorAction Stop
  if ($destinationKey.GetValueNames() -contains $name) {{ throw "A startup value named '$name' already exists at the destination; nothing was changed." }}
}} else {{
  New-Item -Path $dst -ErrorAction Stop | Out-Null
}}
New-ItemProperty -LiteralPath $dst -Name $name -Value $raw -PropertyType $kind -ErrorAction Stop | Out-Null
try {{
  Remove-ItemProperty -LiteralPath $src -Name $name -Force -ErrorAction Stop
}} catch {{
  $sourceError=$_.Exception.Message
  try {{
    Remove-ItemProperty -LiteralPath $dst -Name $name -Force -ErrorAction Stop
  }} catch {{
    throw "Could not remove the source startup value ($sourceError), and rollback of the destination copy also failed: $($_.Exception.Message)"
  }}
  throw "Could not remove the source startup value; the destination copy was rolled back: $sourceError"
}}
"#,
        source = quote(source),
        destination = quote(destination),
        name = quote(name)
    )
}

fn is_registry_startup_path(path: &str) -> bool {
    registry_destination_path(path, path.to_ascii_lowercase().ends_with("\\run_disabled")).is_some()
}

fn elevated_file_toggle_reason() -> &'static str {
    "Startup-folder files cannot be moved safely while Cove is elevated. Move this item manually or use Windows Startup Apps settings."
}

fn registry_destination_path(path: &str, enabling: bool) -> Option<String> {
    const ENABLED: &str = "\\run";
    const DISABLED: &str = "\\run_disabled";
    let lower = path.to_ascii_lowercase();
    let source_suffix = if enabling { DISABLED } else { ENABLED };
    if !lower.ends_with(source_suffix) {
        return None;
    }
    let base = &lower[..lower.len() - source_suffix.len()];
    if !matches!(
        base,
        "hkcu:\\software\\microsoft\\windows\\currentversion"
            | "hklm:\\software\\microsoft\\windows\\currentversion"
            | "hklm:\\software\\wow6432node\\microsoft\\windows\\currentversion"
    ) {
        return None;
    }
    let destination_suffix = if enabling { "\\Run" } else { "\\Run_Disabled" };
    Some(format!(
        "{}{}",
        &path[..path.len() - source_suffix.len()],
        destination_suffix
    ))
}

#[cfg(not(target_os = "windows"))]
pub fn toggle_by_id(_id: &str, _enabled: bool) -> Result<String, String> {
    Ok("[stub] Toggled".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_destination_mapping_is_source_specific() {
        assert_eq!(
            registry_destination_path(
                r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
                false
            )
            .as_deref(),
            Some(r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run_Disabled")
        );
        assert_eq!(
            registry_destination_path(
                r"HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run_Disabled",
                true
            )
            .as_deref(),
            Some(r"HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")
        );
    }

    #[test]
    fn file_and_lookalike_paths_are_not_registry_startup_sources() {
        assert!(!is_registry_startup_path(
            r"C:\Users\Alice\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\tool.lnk"
        ));
        assert!(
            registry_destination_path(r"HKCU:\Software\Other\CurrentVersion\Run", false).is_none()
        );
    }

    #[test]
    fn registry_move_script_refuses_collisions_and_rolls_back_partial_copy() {
        let script = registry_move_script(
            r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run_Disabled",
            "Example",
        );
        assert!(script.contains("already exists at the destination"));
        assert!(script.contains("rollback of the destination copy also failed"));
        assert!(script.contains("the destination copy was rolled back"));
        assert!(!script.contains(
            "New-ItemProperty -LiteralPath $dst -Name $name -Value $raw -PropertyType $kind -Force"
        ));
    }
}
