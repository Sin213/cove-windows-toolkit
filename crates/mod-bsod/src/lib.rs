use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct BsodDump {
    pub file: String,
    pub date: String,
    pub bug_check: String,
    pub bug_check_name: String,
    pub faulting_module: String,
    pub description: String,
    pub recommendation: String,
}

#[derive(Serialize, Clone)]
pub struct BsodReport {
    pub complete: bool,
    pub error: Option<String>,
    pub scanned_paths: Vec<String>,
    pub dumps: Vec<BsodDump>,
}

#[cfg(target_os = "windows")]
pub fn scan_dumps_report() -> BsodReport {
    let script = r#"
$ErrorActionPreference='Stop'
try {
  $config = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -ErrorAction Stop
  $mini = if ($config.MinidumpDir) { [Environment]::ExpandEnvironmentVariables([string]$config.MinidumpDir) } else { Join-Path $env:SystemRoot 'Minidump' }
  $full = if ($config.DumpFile) { [Environment]::ExpandEnvironmentVariables([string]$config.DumpFile) } else { Join-Path $env:SystemRoot 'MEMORY.DMP' }
  $found = @()
  if (Test-Path -LiteralPath $mini) {
    $found += Get-ChildItem -LiteralPath $mini -Filter '*.dmp' -File -ErrorAction Stop | Sort-Object LastWriteTime -Descending | Select-Object -First 10 | ForEach-Object { [pscustomobject]@{ file=$_.FullName; date=$_.LastWriteTime.ToString('o') } }
  }
  if (Test-Path -LiteralPath $full -PathType Leaf) {
    $item = Get-Item -LiteralPath $full -ErrorAction Stop
    $found += [pscustomobject]@{ file=$item.FullName; date=$item.LastWriteTime.ToString('o') }
  }
  [pscustomobject]@{ complete=$true; error=$null; scanned_paths=@($mini,$full); dumps=@($found) } | ConvertTo-Json -Depth 4 -Compress
} catch {
  [pscustomobject]@{ complete=$false; error=$_.Exception.Message; scanned_paths=@(); dumps=@() } | ConvertTo-Json -Depth 4 -Compress
}
"#;
    let output = match optimizer_core::powershell(script).output() {
        Ok(output) => output,
        Err(error) => {
            return BsodReport {
                complete: false,
                error: Some(error.to_string()),
                scanned_paths: Vec::new(),
                dumps: Vec::new(),
            };
        }
    };
    let value: serde_json::Value = match serde_json::from_slice(&output.stdout) {
        Ok(value) => value,
        Err(error) => {
            return BsodReport {
                complete: false,
                error: Some(error.to_string()),
                scanned_paths: Vec::new(),
                dumps: Vec::new(),
            };
        }
    };
    let dumps = value
        .get("dumps")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    Some(BsodDump {
                        file: item.get("file")?.as_str()?.to_string(),
                        date: item.get("date")?.as_str()?.to_string(),
                        bug_check: "See details".into(),
                        bug_check_name: "MINIDUMP_FOUND".into(),
                        faulting_module: "Requires WinDbg".into(),
                        description: "Crash dump found. Use WinDbg for bug check analysis.".into(),
                        recommendation:
                            "Update drivers and run memory diagnostics if crashes are frequent."
                                .into(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    BsodReport {
        complete: value
            .get("complete")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        error: value
            .get("error")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        scanned_paths: value
            .get("scanned_paths")
            .and_then(|v| v.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
        dumps,
    }
}

#[cfg(not(target_os = "windows"))]
pub fn scan_dumps_report() -> BsodReport {
    BsodReport {
        complete: false,
        error: Some("Crash dumps are unavailable on this platform.".into()),
        scanned_paths: Vec::new(),
        dumps: Vec::new(),
    }
}

#[cfg(target_os = "windows")]
pub fn scan_dumps() -> Vec<BsodDump> {
    let ps = r#"
$dir = "$env:SystemRoot\Minidump"
if (Test-Path $dir) {
    Get-ChildItem -Path $dir -Filter '*.dmp' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 10 |
        ForEach-Object {
            Write-Output "DUMP|$($_.FullName)|$($_.LastWriteTime.ToString('o'))|$($_.Length)"
        }
}
# Full/kernel memory dump (used when minidumps are disabled)
$full = "$env:SystemRoot\MEMORY.DMP"
if (Test-Path $full) {
    $f = Get-Item $full -ErrorAction SilentlyContinue
    if ($f) { Write-Output "DUMP|$($f.FullName)|$($f.LastWriteTime.ToString('o'))|$($f.Length)" }
}
"#;

    let mut dumps = Vec::new();
    if let Ok(o) = optimizer_core::powershell(ps).output() {
        let stdout = String::from_utf8_lossy(&o.stdout);
        for line in stdout.lines() {
            if !line.starts_with("DUMP|") {
                continue;
            }
            let p: Vec<&str> = line.splitn(4, '|').collect();
            if p.len() >= 3 {
                dumps.push(BsodDump {
                    file: p[1].trim().to_string(),
                    date: p[2].trim().to_string(),
                    bug_check: "See details".into(),
                    bug_check_name: "MINIDUMP_FOUND".into(),
                    faulting_module: "Requires WinDbg".into(),
                    description:
                        "Minidump found. Use WinDbg or BlueScreenView for bug check analysis."
                            .into(),
                    recommendation:
                        "Update drivers and run memory diagnostics if crashes are frequent.".into(),
                });
            }
        }
    }
    dumps
}

#[cfg(not(target_os = "windows"))]
pub fn scan_dumps() -> Vec<BsodDump> {
    Vec::new()
}
