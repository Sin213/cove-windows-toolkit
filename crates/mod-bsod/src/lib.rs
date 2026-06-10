use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct BsodDump {
    pub file: String,
    pub date: String,
    pub bug_check: String,
    pub bug_check_name: String,
    pub faulting_module: String,
    pub description: String,
    pub recommendation: String,
}

#[cfg(target_os = "windows")]
pub fn scan_dumps() -> Vec<BsodDump> {
    

    let ps = r#"
$dir = "$env:SystemRoot\Minidump"
if (-not (Test-Path $dir)) { exit 0 }
Get-ChildItem -Path $dir -Filter '*.dmp' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 10 |
    ForEach-Object {
        Write-Output "DUMP|$($_.FullName)|$($_.LastWriteTime.ToString('o'))|$($_.Length)"
    }
"#;

    let mut dumps = Vec::new();
    if let Ok(o) = optimizer_core::silent_cmd("powershell").args(["-NoProfile", "-Command", ps]).output() {
        let stdout = String::from_utf8_lossy(&o.stdout);
        for line in stdout.lines() {
            if !line.starts_with("DUMP|") { continue; }
            let p: Vec<&str> = line.splitn(4, '|').collect();
            if p.len() >= 3 {
                dumps.push(BsodDump {
                    file: p[1].trim().to_string(),
                    date: p[2].trim().to_string(),
                    bug_check: "See details".into(),
                    bug_check_name: "MINIDUMP_FOUND".into(),
                    faulting_module: "Requires WinDbg".into(),
                    description: "Minidump found. Use WinDbg or BlueScreenView for bug check analysis.".into(),
                    recommendation: "Update drivers and run memory diagnostics if crashes are frequent.".into(),
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
