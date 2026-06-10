use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct EventEntry {
    pub id: u64,
    pub source: String,
    pub level: String,
    pub time: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct LogSummary {
    pub critical: u64,
    pub error: u64,
    pub warning: u64,
    pub recent_events: Vec<EventEntry>,
}

#[derive(Serialize)]
pub struct EventLogReport {
    pub system: LogSummary,
    pub application: LogSummary,
}

#[cfg(target_os = "windows")]
pub fn get_summary() -> EventLogReport {
    EventLogReport {
        system: query_log("System"),
        application: query_log("Application"),
    }
}

#[cfg(not(target_os = "windows"))]
pub fn get_summary() -> EventLogReport {
    EventLogReport {
        system: LogSummary { critical: 0, error: 0, warning: 0, recent_events: Vec::new() },
        application: LogSummary { critical: 0, error: 0, warning: 0, recent_events: Vec::new() },
    }
}

#[cfg(target_os = "windows")]
fn query_log(log_name: &str) -> LogSummary {
    let ps = format!(
        r#"
try {{ $c = @(Get-WinEvent -FilterHashtable @{{LogName='{log}'; Level=1}} -ErrorAction Stop).Count }} catch {{ $c = 0 }}
try {{ $e = @(Get-WinEvent -FilterHashtable @{{LogName='{log}'; Level=2}} -ErrorAction Stop).Count }} catch {{ $e = 0 }}
try {{ $w = @(Get-WinEvent -FilterHashtable @{{LogName='{log}'; Level=3}} -ErrorAction Stop).Count }} catch {{ $w = 0 }}
Write-Output "COUNTS|$c|$e|$w"

try {{
    Get-WinEvent -FilterHashtable @{{LogName='{log}'; Level=1,2,3}} -MaxEvents 50 -ErrorAction Stop | ForEach-Object {{
        $lvl = switch ($_.Level) {{ 1 {{'Critical'}} 2 {{'Error'}} 3 {{'Warning'}} default {{'Info'}} }}
        $msg = if ($_.Message) {{ ($_.Message -replace '[\r\n]+',' ').Substring(0, [Math]::Min($_.Message.Length, 200)) }} else {{ 'No message' }}
        Write-Output "EVT|$($_.Id)|$($_.ProviderName)|$lvl|$($_.TimeCreated.ToString('o'))|$msg"
    }}
}} catch {{}}"#,
        log = log_name
    );

    let mut summary = LogSummary { critical: 0, error: 0, warning: 0, recent_events: Vec::new() };

    if let Ok(o) = optimizer_core::silent_cmd("powershell").args(["-NoProfile", "-Command", &ps]).output() {
        let stdout = String::from_utf8_lossy(&o.stdout);
        for line in stdout.lines() {
            if line.starts_with("COUNTS|") {
                let p: Vec<&str> = line.split('|').collect();
                if p.len() >= 4 {
                    summary.critical = p[1].trim().parse().unwrap_or(0);
                    summary.error = p[2].trim().parse().unwrap_or(0);
                    summary.warning = p[3].trim().parse().unwrap_or(0);
                }
            } else if line.starts_with("EVT|") {
                let p: Vec<&str> = line.splitn(6, '|').collect();
                if p.len() >= 6 {
                    summary.recent_events.push(EventEntry {
                        id: p[1].trim().parse().unwrap_or(0),
                        source: p[2].trim().to_string(),
                        level: p[3].trim().to_string(),
                        time: p[4].trim().to_string(),
                        message: p[5].trim().to_string(),
                    });
                }
            }
        }
    }
    summary
}
