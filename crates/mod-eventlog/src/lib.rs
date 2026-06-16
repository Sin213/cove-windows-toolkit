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
    // Bound everything to a recent window (last 7 days) and derive the counts
    // from the events we actually retrieve, so the summary numbers always match
    // the list shown. Previously the counts were all-time totals while the list
    // was capped, so "257 errors" could display only a handful of entries.
    // The per-level cap is set high (2000) so the full recent history is
    // scrollable for both System and Application, instead of being truncated
    // at a few hundred on noisy logs (e.g. System).
    let ps = format!(
        r#"
$cutoff = (Get-Date).AddDays(-7)
foreach ($lvl in @(1,2,3)) {{
    $label = switch ($lvl) {{ 1 {{'Critical'}} 2 {{'Error'}} 3 {{'Warning'}} }}
    try {{
        Get-WinEvent -FilterHashtable @{{LogName='{log}'; Level=$lvl; StartTime=$cutoff}} -MaxEvents 2000 -ErrorAction Stop | ForEach-Object {{
            $msg = if ($_.Message) {{ ($_.Message -replace '[\r\n]+',' ').Substring(0, [Math]::Min($_.Message.Length, 200)) }} else {{ 'No message' }}
            Write-Output "EVT|$($_.Id)|$($_.ProviderName)|$label|$($_.TimeCreated.ToString('o'))|$msg"
        }}
    }} catch {{}}
}}"#,
        log = log_name
    );

    let mut summary = LogSummary { critical: 0, error: 0, warning: 0, recent_events: Vec::new() };

    if let Ok(o) = optimizer_core::powershell(&ps).output() {
        let stdout = String::from_utf8_lossy(&o.stdout);
        for line in stdout.lines() {
            if let Some(rest) = line.strip_prefix("EVT|") {
                let p: Vec<&str> = rest.splitn(5, '|').collect();
                if p.len() >= 5 {
                    let level = p[2].trim().to_string();
                    match level.as_str() {
                        "Critical" => summary.critical += 1,
                        "Error" => summary.error += 1,
                        "Warning" => summary.warning += 1,
                        _ => {}
                    }
                    summary.recent_events.push(EventEntry {
                        id: p[0].trim().parse().unwrap_or(0),
                        source: p[1].trim().to_string(),
                        level,
                        time: p[3].trim().to_string(),
                        message: p[4].trim().to_string(),
                    });
                }
            }
        }
    }
    summary
}
