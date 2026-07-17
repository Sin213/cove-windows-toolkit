use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct EventEntry {
    pub id: u64,
    pub source: String,
    pub level: String,
    pub time: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct LogSummary {
    pub complete: bool,
    pub query_error: Option<String>,
    pub window_days: u8,
    pub truncated: bool,
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
        system: empty_summary(
            false,
            Some("Event logs are unavailable on this platform.".into()),
        ),
        application: empty_summary(
            false,
            Some("Event logs are unavailable on this platform.".into()),
        ),
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
            $msg = if ($_.Message) {{ $m = ($_.Message -replace '[\r\n]+',' '); $m.Substring(0, [Math]::Min($m.Length, 200)) }} else {{ 'No message' }}
            $event = [pscustomobject]@{{ id=[uint64]$_.Id; source=[string]$_.ProviderName; level=$label; time=$_.TimeCreated.ToString('o'); message=$msg }}
            Write-Output ('EVTJSON|' + ($event | ConvertTo-Json -Compress))
        }}
    }} catch {{ Write-Output ('ERR|' + $_.Exception.Message) }}
}}"#,
        log = log_name
    );

    let mut summary = empty_summary(true, None);

    if let Ok(o) = optimizer_core::powershell(&ps).output() {
        let stdout = String::from_utf8_lossy(&o.stdout);
        for line in stdout.lines() {
            if let Some(rest) = line.strip_prefix("EVTJSON|") {
                if let Ok(event) = serde_json::from_str::<EventEntry>(rest) {
                    let level = event.level.as_str();
                    match level {
                        "Critical" => summary.critical += 1,
                        "Error" => summary.error += 1,
                        "Warning" => summary.warning += 1,
                        _ => {}
                    }
                    summary.recent_events.push(event);
                }
            } else if let Some(error) = line.strip_prefix("ERR|") {
                summary.complete = false;
                summary.query_error = Some(error.to_string());
            }
        }
    } else {
        summary.complete = false;
        summary.query_error = Some("Failed to start the event-log query.".into());
    }
    summary.truncated =
        summary.critical >= 2000 || summary.error >= 2000 || summary.warning >= 2000;
    summary.recent_events.sort_by(|a, b| b.time.cmp(&a.time));
    summary
}

fn empty_summary(complete: bool, error: Option<String>) -> LogSummary {
    LogSummary {
        complete,
        query_error: error,
        window_days: 7,
        truncated: false,
        critical: 0,
        error: 0,
        warning: 0,
        recent_events: Vec::new(),
    }
}
