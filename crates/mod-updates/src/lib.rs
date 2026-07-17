use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct PendingUpdate {
    pub title: String,
    pub size_mb: u64,
    pub severity: String,
    pub category: String,
}

#[derive(Serialize)]
pub struct UpdateStatus {
    pub complete: bool,
    pub query_error: Option<String>,
    pub last_check: Option<String>,
    pub last_install: Option<String>,
    pub service_status: String,
    pub pending_updates: Vec<PendingUpdate>,
    pub component_store_health: String,
    pub days_since_last_update: Option<u64>,
}

#[cfg(target_os = "windows")]
pub fn get_status() -> UpdateStatus {
    let ps = r#"
# WU service status
$svc = Get-Service wuauserv -ErrorAction SilentlyContinue
$svcStatus = if ($svc) { $svc.Status.ToString() } else { 'Unknown' }
$errors = @()

# Last install/check dates
try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $count = $searcher.GetTotalHistoryCount()
    if ($count -gt 0) {
        $last = $searcher.QueryHistory(0, 1) | Select-Object -First 1
        $lastInstall = [DateTime]::SpecifyKind($last.Date, [DateTimeKind]::Utc).ToString('o')
    } else { $lastInstall = 'Never' }
} catch { $lastInstall = 'Unknown'; $errors += $_.Exception.Message }
$lastCheck = try { (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect' -Name LastSuccessTime -ErrorAction Stop).LastSuccessTime } catch { $errors += $_.Exception.Message; 'Unknown' }

# Pending updates
try {
    $searcher2 = $session.CreateUpdateSearcher()
    $result = $searcher2.Search("IsInstalled=0 AND IsHidden=0")
    $pending = @()
    foreach ($u in $result.Updates) {
        $sev = switch ($u.MsrcSeverity) {
            'Critical' {'Critical'} 'Important' {'Important'} 'Moderate' {'Moderate'} 'Low' {'Low'}
            { [string]::IsNullOrWhiteSpace($_) } {'Optional'} default {[string]$u.MsrcSeverity}
        }
        $cat = if ($u.Categories.Count -gt 0) { $u.Categories.Item(0).Name } else { 'Other' }
        $sizeMB = [int64][math]::Round($u.MaxDownloadSize / 1MB, 0)
        $pending += [pscustomobject]@{ title=[string]$u.Title; size_mb=$sizeMB; severity=$sev; category=$cat }
    }
} catch { $pending = @(); $errors += $_.Exception.Message }

Write-Output "STATUS|$svcStatus|$lastCheck|$lastInstall"
foreach ($p in $pending) { Write-Output ('UPDATEJSON|' + ($p | ConvertTo-Json -Compress)) }

# Component store
try {
    $dism = & dism /Online /Cleanup-Image /CheckHealth 2>&1
    if ($LASTEXITCODE -ne 0) {
        # e.g. error 740 (needs elevation) - we can't tell, so don't claim corruption
        Write-Output "COMP|Unknown"
    } elseif ($dism -match 'No component store corruption') {
        Write-Output "COMP|Healthy"
    } elseif ($dism -match 'repairable|corruption') {
        Write-Output "COMP|Needs Repair"
    } else {
        # DISM's health text is localized; on non-English Windows a healthy store
        # matches neither pattern. Report 'Unknown' rather than a false 'Needs Repair'.
        Write-Output "COMP|Unknown"
    }
} catch { Write-Output "COMP|Unknown" }
foreach ($err in $errors) { Write-Output ('ERR|' + ($err -replace '[\r\n]+',' ')) }
"#;

    let mut status = UpdateStatus {
        complete: false,
        query_error: None,
        last_check: None,
        last_install: None,
        service_status: "Unknown".into(),
        pending_updates: Vec::new(),
        component_store_health: "Unknown".into(),
        days_since_last_update: None,
    };

    if let Ok(o) = optimizer_core::powershell(ps).output() {
        let stdout = String::from_utf8_lossy(&o.stdout);
        for line in stdout.lines() {
            if line.starts_with("STATUS|") {
                let p: Vec<&str> = line.splitn(4, '|').collect();
                if p.len() >= 4 {
                    status.service_status = p[1].trim().to_string();
                    status.last_check = parse_update_date(p[2]);
                    status.last_install = parse_update_date(p[3]);
                    status.complete = true;
                }
            } else if let Some(rest) = line.strip_prefix("UPDATEJSON|") {
                if let Ok(update) = serde_json::from_str::<serde_json::Value>(rest) {
                    status.pending_updates.push(PendingUpdate {
                        title: update
                            .get("title")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string(),
                        size_mb: update.get("size_mb").and_then(|v| v.as_u64()).unwrap_or(0),
                        severity: update
                            .get("severity")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown")
                            .to_string(),
                        category: update
                            .get("category")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Other")
                            .to_string(),
                    });
                }
            } else if let Some(component) = line.strip_prefix("COMP|") {
                status.component_store_health = component.trim().to_string();
            } else if let Some(error) = line.strip_prefix("ERR|") {
                status.complete = false;
                status.query_error = Some(error.to_string());
            }
        }
    }

    if let Some(date) = status
        .last_install
        .as_deref()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
    {
        let days = (chrono::Utc::now() - date.with_timezone(&chrono::Utc)).num_days();
        status.days_since_last_update = Some(days.max(0) as u64);
    }

    status
}

#[cfg(not(target_os = "windows"))]
pub fn get_status() -> UpdateStatus {
    UpdateStatus {
        complete: false,
        query_error: Some("Windows Update is unavailable on this platform.".into()),
        last_check: None,
        last_install: None,
        service_status: "N/A".into(),
        pending_updates: Vec::new(),
        component_store_health: "N/A".into(),
        days_since_last_update: None,
    }
}

fn parse_update_date(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()
        && value != "Unknown"
        && value != "Never"
        && chrono::DateTime::parse_from_rfc3339(value).is_ok())
    .then(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::parse_update_date;

    #[test]
    fn update_dates_preserve_unknown_as_none() {
        assert_eq!(parse_update_date("Unknown"), None);
        assert_eq!(parse_update_date("Never"), None);
        assert_eq!(parse_update_date("not-a-date"), None);
        assert_eq!(
            parse_update_date("2026-07-16T12:00:00Z").as_deref(),
            Some("2026-07-16T12:00:00Z")
        );
    }
}
