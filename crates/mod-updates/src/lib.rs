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
    pub last_check: String,
    pub last_install: String,
    pub service_status: String,
    pub pending_updates: Vec<PendingUpdate>,
    pub component_store_health: String,
    pub days_since_last_update: u64,
}

#[cfg(target_os = "windows")]
pub fn get_status() -> UpdateStatus {
    

    let ps = r#"
# WU service status
$svc = Get-Service wuauserv -ErrorAction SilentlyContinue
$svcStatus = if ($svc) { $svc.Status.ToString() } else { 'Unknown' }

# Last install/check dates
try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $count = $searcher.GetTotalHistoryCount()
    if ($count -gt 0) {
        $last = $searcher.QueryHistory(0, 1) | Select-Object -First 1
        $lastInstall = [DateTime]::SpecifyKind($last.Date, [DateTimeKind]::Utc).ToString('o')
    } else { $lastInstall = 'Never' }
} catch { $lastInstall = 'Unknown' }

# Pending updates
try {
    $searcher2 = $session.CreateUpdateSearcher()
    $result = $searcher2.Search("IsInstalled=0 AND IsHidden=0")
    $pending = @()
    foreach ($u in $result.Updates) {
        $sev = switch ($u.MsrcSeverity) { 'Critical' {'Critical'} 'Important' {'Important'} default {'Optional'} }
        $cat = if ($u.Categories.Count -gt 0) { $u.Categories.Item(0).Name } else { 'Other' }
        $sizeMB = [math]::Round($u.MaxDownloadSize / 1MB, 0)
        $pending += "$($u.Title)|$sizeMB|$sev|$cat"
    }
} catch { $pending = @() }

Write-Output "STATUS|$svcStatus|$lastInstall"
foreach ($p in $pending) { Write-Output "UPDATE|$p" }

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
"#;

    let mut status = UpdateStatus {
        last_check: String::new(),
        last_install: String::new(),
        service_status: "Unknown".into(),
        pending_updates: Vec::new(),
        component_store_health: "Unknown".into(),
        days_since_last_update: 0,
    };

    if let Ok(o) = optimizer_core::powershell(ps).output() {
        let stdout = String::from_utf8_lossy(&o.stdout);
        for line in stdout.lines() {
            if line.starts_with("STATUS|") {
                let p: Vec<&str> = line.splitn(3, '|').collect();
                if p.len() >= 3 {
                    status.service_status = p[1].trim().to_string();
                    status.last_install = p[2].trim().to_string();
                    status.last_check = status.last_install.clone();
                }
            } else if line.starts_with("UPDATE|") {
                let rest = &line[7..];
                // Split from the right so a '|' inside the update title doesn't
                // shift the trailing size/severity/category fields.
                let p: Vec<&str> = rest.rsplitn(4, '|').collect(); // [cat, sev, size, title]
                if p.len() >= 4 {
                    status.pending_updates.push(PendingUpdate {
                        title: p[3].trim().to_string(),
                        size_mb: p[2].trim().parse().unwrap_or(0),
                        severity: p[1].trim().to_string(),
                        category: p[0].trim().to_string(),
                    });
                }
            } else if line.starts_with("COMP|") {
                status.component_store_health = line[5..].trim().to_string();
            }
        }
    }

    if let Ok(date) = chrono::DateTime::parse_from_rfc3339(&status.last_install) {
        let days = (chrono::Utc::now() - date.with_timezone(&chrono::Utc)).num_days();
        status.days_since_last_update = days.max(0) as u64;
    }

    status
}

#[cfg(not(target_os = "windows"))]
pub fn get_status() -> UpdateStatus {
    UpdateStatus {
        last_check: String::new(),
        last_install: String::new(),
        service_status: "N/A".into(),
        pending_updates: Vec::new(),
        component_store_health: "N/A".into(),
        days_since_last_update: 0,
    }
}
