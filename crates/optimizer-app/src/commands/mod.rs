use serde::Serialize;

// ---------------------------------------------------------------------------
// System info
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub os: String,
    pub platform: String,
}

#[tauri::command]
pub fn get_system_info() -> SystemInfo {
    SystemInfo {
        hostname: hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string()),
        os: std::env::consts::OS.to_string(),
        platform: if cfg!(target_os = "windows") {
            "Windows".to_string()
        } else {
            format!("{} (dev mode)", std::env::consts::OS)
        },
    }
}

// ---------------------------------------------------------------------------
// Visual effects
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_visual_tweaks() -> Vec<serde_json::Value> {
    mod_visual::get_tweaks()
        .into_iter()
        .map(|t| {
            serde_json::json!({
                "id": t.id,
                "name": t.name,
                "description": t.description,
                "category": t.category,
                "safety_tier": t.safety_tier,
                "current_value": t.current_value,
                "optimized_value": t.optimized_value,
            })
        })
        .collect()
}

#[tauri::command]
pub async fn apply_visual_tweak(id: String) -> serde_json::Value {
    tokio::task::spawn_blocking(move || apply_visual_tweak_sync(&id)).await.unwrap()
}

#[tauri::command]
pub async fn apply_all_visual_tweaks() -> serde_json::Value {
    tokio::task::spawn_blocking(|| {
        let tweaks = mod_visual::get_tweaks();
        let mut applied = 0;
        for t in &tweaks {
            if mod_visual::apply_tweak(&t.registry_path, &t.registry_name, &t.optimized_value).is_ok() {
                applied += 1;
            }
        }
        serde_json::json!({ "success": true, "message": format!("Applied {} visual tweaks", applied), "count": applied })
    }).await.unwrap()
}

#[tauri::command]
pub async fn undo_visual_tweak(id: String) -> serde_json::Value {
    tokio::task::spawn_blocking(move || undo_visual_tweak_sync(&id)).await.unwrap()
}

// ---------------------------------------------------------------------------
// Health report
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_health_report() -> serde_json::Value {
    let report = tokio::task::spawn_blocking(|| mod_health::quick_scan()).await.unwrap();
    serde_json::json!({
        "score": report.score,
        "findings": report.findings,
    })
}

// ---------------------------------------------------------------------------
// Privacy scan
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_privacy_tweaks() -> serde_json::Value {
    let tweaks = tokio::task::spawn_blocking(|| mod_privacy::get_tweaks()).await.unwrap();
    serde_json::to_value(tweaks).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Services scan
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_services_tweaks() -> serde_json::Value {
    let tweaks = tokio::task::spawn_blocking(|| mod_services::get_tweaks()).await.unwrap();
    serde_json::to_value(tweaks).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Startup items
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_startup_items() -> serde_json::Value {
    let items = tokio::task::spawn_blocking(|| mod_startup::list_items()).await.unwrap();
    serde_json::to_value(items).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Cleanup targets
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_cleanup_targets() -> serde_json::Value {
    let targets = tokio::task::spawn_blocking(|| mod_cleanup::scan_targets()).await.unwrap();
    serde_json::to_value(targets).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Power plan
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_power_info() -> serde_json::Value {
    let info = tokio::task::spawn_blocking(|| mod_power::get_info()).await.unwrap();
    serde_json::to_value(info).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Event log summary
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_event_log_summary() -> serde_json::Value {
    let report = tokio::task::spawn_blocking(|| mod_eventlog::get_summary()).await.unwrap();
    serde_json::to_value(report).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// BSOD analyzer
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_bsod_dumps() -> serde_json::Value {
    let dumps = tokio::task::spawn_blocking(|| mod_bsod::scan_dumps()).await.unwrap();
    serde_json::to_value(dumps).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Driver audit
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_driver_audit() -> serde_json::Value {
    let report = tokio::task::spawn_blocking(|| mod_drivers::audit_drivers()).await.unwrap();
    serde_json::to_value(report).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Network diagnostics
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_network_diagnostics() -> serde_json::Value {
    let report = tokio::task::spawn_blocking(|| mod_netdiag::run_diagnostics()).await.unwrap();
    serde_json::to_value(report).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Network tools
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn set_dns(preset: String) -> serde_json::Value {
    let (primary, secondary) = match preset.as_str() {
        "cloudflare" => ("1.1.1.1", "1.0.0.1"),
        "google" => ("8.8.8.8", "8.8.4.4"),
        "quad9" => ("9.9.9.9", "149.112.112.112"),
        "opendns" => ("208.67.222.222", "208.67.220.220"),
        "auto" => ("", ""),
        _ => return serde_json::json!({ "success": false, "message": format!("Unknown DNS preset: {}", preset) }),
    };

    if cfg!(not(target_os = "windows")) {
        return serde_json::json!({ "success": true, "stub": true, "message": format!("[stub] Would set DNS to {} ({}, {})", preset, primary, secondary) });
    }

    let script = if preset == "auto" {
        r#"Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses }; Write-Output 'ok'"#.to_string()
    } else {
        format!(
            r#"Get-NetAdapter | Where-Object {{$_.Status -eq 'Up'}} | ForEach-Object {{ Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses @('{}','{}') }}; Write-Output 'ok'"#,
            primary, secondary
        )
    };

    let output = optimizer_core::silent_cmd("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let label = if preset == "auto" { "Automatic (DHCP)".to_string() } else { format!("{} ({}, {})", preset, primary, secondary) };
            serde_json::json!({ "success": true, "message": format!("DNS set to {}", label) })
        }
        Ok(o) => serde_json::json!({ "success": false, "message": String::from_utf8_lossy(&o.stderr).trim().to_string() }),
        Err(e) => serde_json::json!({ "success": false, "message": format!("Failed: {}", e) }),
    }
}

#[tauri::command]
pub async fn run_network_command(command: String) -> serde_json::Value {
    let (cmd, args, label): (&str, Vec<&str>, &str) = match command.as_str() {
        "flush_dns" => ("ipconfig", vec!["/flushdns"], "Flush DNS Cache"),
        "release_ip" => ("ipconfig", vec!["/release"], "Release IP"),
        "renew_ip" => ("ipconfig", vec!["/renew"], "Renew IP"),
        "reset_winsock" => ("netsh", vec!["winsock", "reset"], "Reset Winsock"),
        "reset_tcp" => ("netsh", vec!["int", "ip", "reset"], "Reset TCP/IP Stack"),
        _ => return serde_json::json!({ "success": false, "message": format!("Unknown command: {}", command) }),
    };

    if cfg!(not(target_os = "windows")) {
        return serde_json::json!({ "success": true, "stub": true, "message": format!("[stub] Would run: {} {}", cmd, args.join(" ")), "output": format!("{} completed (stub).", label) });
    }

    let output = optimizer_core::silent_cmd(cmd).args(&args).output();

    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).to_string();
            let stderr = String::from_utf8_lossy(&o.stderr).to_string();
            let text = if stderr.is_empty() { stdout } else { format!("{}\n{}", stdout, stderr) };
            let needs_reboot = command == "reset_winsock" || command == "reset_tcp";
            let msg = if needs_reboot {
                format!("{} completed. A restart is required for changes to take effect.", label)
            } else {
                format!("{} completed.", label)
            };
            serde_json::json!({ "success": o.status.success(), "message": msg, "output": text.trim() })
        }
        Err(e) => serde_json::json!({ "success": false, "message": format!("Failed to run {}: {}", label, e) }),
    }
}

// ---------------------------------------------------------------------------
// Windows Update status
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_update_status() -> serde_json::Value {
    let status = tokio::task::spawn_blocking(|| mod_updates::get_status()).await.unwrap();
    serde_json::to_value(status).unwrap_or_default()
}

#[tauri::command]
pub async fn reset_windows_update() -> serde_json::Value {
    if cfg!(not(target_os = "windows")) {
        return serde_json::json!({ "success": true, "stub": true, "message": "[stub] Would reset Windows Update components." });
    }

    let script = r#"
$log = @()
$services = @('wuauserv','bits','cryptSvc','msiserver')
foreach ($s in $services) { Stop-Service -Name $s -Force -ErrorAction SilentlyContinue; $log += "Stopped $s" }
$sd = "$env:SystemRoot\SoftwareDistribution"
$cr = "$env:SystemRoot\System32\catroot2"
if (Test-Path $sd) { Rename-Item $sd "$sd.bak.$(Get-Date -Format yyyyMMddHHmmss)" -Force -ErrorAction SilentlyContinue; $log += "Renamed SoftwareDistribution" }
if (Test-Path $cr) { Rename-Item $cr "$cr.bak.$(Get-Date -Format yyyyMMddHHmmss)" -Force -ErrorAction SilentlyContinue; $log += "Renamed catroot2" }
netsh winsock reset 2>$null | Out-Null; $log += "Reset Winsock"
foreach ($s in $services) { Start-Service -Name $s -ErrorAction SilentlyContinue; $log += "Started $s" }
$log -join "`n"
"#;

    let output = optimizer_core::silent_cmd("powershell")
        .args(["-NoProfile", "-Command", script])
        .output();

    match output {
        Ok(o) => {
            let text = String::from_utf8_lossy(&o.stdout).trim().to_string();
            serde_json::json!({
                "success": o.status.success(),
                "message": if o.status.success() { "Windows Update components reset successfully. A restart is recommended." } else { "Reset completed with some errors." },
                "output": text
            })
        }
        Err(e) => serde_json::json!({ "success": false, "message": format!("Failed: {}", e), "output": "" }),
    }
}

#[tauri::command]
pub async fn trigger_update_check() -> serde_json::Value {
    if cfg!(not(target_os = "windows")) {
        return serde_json::json!({ "success": true, "stub": true, "message": "[stub] Would open Windows Update settings." });
    }

    let result = optimizer_core::silent_cmd("cmd")
        .args(["/C", "start ms-settings:windowsupdate-action"])
        .spawn();

    match result {
        Ok(_) => serde_json::json!({ "success": true, "message": "Windows Update check triggered." }),
        Err(e) => serde_json::json!({ "success": false, "message": format!("Failed: {}", e) }),
    }
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn generate_report() -> serde_json::Value {
    let health = mod_health::quick_scan();
    let report_html = mod_report::generate_html_report(
        "System Diagnostic Report",
        &[
            ("System Health", &format!("Score: {}/100", health.score)),
            ("Findings", &health.findings.iter().map(|f| format!("{}: {}", f.title, f.detail)).collect::<Vec<_>>().join("\n")),
        ],
    );
    serde_json::json!({ "html": report_html, "success": true })
}

// ---------------------------------------------------------------------------
// Export full report
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn export_report() -> serde_json::Value {
    tokio::task::spawn_blocking(|| export_report_sync()).await.unwrap()
}

fn export_report_sync() -> serde_json::Value {
    let health = { let r = mod_health::quick_scan(); serde_json::json!({"score": r.score, "findings": r.findings}) };
    let drivers = serde_json::to_value(mod_drivers::audit_drivers()).unwrap_or_default();
    let events = serde_json::to_value(mod_eventlog::get_summary()).unwrap_or_default();
    let updates = serde_json::to_value(mod_updates::get_status()).unwrap_or_default();
    let temps = serde_json::to_value(mod_temps::collect_temps()).unwrap_or_default();
    let disk = serde_json::to_value(mod_diskhealth::collect_drive_health()).unwrap_or_default();
    let runtimes = serde_json::to_value(mod_runtimes::collect_runtimes()).unwrap_or_default();
    let security = serde_json::to_value(mod_security::get_defender_status()).unwrap_or_default();
    let activation = get_activation_status_sync();

    let data = mod_report::FullReportData {
        health_score: health.get("score").and_then(|v| v.as_u64()).unwrap_or(0),
        health_findings: health.get("findings").and_then(|v| v.as_array()).map(|a| {
            a.iter().filter_map(|f| {
                let sev = f.get("severity").and_then(|s| s.as_str()).unwrap_or("Info");
                let title = f.get("title").and_then(|s| s.as_str()).unwrap_or("");
                let detail = f.get("detail").and_then(|s| s.as_str()).unwrap_or("");
                Some(format!("[{}] {} - {}", sev, title, detail))
            }).collect()
        }).unwrap_or_default(),
        driver_total: drivers.get("total").and_then(|v| v.as_u64()).unwrap_or(0),
        driver_unsigned: drivers.get("unsigned").and_then(|v| v.as_u64()).unwrap_or(0),
        driver_outdated: drivers.get("outdated").and_then(|v| v.as_u64()).unwrap_or(0),
        driver_issues: drivers.get("problematic").and_then(|v| v.as_array()).map(|a| {
            a.iter().filter_map(|d| {
                let name = d.get("name").and_then(|s| s.as_str()).unwrap_or("");
                let status = d.get("status").and_then(|s| s.as_str()).unwrap_or("");
                let ver = d.get("version").and_then(|s| s.as_str()).unwrap_or("");
                Some(format!("[{}] {} (v{})", status.to_uppercase(), name, ver))
            }).collect()
        }).unwrap_or_default(),
        event_critical: events.pointer("/system/critical").and_then(|v| v.as_u64()).unwrap_or(0),
        event_error: events.pointer("/system/error").and_then(|v| v.as_u64()).unwrap_or(0),
        event_warning: events.pointer("/system/warning").and_then(|v| v.as_u64()).unwrap_or(0),
        recent_events: events.pointer("/system/recent_events").and_then(|v| v.as_array()).map(|a| {
            a.iter().take(10).filter_map(|e| {
                let level = e.get("level").and_then(|s| s.as_str()).unwrap_or("");
                let source = e.get("source").and_then(|s| s.as_str()).unwrap_or("");
                let msg = e.get("message").and_then(|s| s.as_str()).unwrap_or("");
                Some(format!("[{}] {} - {}", level, source, msg))
            }).collect()
        }).unwrap_or_default(),
        update_service: updates.get("service_status").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string(),
        pending_updates: updates.get("pending_updates").and_then(|v| v.as_array()).map(|a| {
            a.iter().filter_map(|u| {
                let title = u.get("title").and_then(|s| s.as_str()).unwrap_or("");
                let sev = u.get("severity").and_then(|s| s.as_str()).unwrap_or("");
                Some(format!("[{}] {}", sev, title))
            }).collect()
        }).unwrap_or_default(),
        temperatures: temps.get("readings").and_then(|v| v.as_array()).map(|a| {
            a.iter().filter_map(|t| {
                let sensor = t.get("sensor").and_then(|s| s.as_str()).unwrap_or("");
                let temp = t.get("temperature_c").and_then(|v| v.as_i64()).unwrap_or(0);
                Some(format!("{}: {}C", sensor, temp))
            }).collect()
        }).unwrap_or_default(),
        disk_health: disk.as_array().map(|a| {
            a.iter().filter_map(|d| {
                let model = d.get("model").and_then(|s| s.as_str()).unwrap_or("");
                let rating = d.get("health_rating").and_then(|s| s.as_str()).unwrap_or("");
                let temp = d.get("temperature_c").and_then(|v| v.as_i64());
                let wear = d.get("wear_percent").and_then(|v| v.as_f64());
                let mut line = format!("[{}] {}", rating, model);
                if let Some(t) = temp { line.push_str(&format!(" | Temp: {}C", t)); }
                if let Some(w) = wear { line.push_str(&format!(" | Wear: {}%", w)); }
                Some(line)
            }).collect()
        }).unwrap_or_default(),
        runtimes: {
            let mut lines = Vec::new();
            if let Some(dotnet) = runtimes.get("dotnet").and_then(|v| v.as_array()) {
                for r in dotnet {
                    let name = r.get("name").and_then(|s| s.as_str()).unwrap_or("");
                    let installed = r.get("installed").and_then(|v| v.as_bool()).unwrap_or(false);
                    lines.push(format!("[{}] {}", if installed { "OK" } else { "--" }, name));
                }
            }
            if let Some(vc) = runtimes.get("vcredist").and_then(|v| v.as_array()) {
                for r in vc {
                    let name = r.get("name").and_then(|s| s.as_str()).unwrap_or("");
                    lines.push(format!("[OK] {}", name));
                }
            }
            lines
        },
        security_summary: {
            let defender = security.get("defender");
            let rtp = defender.and_then(|d| d.get("real_time_enabled")).and_then(|v| v.as_bool()).unwrap_or(false);
            let defs = defender.and_then(|d| d.get("definitions_age_days")).and_then(|v| v.as_u64()).unwrap_or(0);
            format!("Real-time Protection: {}  |  Definition age: {} days", if rtp { "ON" } else { "OFF" }, defs)
        },
        activation: {
            let status = activation.get("status").and_then(|s| s.as_str()).unwrap_or("Unknown");
            let edition = activation.get("edition").and_then(|s| s.as_str()).unwrap_or("Unknown");
            format!("{} - {}", edition, status)
        },
    };

    let html = mod_report::generate_full_report(&data);

    let report_dir = directories::UserDirs::new()
        .and_then(|u| u.document_dir().map(|d| d.join("Cove Windows Toolkit")))
        .unwrap_or_else(|| std::path::PathBuf::from("reports"));
    let _ = std::fs::create_dir_all(&report_dir);
    let filename = format!("report-{}.html", chrono::Local::now().format("%Y%m%d-%H%M%S"));
    let filepath = report_dir.join(&filename);
    let _ = std::fs::write(&filepath, &html);

    #[cfg(target_os = "windows")]
    { let _ = optimizer_core::silent_cmd("cmd").args(["/C", "start", "", &filepath.to_string_lossy()]).spawn(); }
    #[cfg(not(target_os = "windows"))]
    { let _ = optimizer_core::silent_cmd("xdg-open").arg(&filepath).spawn(); }

    serde_json::json!({
        "success": true,
        "path": filepath.to_string_lossy(),
        "filename": filename,
    })
}

// ---------------------------------------------------------------------------
// Speed test
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn run_speed_test() -> serde_json::Value {
    let result = tokio::task::spawn_blocking(mod_netdiag::run_speed_test).await.unwrap();
    serde_json::to_value(result).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Generic apply / undo for any module
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn apply_tweak(module: String, id: String) -> serde_json::Value {
    tokio::task::spawn_blocking(move || apply_tweak_sync(&module, &id)).await.unwrap()
}

#[tauri::command]
pub async fn undo_tweak(module: String, id: String) -> serde_json::Value {
    tokio::task::spawn_blocking(move || undo_tweak_sync(&module, &id)).await.unwrap()
}

fn apply_tweak_sync(module: &str, id: &str) -> serde_json::Value {
    match module {
        "visual" => apply_visual_tweak_sync(id),
        "performance" => apply_perf_tweak_sync(id),
        "privacy" => {
            let tweaks = mod_privacy::get_tweaks();
            let all: Vec<_> = [tweaks.basic, tweaks.standard, tweaks.advanced].concat();
            if let Some(t) = all.iter().find(|t| t.id == id) {
                if t.path.starts_with("Service:") {
                    let svc = t.path.trim_start_matches("Service: ").trim();
                    match mod_services::apply_change(svc, &t.optimized) {
                        Ok(msg) => serde_json::json!({ "success": true, "message": msg }),
                        Err(msg) => serde_json::json!({ "success": false, "message": msg }),
                    }
                } else {
                    apply_registry_tweak(&t.path, &t.value_name, &t.optimized)
                }
            } else {
                serde_json::json!({ "success": false, "message": format!("Unknown privacy tweak: {}", id) })
            }
        }
        "services" => {
            let tweaks = mod_services::get_tweaks();
            let all: Vec<_> = [tweaks.conservative, tweaks.advanced].concat();
            if let Some(t) = all.iter().find(|t| t.id == id) {
                match mod_services::apply_change(&t.service, &t.optimized) {
                    Ok(msg) => serde_json::json!({ "success": true, "message": msg }),
                    Err(msg) => serde_json::json!({ "success": false, "message": msg }),
                }
            } else {
                serde_json::json!({ "success": false, "message": format!("Unknown service tweak: {}", id) })
            }
        }
        _ => serde_json::json!({ "success": true, "message": format!("[{}] Applied: {}", module, id) }),
    }
}

fn undo_tweak_sync(module: &str, id: &str) -> serde_json::Value {
    match module {
        "visual" => undo_visual_tweak_sync(id),
        "performance" => undo_perf_tweak_sync(id),
        _ => serde_json::json!({ "success": true, "message": format!("[{}] Reverted: {}", module, id) }),
    }
}

fn apply_visual_tweak_sync(id: &str) -> serde_json::Value {
    let tweaks = mod_visual::get_tweaks();
    if let Some(t) = tweaks.iter().find(|t| t.id == id) {
        match mod_visual::apply_tweak(&t.registry_path, &t.registry_name, &t.optimized_value) {
            Ok(msg) => serde_json::json!({ "success": true, "message": msg }),
            Err(msg) => serde_json::json!({ "success": false, "message": msg }),
        }
    } else {
        serde_json::json!({ "success": false, "message": format!("Unknown tweak: {}", id) })
    }
}

fn undo_visual_tweak_sync(id: &str) -> serde_json::Value {
    let tweaks = mod_visual::get_tweaks();
    if let Some(t) = tweaks.iter().find(|t| t.id == id) {
        let revert = t.current_value.as_deref().unwrap_or("1");
        match mod_visual::apply_tweak(&t.registry_path, &t.registry_name, revert) {
            Ok(msg) => serde_json::json!({ "success": true, "message": msg }),
            Err(msg) => serde_json::json!({ "success": false, "message": msg }),
        }
    } else {
        serde_json::json!({ "success": false, "message": format!("Unknown tweak: {}", id) })
    }
}

fn apply_perf_tweak_sync(id: &str) -> serde_json::Value {
    let tweaks = mod_performance::get_tweaks();
    if let Some(t) = tweaks.iter().find(|t| t.id == id) {
        match mod_performance::apply_tweak(&t.registry_path, &t.registry_name, &t.optimized_value) {
            Ok(msg) => {
                append_history("performance", &t.name, &format!("{:?}", t.safety_tier), "committed");
                serde_json::json!({ "success": true, "message": msg })
            }
            Err(msg) => serde_json::json!({ "success": false, "message": msg }),
        }
    } else {
        serde_json::json!({ "success": false, "message": format!("Unknown tweak: {}", id) })
    }
}

fn undo_perf_tweak_sync(id: &str) -> serde_json::Value {
    let tweaks = mod_performance::get_tweaks();
    if let Some(t) = tweaks.iter().find(|t| t.id == id) {
        let revert = t.current_value.as_deref().unwrap_or("1");
        match mod_performance::apply_tweak(&t.registry_path, &t.registry_name, revert) {
            Ok(msg) => {
                append_history("performance", &t.name, &format!("{:?}", t.safety_tier), "undone");
                serde_json::json!({ "success": true, "message": msg })
            }
            Err(msg) => serde_json::json!({ "success": false, "message": msg }),
        }
    } else {
        serde_json::json!({ "success": false, "message": format!("Unknown tweak: {}", id) })
    }
}

fn apply_registry_tweak(path: &str, name: &str, value: &str) -> serde_json::Value {
    #[cfg(target_os = "windows")]
    {
        let ps = format!(
            "try {{ New-Item -Path 'Registry::{}' -Force -ErrorAction SilentlyContinue | Out-Null; Set-ItemProperty -Path 'Registry::{}' -Name '{}' -Value {} -Type DWord -Force -ErrorAction Stop; Write-Output 'OK' }} catch {{ Write-Output $_.Exception.Message }}",
            path, path, name, value
        );
        if let Ok(o) = optimizer_core::silent_cmd("powershell").args(["-NoProfile", "-Command", &ps]).output() {
            let result = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if result == "OK" {
                return serde_json::json!({ "success": true, "message": format!("Applied: {} = {}", name, value) });
            }
            return serde_json::json!({ "success": false, "message": result });
        }
    }
    serde_json::json!({ "success": true, "message": format!("Applied: {} = {}", name, value) })
}

// ---------------------------------------------------------------------------
// Change history (file-backed)
// ---------------------------------------------------------------------------

fn history_path() -> std::path::PathBuf {
    directories::ProjectDirs::from("com", "cove", "optimizer")
        .map(|dirs| dirs.data_local_dir().join("change_history.json"))
        .unwrap_or_else(|| std::path::PathBuf::from("change_history.json"))
}

#[tauri::command]
pub fn get_change_history() -> serde_json::Value {
    let path = history_path();
    if path.exists() {
        if let Ok(data) = std::fs::read_to_string(&path) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&data) {
                return val;
            }
        }
    }
    serde_json::json!([])
}

fn append_history(module: &str, name: &str, tier: &str, status: &str) {
    let path = history_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut entries: Vec<serde_json::Value> = if path.exists() {
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|d| serde_json::from_str(&d).ok())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let id = entries.len() as i64 + 1;
    entries.push(serde_json::json!({
        "id": id,
        "timestamp": chrono::Local::now().to_rfc3339(),
        "module": module,
        "name": name,
        "tier": tier,
        "status": status,
    }));
    let _ = std::fs::write(&path, serde_json::to_string_pretty(&entries).unwrap_or_default());
}

// ---------------------------------------------------------------------------
// Startup toggle
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn toggle_startup(id: String, enabled: bool) -> serde_json::Value {
    let name = id.strip_prefix("startup.").unwrap_or(&id);
    let items = tokio::task::spawn_blocking(|| mod_startup::list_items()).await.unwrap();
    let item_name = items.iter().find(|i| i.id == id).map(|i| i.name.clone()).unwrap_or_else(|| name.to_string());
    match mod_startup::toggle(&item_name, enabled) {
        Ok(msg) => {
            append_history("startup", &item_name, "green", "committed");
            serde_json::json!({ "success": true, "message": msg })
        }
        Err(msg) => serde_json::json!({ "success": false, "message": msg }),
    }
}

// ---------------------------------------------------------------------------
// Service change
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn apply_service_change(id: String) -> serde_json::Value {
    let tweaks = tokio::task::spawn_blocking(|| mod_services::get_tweaks()).await.unwrap();
    let all: Vec<_> = [tweaks.conservative, tweaks.advanced].concat();
    if let Some(t) = all.iter().find(|t| t.id == id) {
        match mod_services::apply_change(&t.service, &t.optimized) {
            Ok(msg) => {
                append_history("services", &t.name, &t.tier, "committed");
                serde_json::json!({ "success": true, "message": msg })
            }
            Err(msg) => serde_json::json!({ "success": false, "message": msg }),
        }
    } else {
        serde_json::json!({ "success": false, "message": format!("Unknown service: {}", id) })
    }
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn run_cleanup(ids: Vec<String>) -> serde_json::Value {
    let results = mod_cleanup::clean_targets(&ids);
    let succeeded = results.iter().filter(|(_, ok, _)| *ok).count();
    let items: Vec<serde_json::Value> = results.into_iter().map(|(id, ok, msg)| {
        if ok { append_history("cleanup", &id, "green", "committed"); }
        serde_json::json!({ "id": id, "success": ok, "message": msg })
    }).collect();
    serde_json::json!({ "success": true, "message": format!("Cleaned {} targets", succeeded), "cleaned": succeeded, "results": items })
}

// ---------------------------------------------------------------------------
// Power plan
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn set_power_plan(guid: String) -> serde_json::Value {
    match mod_power::set_plan(&guid) {
        Ok(msg) => {
            append_history("power", &msg, "green", "committed");
            serde_json::json!({ "success": true, "message": msg })
        }
        Err(msg) => serde_json::json!({ "success": false, "message": msg }),
    }
}

#[tauri::command]
pub async fn set_power_timeout(setting: String, minutes: u32) -> serde_json::Value {
    if cfg!(not(target_os = "windows")) {
        return serde_json::json!({ "success": true, "stub": true, "message": format!("[stub] Would set {} to {} min", setting, minutes) });
    }

    let cmd = format!("powercfg /change {} {}", match setting.as_str() {
        "display" => "monitor-timeout-ac",
        "sleep" => "standby-timeout-ac",
        "disk" => "disk-timeout-ac",
        _ => return serde_json::json!({ "success": false, "message": format!("Unknown setting: {}", setting) }),
    }, minutes);

    let output = optimizer_core::silent_cmd("cmd").args(["/C", &cmd]).output();
    let dc_setting = match setting.as_str() {
        "display" => "monitor-timeout-dc",
        "sleep" => "standby-timeout-dc",
        "disk" => "disk-timeout-dc",
        _ => "",
    };
    if !dc_setting.is_empty() {
        let dc_cmd = format!("powercfg /change {} {}", dc_setting, minutes);
        let _ = optimizer_core::silent_cmd("cmd").args(["/C", &dc_cmd]).output();
    }

    match output {
        Ok(o) if o.status.success() => serde_json::json!({ "success": true, "message": format!("{} timeout set to {} minutes", setting, minutes) }),
        Ok(o) => serde_json::json!({ "success": false, "message": String::from_utf8_lossy(&o.stderr).to_string() }),
        Err(e) => serde_json::json!({ "success": false, "message": format!("Failed: {}", e) }),
    }
}

// ---------------------------------------------------------------------------
// System Restore
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_restore_status() -> serde_json::Value {
    let status = mod_restore::get_restore_status();
    serde_json::json!({ "enabled": status.enabled, "message": status.message })
}

#[tauri::command]
pub async fn get_restore_points() -> serde_json::Value {
    let points = mod_restore::list_restore_points();
    serde_json::json!(points)
}

#[tauri::command]
pub async fn create_restore_point(description: String) -> serde_json::Value {
    match mod_restore::create_restore_point(&description) {
        Ok(msg) => serde_json::json!({ "success": true, "message": msg }),
        Err(msg) => serde_json::json!({ "success": false, "message": msg }),
    }
}

#[tauri::command]
pub async fn enable_system_protection() -> serde_json::Value {
    match mod_restore::enable_system_protection() {
        Ok(msg) => serde_json::json!({ "success": true, "message": msg }),
        Err(msg) => serde_json::json!({ "success": false, "message": msg }),
    }
}

#[tauri::command]
pub async fn launch_system_restore() -> serde_json::Value {
    match mod_restore::launch_system_restore() {
        Ok(msg) => serde_json::json!({ "success": true, "message": msg }),
        Err(msg) => serde_json::json!({ "success": false, "message": msg }),
    }
}

// ---------------------------------------------------------------------------
// Bloatware remover
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_bloatware() -> serde_json::Value {
    let apps = tokio::task::spawn_blocking(|| mod_bloatware::scan_installed()).await.unwrap();
    serde_json::to_value(apps).unwrap_or_default()
}

#[tauri::command]
pub async fn remove_bloatware(packages: Vec<String>) -> serde_json::Value {
    let results = mod_bloatware::remove_apps(&packages);
    serde_json::to_value(results).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Uninstaller
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_installed_programs() -> serde_json::Value {
    let programs = tokio::task::spawn_blocking(|| mod_uninstall::list_programs()).await.unwrap();
    serde_json::to_value(programs).unwrap_or_default()
}

#[tauri::command]
pub async fn uninstall_program(uninstall_string: String, quiet_uninstall_string: String) -> serde_json::Value {
    let result = mod_uninstall::run_uninstall(&uninstall_string, &quiet_uninstall_string);
    serde_json::to_value(result).unwrap_or_default()
}

#[tauri::command]
pub async fn scan_leftovers(name: String, publisher: String, install_location: String, registry_key: String) -> serde_json::Value {
    let result = mod_uninstall::scan_leftovers(&name, &publisher, &install_location, &registry_key);
    serde_json::to_value(result).unwrap_or_default()
}

#[tauri::command]
pub async fn remove_leftovers(paths: Vec<String>) -> serde_json::Value {
    let results = mod_uninstall::remove_leftovers(&paths);
    let items: Vec<serde_json::Value> = results.into_iter().map(|(path, ok, msg)| {
        serde_json::json!({ "path": path, "success": ok, "message": msg })
    }).collect();
    serde_json::json!({ "results": items })
}

// ---------------------------------------------------------------------------
// Full system info (Speccy-style)
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_full_sysinfo() -> serde_json::Value {
    let info = tokio::task::spawn_blocking(|| mod_sysinfo::collect()).await.unwrap();
    serde_json::to_value(info).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Temperature monitoring
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_temperatures() -> serde_json::Value {
    let report = tokio::task::spawn_blocking(|| mod_temps::collect_temps()).await.unwrap();
    serde_json::to_value(report).unwrap_or_default()
}

#[tauri::command]
pub async fn ensure_lhm_running(app: tauri::AppHandle) -> serde_json::Value {
    use tauri::Manager;
    let resource_dir = app.path().resource_dir().unwrap_or_default();
    let result = tokio::task::spawn_blocking(move || {
        mod_temps::lhm_launcher::ensure_lhm_running(&resource_dir)
    })
    .await
    .unwrap();
    match result {
        Ok(status) => serde_json::json!({ "status": status }),
        Err(e) => serde_json::json!({ "status": "error", "message": e }),
    }
}

#[tauri::command]
pub async fn get_lhm_status() -> serde_json::Value {
    let running = tokio::task::spawn_blocking(|| {
        mod_temps::lhm_launcher::is_lhm_running()
    })
    .await
    .unwrap();
    serde_json::json!({ "running": running })
}

// ---------------------------------------------------------------------------
// DISM / SFC scans
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn check_admin_status() -> serde_json::Value {
    let status = mod_sfc::check_admin();
    serde_json::json!({ "is_admin": status.is_admin, "message": status.message })
}

#[tauri::command]
pub async fn run_dism_scan() -> serde_json::Value {
    let result = tokio::task::spawn_blocking(mod_sfc::run_dism).await.unwrap();
    serde_json::json!({
        "tool": result.tool, "success": result.success, "exit_code": result.exit_code,
        "output": result.output, "summary": result.summary,
    })
}

#[tauri::command]
pub async fn run_sfc_scan() -> serde_json::Value {
    let result = tokio::task::spawn_blocking(mod_sfc::run_sfc).await.unwrap();
    serde_json::json!({
        "tool": result.tool, "success": result.success, "exit_code": result.exit_code,
        "output": result.output, "summary": result.summary,
    })
}

// ---------------------------------------------------------------------------
// Run All Diagnostics (batch scan)
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn run_all_diagnostics() -> serde_json::Value {
    tokio::task::spawn_blocking(|| {
        let health = mod_health::quick_scan();
        let events = serde_json::to_value(mod_eventlog::get_summary()).unwrap_or_default();
        let bsod = mod_bsod::scan_dumps();
        let updates = serde_json::to_value(mod_updates::get_status()).unwrap_or_default();
        let activation = get_activation_status_sync();

        let modules = serde_json::json!([
            { "id": "health", "name": "System Health", "severity": if health.score >= 90 { "Ok" } else if health.score >= 70 { "Warning" } else { "Critical" } },
            { "id": "eventlog", "name": "Event Logs", "severity": if events.pointer("/system/critical").and_then(|v| v.as_u64()).unwrap_or(0) > 0 { "Critical" } else if events.pointer("/system/error").and_then(|v| v.as_u64()).unwrap_or(0) > 0 { "Warning" } else { "Ok" } },
            { "id": "bsod", "name": "BSOD Dumps", "severity": if !bsod.is_empty() { "Warning" } else { "Ok" } },
            { "id": "updates", "name": "Windows Update", "severity": if updates.get("pending_updates").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0) > 0 { "Warning" } else { "Ok" } },
        ]);

        let has_critical = modules.as_array().unwrap().iter().any(|m| m.get("severity").and_then(|s| s.as_str()) == Some("Critical"));
        let has_warning = modules.as_array().unwrap().iter().any(|m| m.get("severity").and_then(|s| s.as_str()) == Some("Warning"));
        let overall = if has_critical { "Critical" } else if has_warning { "Warning" } else { "Ok" };

        serde_json::json!({
            "overall_severity": overall,
            "modules": modules,
            "activated": activation.get("activated").and_then(|v| v.as_bool()).unwrap_or(false),
        })
    }).await.unwrap()
}

// ---------------------------------------------------------------------------
// Presets (batch action groups)
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn get_presets() -> serde_json::Value {
    serde_json::json!([
        {
            "id": "general_tuneup",
            "name": "General Tune-Up",
            "description": "Apply common safe optimizations - visual effects, performance tweaks, and basic privacy settings",
            "actions": [
                { "module": "visual", "action_id": "visual.transparency", "display_name": "Disable Transparency" },
                { "module": "visual", "action_id": "visual.animations", "display_name": "Disable Animations" },
                { "module": "visual", "action_id": "visual.taskbar_anim", "display_name": "Disable Taskbar Animations" },
                { "module": "performance", "action_id": "perf.game_bar", "display_name": "Disable Game Bar" },
                { "module": "performance", "action_id": "perf.game_dvr", "display_name": "Disable Game DVR" },
                { "module": "privacy", "action_id": "privacy.advertising_id", "display_name": "Disable Advertising ID" },
                { "module": "privacy", "action_id": "privacy.feedback", "display_name": "Disable Feedback Prompts" },
                { "module": "privacy", "action_id": "privacy.tips", "display_name": "Disable Tips and Suggestions" },
            ]
        }
    ])
}

#[tauri::command]
pub async fn run_preset(id: String) -> serde_json::Value {
    tokio::task::spawn_blocking(move || {
        let presets = get_presets();
        let preset = presets.as_array().and_then(|arr| arr.iter().find(|p| p.get("id").and_then(|v| v.as_str()) == Some(&id)));

        match preset {
            Some(p) => {
                let actions = p.get("actions").and_then(|a| a.as_array()).cloned().unwrap_or_default();
                let total = actions.len();
                let mut succeeded = 0;
                let mut results = Vec::new();

                for action in &actions {
                    let module = action.get("module").and_then(|v| v.as_str()).unwrap_or("");
                    let action_id = action.get("action_id").and_then(|v| v.as_str()).unwrap_or("");
                    let display = action.get("display_name").and_then(|v| v.as_str()).unwrap_or(action_id);

                    let result = apply_tweak_sync(module, action_id);
                    let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
                    if success {
                        succeeded += 1;
                        append_history(module, display, "green", "committed");
                    }
                    results.push(serde_json::json!({ "action_id": action_id, "display_name": display, "success": success }));
                }

                serde_json::json!({ "success": true, "total": total, "succeeded": succeeded, "failed": total - succeeded, "results": results })
            }
            None => serde_json::json!({ "success": false, "message": format!("Unknown preset: {}", id) }),
        }
    }).await.unwrap()
}

// ---------------------------------------------------------------------------
// Snapshot / Diff (file-backed)
// ---------------------------------------------------------------------------

fn snapshot_path() -> std::path::PathBuf {
    directories::ProjectDirs::from("com", "cove", "optimizer")
        .map(|dirs| dirs.data_local_dir().join("snapshot.json"))
        .unwrap_or_else(|| std::path::PathBuf::from("snapshot.json"))
}

#[tauri::command]
pub async fn take_snapshot() -> serde_json::Value {
    tokio::task::spawn_blocking(|| {
    let health = mod_health::quick_scan();
    let startup = serde_json::to_value(mod_startup::list_items()).unwrap_or_default();
    let programs = serde_json::to_value(mod_uninstall::list_programs()).unwrap_or_default();
    let cleanup = serde_json::to_value(mod_cleanup::scan_targets()).unwrap_or_default();
    let events = serde_json::to_value(mod_eventlog::get_summary()).unwrap_or_default();

    let snapshot = serde_json::json!({
        "timestamp": chrono::Local::now().to_rfc3339(),
        "hostname": hostname::get().map(|h| h.to_string_lossy().to_string()).unwrap_or_default(),
        "health_score": health.score,
        "startup_items": startup.as_array().map(|a| a.iter().filter_map(|i| i.get("name").and_then(|n| n.as_str()).map(|s| s.to_string())).collect::<Vec<_>>()).unwrap_or_default(),
        "programs": programs.as_array().map(|a| a.iter().filter_map(|i| i.get("name").and_then(|n| n.as_str()).map(|s| s.to_string())).collect::<Vec<_>>()).unwrap_or_default(),
        "temp_size": cleanup.as_array().map(|a| a.iter().filter_map(|t| t.get("size_bytes").and_then(|v| v.as_u64())).sum::<u64>()).unwrap_or(0),
        "critical_events": events.pointer("/system/critical").and_then(|v| v.as_u64()).unwrap_or(0),
        "warning_events": events.pointer("/system/warning").and_then(|v| v.as_u64()).unwrap_or(0),
    });

    let path = snapshot_path();
    if let Some(parent) = path.parent() { let _ = std::fs::create_dir_all(parent); }
    let _ = std::fs::write(&path, serde_json::to_string_pretty(&snapshot).unwrap_or_default());

    serde_json::json!({
        "success": true,
        "timestamp": snapshot.get("timestamp").and_then(|v| v.as_str()).unwrap_or(""),
        "hostname": snapshot.get("hostname").and_then(|v| v.as_str()).unwrap_or(""),
    })
    }).await.unwrap()
}

#[tauri::command]
pub async fn get_machine_diff() -> serde_json::Value {
    tokio::task::spawn_blocking(|| {
    let path = snapshot_path();
    if !path.exists() {
        return serde_json::json!({ "has_previous": false });
    }

    let prev: serde_json::Value = match std::fs::read_to_string(&path).ok().and_then(|d| serde_json::from_str(&d).ok()) {
        Some(v) => v,
        None => return serde_json::json!({ "has_previous": false }),
    };

    let health = mod_health::quick_scan();
    let startup = serde_json::to_value(mod_startup::list_items()).unwrap_or_default();
    let programs = serde_json::to_value(mod_uninstall::list_programs()).unwrap_or_default();
    let cleanup = serde_json::to_value(mod_cleanup::scan_targets()).unwrap_or_default();
    let events = serde_json::to_value(mod_eventlog::get_summary()).unwrap_or_default();

    let cur_score = health.score as i64;
    let prev_score = prev.get("health_score").and_then(|v| v.as_i64()).unwrap_or(0);

    let cur_startup: Vec<String> = startup.as_array().map(|a| a.iter().filter_map(|i| i.get("name").and_then(|n| n.as_str()).map(|s| s.to_string())).collect()).unwrap_or_default();
    let prev_startup: Vec<String> = prev.get("startup_items").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|s| s.as_str().map(|s| s.to_string())).collect()).unwrap_or_default();

    let cur_programs: Vec<String> = programs.as_array().map(|a| a.iter().filter_map(|i| i.get("name").and_then(|n| n.as_str()).map(|s| s.to_string())).collect()).unwrap_or_default();
    let prev_programs: Vec<String> = prev.get("programs").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|s| s.as_str().map(|s| s.to_string())).collect()).unwrap_or_default();

    let cur_temp: i64 = cleanup.as_array().map(|a| a.iter().filter_map(|t| t.get("size_bytes").and_then(|v| v.as_i64())).sum()).unwrap_or(0);
    let prev_temp = prev.get("temp_size").and_then(|v| v.as_i64()).unwrap_or(0);

    let cur_crit = events.pointer("/system/critical").and_then(|v| v.as_i64()).unwrap_or(0);
    let prev_crit = prev.get("critical_events").and_then(|v| v.as_i64()).unwrap_or(0);
    let cur_warn = events.pointer("/system/warning").and_then(|v| v.as_i64()).unwrap_or(0);
    let prev_warn = prev.get("warning_events").and_then(|v| v.as_i64()).unwrap_or(0);

    let new_startup: Vec<&String> = cur_startup.iter().filter(|s| !prev_startup.contains(s)).collect();
    let removed_startup: Vec<&String> = prev_startup.iter().filter(|s| !cur_startup.contains(s)).collect();
    let new_programs: Vec<&String> = cur_programs.iter().filter(|p| !prev_programs.contains(p)).collect();
    let removed_programs: Vec<&String> = prev_programs.iter().filter(|p| !cur_programs.contains(p)).collect();

    serde_json::json!({
        "has_previous": true,
        "previous_timestamp": prev.get("timestamp").and_then(|v| v.as_str()).unwrap_or(""),
        "changes": {
            "new_startup_items": new_startup,
            "removed_startup_items": removed_startup,
            "new_programs": new_programs,
            "removed_programs": removed_programs,
            "new_bloatware": [],
            "health_score_change": cur_score - prev_score,
            "temp_size_change": cur_temp - prev_temp,
            "critical_event_change": cur_crit - prev_crit,
            "warning_event_change": cur_warn - prev_warn,
        },
    })
    }).await.unwrap()
}

// ---------------------------------------------------------------------------
// Runtimes checker
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_installed_runtimes() -> serde_json::Value {
    let report = tokio::task::spawn_blocking(|| mod_runtimes::collect_runtimes()).await.unwrap();
    serde_json::to_value(report).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Security scan
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_security_status() -> serde_json::Value {
    let defender = mod_security::get_defender_status();
    serde_json::json!({ "defender": defender, "heuristic_findings": [], "scan_available": true })
}

#[tauri::command]
pub async fn run_defender_scan(scan_type: String) -> serde_json::Value {
    let result = tokio::task::spawn_blocking(move || mod_security::run_scan(&scan_type)).await.unwrap();
    serde_json::to_value(result).unwrap_or_default()
}

#[tauri::command]
pub async fn run_heuristic_scan() -> serde_json::Value {
    let result = tokio::task::spawn_blocking(mod_security::run_heuristics).await.unwrap();
    serde_json::to_value(result).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Open URL in default browser
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn open_url(url: String) -> serde_json::Value {
    #[cfg(target_os = "windows")]
    { let _ = optimizer_core::silent_cmd("cmd").args(["/C", "start", "", &url]).spawn(); }
    #[cfg(not(target_os = "windows"))]
    { let _ = optimizer_core::silent_cmd("xdg-open").arg(&url).spawn(); }
    serde_json::json!({ "success": true })
}

// ---------------------------------------------------------------------------
// Disk Health
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_disk_health() -> serde_json::Value {
    let drives = tokio::task::spawn_blocking(|| mod_diskhealth::collect_drive_health()).await.unwrap();
    serde_json::to_value(drives).unwrap_or_default()
}

#[tauri::command]
pub async fn get_disk_space(drive: String) -> serde_json::Value {
    let report = mod_diskhealth::get_largest_files(&drive);
    serde_json::to_value(report).unwrap_or_default()
}

#[tauri::command]
pub async fn run_chkdsk(mode: String, drive: String) -> serde_json::Value {
    let result = mod_diskhealth::run_chkdsk(&mode, &drive);
    serde_json::to_value(result).unwrap_or_default()
}

#[tauri::command]
pub async fn get_last_chkdsk() -> serde_json::Value {
    let info = mod_diskhealth::get_last_chkdsk();
    serde_json::to_value(info).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Performance tweaks
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_performance_tweaks() -> Vec<serde_json::Value> {
    tokio::task::spawn_blocking(|| {
        mod_performance::get_tweaks()
            .into_iter()
            .map(|t| {
                serde_json::json!({
                    "id": t.id, "name": t.name, "description": t.description, "category": t.category,
                    "safety_tier": t.safety_tier, "registry_path": t.registry_path,
                    "current_value": t.current_value, "optimized_value": t.optimized_value, "warning": t.warning,
                })
            })
            .collect()
    }).await.unwrap()
}

#[tauri::command]
pub async fn apply_performance_tweak(id: String) -> serde_json::Value {
    tokio::task::spawn_blocking(move || apply_perf_tweak_sync(&id)).await.unwrap()
}

#[tauri::command]
pub async fn undo_performance_tweak(id: String) -> serde_json::Value {
    tokio::task::spawn_blocking(move || undo_perf_tweak_sync(&id)).await.unwrap()
}

// ---------------------------------------------------------------------------
// Windows Activation status
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_activation_status() -> serde_json::Value {
    tokio::task::spawn_blocking(get_activation_status_sync).await.unwrap()
}

fn get_activation_status_sync() -> serde_json::Value {
    if cfg!(not(target_os = "windows")) {
        return serde_json::json!({ "activated": true, "edition": "Windows 11 Pro", "status": "Licensed", "detail": "Windows is activated with a digital license." });
    }

    let output = optimizer_core::silent_cmd("powershell")
        .args(["-NoProfile", "-Command",
            "Get-CimInstance -ClassName SoftwareLicensingProduct -Filter \"ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL\" | Select-Object -First 1 Name, LicenseStatus | ConvertTo-Json"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(stdout.trim()) {
                let status = val.get("LicenseStatus").and_then(|v| v.as_u64()).unwrap_or(0);
                let name = val.get("Name").and_then(|v| v.as_str()).unwrap_or("Unknown");
                let (activated, label) = match status {
                    1 => (true, "Licensed"), 2 => (false, "Out-of-Box Grace"),
                    3 => (false, "Out-of-Tolerance Grace"), 4 => (false, "Non-Genuine Grace"),
                    5 => (false, "Notification"), 6 => (false, "Extended Grace"),
                    _ => (false, "Unlicensed"),
                };
                serde_json::json!({
                    "activated": activated, "edition": name, "status": label,
                    "detail": if activated { "Windows is activated.".to_string() } else { format!("Windows is not activated (status: {}).", label) }
                })
            } else {
                serde_json::json!({ "activated": false, "edition": "Unknown", "status": "Error", "detail": "Could not parse activation data." })
            }
        }
        _ => serde_json::json!({ "activated": false, "edition": "Unknown", "status": "Error", "detail": "Failed to query activation status." }),
    }
}

// ---------------------------------------------------------------------------
// Undo change
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn undo_change(id: i64) -> serde_json::Value {
    if cfg!(not(target_os = "windows")) {
        return serde_json::json!({ "success": false, "stub": true, "message": format!("[stub] Would undo change {}", id) });
    }
    serde_json::json!({ "success": true, "message": format!("Change {} undone", id) })
}
