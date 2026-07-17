use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

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

/// Graceful fallback when a `spawn_blocking` task panics: instead of `.unwrap()`
/// poisoning the invoke (which surfaces to the UI as an unhandled rejection with
/// no message), log it and return a structured error the panels already render.
fn join_fallback() -> serde_json::Value {
    serde_json::json!({
        "success": false,
        "message": "The operation failed unexpectedly (internal error). Please try again."
    })
}

// ---------------------------------------------------------------------------
// Visual effects
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_visual_tweaks() -> Vec<serde_json::Value> {
    tokio::task::spawn_blocking(|| {
        mod_visual::get_tweaks()
            .into_iter()
            .map(|t| {
                let applied = t.current_value.as_deref() == Some(t.optimized_value.as_str());
                serde_json::json!({
                    "id": t.id,
                    "name": t.name,
                    "description": t.description,
                    "category": t.category,
                    "safety_tier": t.safety_tier,
                    "current_value": t.current_value,
                    "optimized_value": t.optimized_value,
                    "applied": applied,
                    "can_undo": load_snapshot(&t.id).is_some(),
                })
            })
            .collect()
    })
    .await
    .unwrap_or_default()
}

#[tauri::command]
pub async fn apply_visual_tweak(id: String) -> serde_json::Value {
    tokio::task::spawn_blocking(move || apply_visual_tweak_sync(&id))
        .await
        .unwrap_or_else(|_| join_fallback())
}

#[tauri::command]
pub async fn undo_visual_tweak(id: String) -> serde_json::Value {
    tokio::task::spawn_blocking(move || undo_visual_tweak_sync(&id))
        .await
        .unwrap_or_else(|_| join_fallback())
}

// ---------------------------------------------------------------------------
// Health report
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_health_report() -> serde_json::Value {
    tokio::task::spawn_blocking(|| {
        let report = mod_health::quick_scan();
        serde_json::json!({
            "score": report.score,
            "complete": report.complete,
            "findings": report.findings,
        })
    })
    .await
    .unwrap_or_else(|_| join_fallback())
}

// ---------------------------------------------------------------------------
// Privacy scan
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_privacy_tweaks() -> serde_json::Value {
    tokio::task::spawn_blocking(|| {
        serde_json::to_value(mod_privacy::get_tweaks()).unwrap_or_default()
    })
    .await
    .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Services scan
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_services_tweaks() -> serde_json::Value {
    tokio::task::spawn_blocking(|| {
        serde_json::to_value(mod_services::get_tweaks()).unwrap_or_default()
    })
    .await
    .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Startup items
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_startup_items() -> serde_json::Value {
    tokio::task::spawn_blocking(|| {
        serde_json::to_value(mod_startup::list_items_v2().unwrap_or_default()).unwrap_or_default()
    })
    .await
    .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Cleanup targets
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_cleanup_targets() -> serde_json::Value {
    tokio::task::spawn_blocking(|| {
        serde_json::to_value(mod_cleanup::scan_targets()).unwrap_or_default()
    })
    .await
    .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Power plan
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_power_info() -> serde_json::Value {
    tokio::task::spawn_blocking(|| serde_json::to_value(mod_power::get_info()).unwrap_or_default())
        .await
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Event log summary
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_event_log_summary() -> serde_json::Value {
    tokio::task::spawn_blocking(|| {
        serde_json::to_value(mod_eventlog::get_summary()).unwrap_or_default()
    })
    .await
    .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// BSOD analyzer
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_bsod_dumps() -> serde_json::Value {
    tokio::task::spawn_blocking(|| {
        serde_json::to_value(mod_bsod::scan_dumps_report()).unwrap_or_default()
    })
    .await
    .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Network diagnostics
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_network_diagnostics() -> serde_json::Value {
    tokio::task::spawn_blocking(|| {
        serde_json::to_value(mod_netdiag::run_diagnostics()).unwrap_or_default()
    })
    .await
    .unwrap_or_default()
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
        _ => {
            return serde_json::json!({ "success": false, "message": format!("Unknown DNS preset: {}", preset) });
        }
    };

    if cfg!(not(target_os = "windows")) {
        return serde_json::json!({ "success": true, "stub": true, "message": format!("[stub] Would set DNS to {} ({}, {})", preset, primary, secondary) });
    }

    // Set-DnsClientServerAddress raises NON-terminating errors that don't set a
    // non-zero exit code, so trap them and emit an explicit OK/FAIL marker.
    let inner = if preset == "auto" {
        "Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses".to_string()
    } else {
        format!(
            "Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses @('{}','{}')",
            primary, secondary
        )
    };
    let verification = if preset == "auto" {
        "".to_string()
    } else {
        format!(
            "; $actual=@(Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop | Select-Object -ExpandProperty ServerAddresses); if (($actual -join ',') -ne '{},{}') {{ throw ('DNS verification failed: ' + ($actual -join ',')) }}",
            primary, secondary
        )
    };
    let script = format!(
        "$ErrorActionPreference='Stop'; try {{ $routes=@(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | Where-Object {{$_.NextHop -ne '0.0.0.0'}} | Sort-Object RouteMetric); if ($routes.Count -eq 0) {{ throw 'No active default route was found.' }}; $adapter=Get-NetAdapter -InterfaceIndex $routes[0].InterfaceIndex -ErrorAction Stop; if ($adapter.ifOperStatus -ne 'Up') {{ throw 'The default-route adapter is not up.' }}; $adapter | ForEach-Object {{ {} }}{}; Write-Output 'OK' }} catch {{ Write-Output ('FAIL|' + $_.Exception.Message) }}",
        inner, verification
    );

    let output =
        match tokio::task::spawn_blocking(move || optimizer_core::powershell(&script).output())
            .await
        {
            Ok(output) => output,
            Err(_) => return join_fallback(),
        };

    match output {
        Ok(o) => {
            let out = String::from_utf8_lossy(&o.stdout);
            let last = out
                .lines()
                .map(str::trim)
                .rfind(|l| !l.is_empty())
                .unwrap_or("");
            if last == "OK" {
                let label = if preset == "auto" {
                    "Automatic (DHCP)".to_string()
                } else {
                    format!("{} ({}, {})", preset, primary, secondary)
                };
                serde_json::json!({ "success": true, "message": format!("DNS set to {}", label) })
            } else if let Some(m) = last.strip_prefix("FAIL|") {
                serde_json::json!({ "success": false, "message": m.to_string() })
            } else {
                serde_json::json!({ "success": false, "message": String::from_utf8_lossy(&o.stderr).trim().to_string() })
            }
        }
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
        _ => {
            return serde_json::json!({ "success": false, "message": format!("Unknown command: {}", command) });
        }
    };

    if cfg!(not(target_os = "windows")) {
        return serde_json::json!({ "success": true, "stub": true, "message": format!("[stub] Would run: {} {}", cmd, args.join(" ")), "output": format!("{} completed (stub).", label) });
    }

    let output =
        tokio::task::spawn_blocking(move || optimizer_core::silent_cmd(cmd).args(&args).output())
            .await;
    let output = match output {
        Ok(output) => output,
        Err(_) => return join_fallback(),
    };

    match output {
        Ok(o) => {
            let stdout = optimizer_core::decode_console_output(&o.stdout);
            let stderr = optimizer_core::decode_console_output(&o.stderr);
            let text = if stderr.is_empty() {
                stdout
            } else {
                format!("{}\n{}", stdout, stderr)
            };
            let needs_reboot = command == "reset_winsock" || command == "reset_tcp";
            let msg = if !o.status.success() {
                format!("{} failed.", label)
            } else if needs_reboot {
                format!(
                    "{} completed. A restart is required for changes to take effect.",
                    label
                )
            } else {
                format!("{} completed.", label)
            };
            serde_json::json!({ "success": o.status.success(), "message": msg, "output": text.trim() })
        }
        Err(e) => {
            serde_json::json!({ "success": false, "message": format!("Failed to run {}: {}", label, e) })
        }
    }
}

// ---------------------------------------------------------------------------
// Windows Update status
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_update_status() -> serde_json::Value {
    tokio::task::spawn_blocking(|| {
        serde_json::to_value(mod_updates::get_status()).unwrap_or_default()
    })
    .await
    .unwrap_or_default()
}

#[tauri::command]
pub async fn reset_windows_update() -> serde_json::Value {
    if cfg!(not(target_os = "windows")) {
        return serde_json::json!({ "success": true, "stub": true, "message": "[stub] Would reset Windows Update components." });
    }

    let script = r#"
$ErrorActionPreference = 'Stop'
$log = @(); $stopped = @()
$services = @('wuauserv','bits','cryptSvc','msiserver')
try {
  foreach ($s in $services) { Stop-Service -Name $s -Force -ErrorAction Stop; $stopped += $s; $log += "Stopped $s" }
  $sd = Join-Path $env:SystemRoot 'SoftwareDistribution'
  $cr = Join-Path $env:SystemRoot 'System32\catroot2'
  $stamp = Get-Date -Format yyyyMMddHHmmss
  if (Test-Path -LiteralPath $sd) { Rename-Item -LiteralPath $sd -NewName "SoftwareDistribution.bak.$stamp" -ErrorAction Stop; $log += 'Renamed SoftwareDistribution' }
  if (Test-Path -LiteralPath $cr) { Rename-Item -LiteralPath $cr -NewName "catroot2.bak.$stamp" -ErrorAction Stop; $log += 'Renamed catroot2' }
} finally {
  foreach ($s in $stopped) { Start-Service -Name $s -ErrorAction Continue; if ((Get-Service -Name $s).Status -ne 'Running') { throw "Failed to restart $s" }; $log += "Started $s" }
}
$log -join "`n"
"#;

    let output = match tokio::task::spawn_blocking(move || {
        optimizer_core::powershell(script).output()
    })
    .await
    {
        Ok(output) => output,
        Err(_) => return join_fallback(),
    };

    match output {
        Ok(o) => {
            let text = String::from_utf8_lossy(&o.stdout).trim().to_string();
            serde_json::json!({
                "success": o.status.success(),
                "message": if o.status.success() { "Windows Update components reset successfully. A restart is recommended." } else { "Reset completed with some errors." },
                "output": text
            })
        }
        Err(e) => {
            serde_json::json!({ "success": false, "message": format!("Failed: {}", e), "output": "" })
        }
    }
}

#[tauri::command]
pub async fn trigger_update_check() -> serde_json::Value {
    if cfg!(not(target_os = "windows")) {
        return serde_json::json!({ "success": true, "stub": true, "message": "[stub] Would open Windows Update settings." });
    }

    open_url("ms-settings:windowsupdate-action".into())
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn generate_report() -> serde_json::Value {
    tokio::task::spawn_blocking(|| {
        let health = mod_health::quick_scan();
        let report_html = mod_report::generate_html_report(
            "System Diagnostic Report",
            &[
                (
                    "System Health",
                    &health
                        .score
                        .map(|score| format!("Score: {score}/100"))
                        .unwrap_or_else(|| "Score: Unknown (incomplete scan)".into()),
                ),
                (
                    "Findings",
                    &health
                        .findings
                        .iter()
                        .map(|f| format!("{}: {}", f.title, f.detail))
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        );
        serde_json::json!({ "html": report_html, "success": true })
    })
    .await
    .unwrap_or_else(|_| join_fallback())
}

// ---------------------------------------------------------------------------
// Export full report
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn export_report() -> serde_json::Value {
    tokio::task::spawn_blocking(export_report_sync)
        .await
        .unwrap_or_else(|_| join_fallback())
}

fn export_report_sync() -> serde_json::Value {
    let health = {
        let r = mod_health::quick_scan();
        serde_json::json!({"score": r.score, "findings": r.findings})
    };
    let drivers = serde_json::to_value(mod_drivers::audit_drivers()).unwrap_or_default();
    let events = serde_json::to_value(mod_eventlog::get_summary()).unwrap_or_default();
    let updates = serde_json::to_value(mod_updates::get_status()).unwrap_or_default();
    let temps = serde_json::to_value(mod_temps::collect_temps()).unwrap_or_default();
    let disk = serde_json::to_value(mod_diskhealth::collect_drive_health()).unwrap_or_default();
    let runtimes = serde_json::to_value(mod_runtimes::collect_runtimes()).unwrap_or_default();
    let security = serde_json::to_value(mod_security::get_defender_status()).unwrap_or_default();
    let activation = get_activation_status_sync();

    let data = mod_report::FullReportData {
        health_score: health.get("score").and_then(|v| v.as_u64()),
        health_findings: health
            .get("findings")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .map(|f| {
                        let sev = f.get("severity").and_then(|s| s.as_str()).unwrap_or("Info");
                        let title = f.get("title").and_then(|s| s.as_str()).unwrap_or("");
                        let detail = f.get("detail").and_then(|s| s.as_str()).unwrap_or("");
                        format!("[{}] {} - {}", sev, title, detail)
                    })
                    .collect()
            })
            .unwrap_or_default(),
        driver_total: drivers.get("total").and_then(|v| v.as_u64()).unwrap_or(0),
        driver_unsigned: drivers
            .get("unsigned")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        driver_outdated: drivers.get("outdated").and_then(|v| v.as_u64()),
        driver_issues: drivers
            .get("problematic")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .map(|d| {
                        let name = d.get("name").and_then(|s| s.as_str()).unwrap_or("");
                        let status = d.get("status").and_then(|s| s.as_str()).unwrap_or("");
                        let ver = d.get("version").and_then(|s| s.as_str()).unwrap_or("");
                        format!("[{}] {} (v{})", status.to_uppercase(), name, ver)
                    })
                    .collect()
            })
            .unwrap_or_default(),
        event_critical: events
            .pointer("/system/critical")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        event_error: events
            .pointer("/system/error")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        event_warning: events
            .pointer("/system/warning")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        recent_events: events
            .pointer("/system/recent_events")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .take(10)
                    .map(|e| {
                        let level = e.get("level").and_then(|s| s.as_str()).unwrap_or("");
                        let source = e.get("source").and_then(|s| s.as_str()).unwrap_or("");
                        let msg = e.get("message").and_then(|s| s.as_str()).unwrap_or("");
                        format!("[{}] {} - {}", level, source, msg)
                    })
                    .collect()
            })
            .unwrap_or_default(),
        update_service: updates
            .get("service_status")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown")
            .to_string(),
        update_complete: updates
            .get("complete")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        pending_updates: updates
            .get("pending_updates")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .map(|u| {
                        let title = u.get("title").and_then(|s| s.as_str()).unwrap_or("");
                        let sev = u.get("severity").and_then(|s| s.as_str()).unwrap_or("");
                        format!("[{}] {}", sev, title)
                    })
                    .collect()
            })
            .unwrap_or_default(),
        temperatures: temps
            .get("readings")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|t| {
                        let sensor = t.get("sensor").and_then(|s| s.as_str()).unwrap_or("");
                        let temp = t.get("temperature_c").and_then(|v| v.as_f64())?;
                        Some(format!("{}: {:.1}C", sensor, temp))
                    })
                    .collect()
            })
            .unwrap_or_default(),
        disk_health: disk
            .get("drives")
            .and_then(|value| value.as_array())
            .map(|a| {
                a.iter()
                    .map(|d| {
                        let model = d.get("model").and_then(|s| s.as_str()).unwrap_or("");
                        let rating = d
                            .get("health_rating")
                            .and_then(|s| s.as_str())
                            .unwrap_or("");
                        let temp = d.get("temperature_c").and_then(|v| v.as_i64());
                        let wear = d.get("wear_percent").and_then(|v| v.as_f64());
                        let mut line = format!("[{}] {}", rating, model);
                        if let Some(t) = temp {
                            line.push_str(&format!(" | Temp: {}C", t));
                        }
                        if let Some(w) = wear {
                            line.push_str(&format!(" | Wear: {}%", w));
                        }
                        line
                    })
                    .collect()
            })
            .unwrap_or_default(),
        runtimes: {
            let mut lines = Vec::new();
            if let Some(dotnet) = runtimes.get("dotnet").and_then(|v| v.as_array()) {
                for r in dotnet {
                    let name = r.get("name").and_then(|s| s.as_str()).unwrap_or("");
                    let installed = r
                        .get("installed")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    lines.push(format!(
                        "[{}] {}",
                        if installed { "OK" } else { "--" },
                        name
                    ));
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
            if defender
                .and_then(|d| d.get("known"))
                .and_then(|v| v.as_bool())
                != Some(true)
            {
                "Defender status: Unknown (query failed)".to_string()
            } else {
                let rtp = defender
                    .and_then(|d| d.get("real_time_enabled"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let defs = defender
                    .and_then(|d| d.get("definitions_age_days"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                format!(
                    "Real-time Protection: {}  |  Definition age: {} days",
                    if rtp { "ON" } else { "OFF" },
                    defs
                )
            }
        },
        activation: {
            let status = activation
                .get("status")
                .and_then(|s| s.as_str())
                .unwrap_or("Unknown");
            let edition = activation
                .get("edition")
                .and_then(|s| s.as_str())
                .unwrap_or("Unknown");
            format!("{} - {}", edition, status)
        },
    };

    let html = mod_report::generate_full_report(&data);

    let report_dir = directories::UserDirs::new()
        .and_then(|u| u.document_dir().map(|d| d.join("Cove Windows Toolkit")))
        .unwrap_or_else(|| std::path::PathBuf::from("reports"));
    if let Err(error) = std::fs::create_dir_all(&report_dir) {
        return serde_json::json!({ "success": false, "message": format!("Could not create report folder: {error}") });
    }
    let filename = format!(
        "report-{}.html",
        chrono::Local::now().format("%Y%m%d-%H%M%S")
    );
    let filepath = report_dir.join(&filename);
    if let Err(error) = std::fs::write(&filepath, &html) {
        return serde_json::json!({ "success": false, "message": format!("Could not write report: {error}") });
    }

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
    tokio::task::spawn_blocking(|| {
        serde_json::to_value(mod_netdiag::run_speed_test()).unwrap_or_default()
    })
    .await
    .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Generic apply / undo for any module
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn apply_tweak(module: String, id: String) -> serde_json::Value {
    tokio::task::spawn_blocking(move || apply_tweak_sync(&module, &id))
        .await
        .unwrap_or_else(|_| join_fallback())
}

#[tauri::command]
pub async fn undo_tweak(module: String, id: String) -> serde_json::Value {
    tokio::task::spawn_blocking(move || undo_tweak_sync(&module, &id))
        .await
        .unwrap_or_else(|_| join_fallback())
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
                    // Service-based privacy tweaks can't be auto-reverted (no prior
                    // start-type snapshot), so log them but don't promise an undo.
                    let svc = t.path.trim_start_matches("Service: ").trim();
                    match mod_services::apply_change(svc, &t.optimized) {
                        Ok(msg) => change_with_history(msg, "services", Some(id), &t.name, &t.tier),
                        Err(msg) => serde_json::json!({ "success": false, "message": msg }),
                    }
                } else {
                    // Snapshot the pre-apply value (None => value was absent) so the
                    // change can be reverted from history later.
                    let current = if t.current == "NotSet" {
                        None
                    } else {
                        Some(t.current.as_str())
                    };
                    if let Err(message) = save_snapshot(id, current) {
                        return serde_json::json!({ "success": false, "message": format!("Could not save rollback data: {message}") });
                    }
                    let result = apply_registry_tweak(&t.path, &t.value_name, &t.optimized);
                    if result
                        .get("success")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        return change_with_history(
                            result
                                .get("message")
                                .and_then(|v| v.as_str())
                                .unwrap_or("Applied")
                                .to_string(),
                            "privacy",
                            Some(id),
                            &t.name,
                            &t.tier,
                        );
                    }
                    result
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
                    Ok(msg) => change_with_history(msg, "services", Some(id), &t.name, &t.tier),
                    Err(msg) => serde_json::json!({ "success": false, "message": msg }),
                }
            } else {
                serde_json::json!({ "success": false, "message": format!("Unknown service tweak: {}", id) })
            }
        }
        _ => {
            serde_json::json!({ "success": false, "message": format!("Unknown tweak module: {}", module) })
        }
    }
}

/// Revert a registry-based privacy tweak using its pre-apply snapshot.
/// Service-based privacy tweaks have no prior-state snapshot and can't be auto-reverted.
fn undo_privacy_tweak_sync(id: &str) -> serde_json::Value {
    let tweaks = mod_privacy::get_tweaks();
    let all: Vec<_> = [tweaks.basic, tweaks.standard, tweaks.advanced].concat();
    let Some(t) = all.iter().find(|t| t.id == id) else {
        return serde_json::json!({ "success": false, "message": format!("Unknown privacy tweak: {}", id) });
    };
    if t.path.starts_with("Service:") {
        return serde_json::json!({
            "success": false,
            "message": "Service changes can't be reverted automatically; re-enable the service from the Services panel."
        });
    }
    let result = match load_snapshot(id) {
        Some(Some(v)) => apply_registry_tweak(&t.path, &t.value_name, &v),
        Some(None) => match delete_registry_value(&t.path, &t.value_name) {
            Ok(msg) => serde_json::json!({ "success": true, "message": msg }),
            Err(msg) => serde_json::json!({ "success": false, "message": msg }),
        },
        None => {
            serde_json::json!({ "success": false, "message": "No saved original value to restore." })
        }
    };
    if result
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        && let Err(message) = delete_snapshot(id)
    {
        return serde_json::json!({ "success": false, "message": format!("Restored the setting but could not consume rollback data: {message}") });
    }
    result
}

fn undo_tweak_sync(module: &str, id: &str) -> serde_json::Value {
    match module {
        "visual" => undo_visual_tweak_sync(id),
        "performance" => undo_perf_tweak_sync(id),
        "privacy" => undo_privacy_tweak_sync(id),
        // Don't claim success for modules whose undo isn't implemented (e.g. services).
        _ => serde_json::json!({
            "success": false,
            "message": format!("Undo is not supported for '{}' changes.", module)
        }),
    }
}

fn apply_visual_tweak_sync(id: &str) -> serde_json::Value {
    let tweaks = mod_visual::get_tweaks();
    if let Some(t) = tweaks.iter().find(|t| t.id == id) {
        // Snapshot the original value before changing it, so undo can restore it.
        if let Err(message) = save_snapshot(id, t.current_value.as_deref()) {
            return serde_json::json!({ "success": false, "message": format!("Could not save rollback data: {message}") });
        }
        match mod_visual::apply_tweak(&t.registry_path, &t.registry_name, &t.optimized_value) {
            Ok(msg) => change_with_history(
                msg,
                "visual",
                Some(id),
                &t.name,
                &format!("{:?}", t.safety_tier),
            ),
            Err(msg) => serde_json::json!({ "success": false, "message": msg }),
        }
    } else {
        serde_json::json!({ "success": false, "message": format!("Unknown tweak: {}", id) })
    }
}

fn undo_visual_tweak_sync(id: &str) -> serde_json::Value {
    let tweaks = mod_visual::get_tweaks();
    if let Some(t) = tweaks.iter().find(|t| t.id == id) {
        let result = match load_snapshot(id) {
            Some(Some(v)) => mod_visual::apply_tweak(&t.registry_path, &t.registry_name, &v),
            Some(None) => delete_registry_value(&t.registry_path, &t.registry_name),
            None => Err("No saved original value to restore.".into()),
        };
        match result {
            Ok(msg) => {
                if let Err(message) = delete_snapshot(id) {
                    return serde_json::json!({ "success": false, "message": format!("Restored the setting but could not consume rollback data: {message}") });
                }
                serde_json::json!({ "success": true, "message": msg })
            }
            Err(msg) => serde_json::json!({ "success": false, "message": msg }),
        }
    } else {
        serde_json::json!({ "success": false, "message": format!("Unknown tweak: {}", id) })
    }
}

fn apply_perf_tweak_sync(id: &str) -> serde_json::Value {
    let tweaks = mod_performance::get_tweaks();
    if let Some(t) = tweaks.iter().find(|t| t.id == id) {
        if let Err(message) = save_snapshot(id, t.current_value.as_deref()) {
            return serde_json::json!({ "success": false, "message": format!("Could not save rollback data: {message}") });
        }
        match mod_performance::apply_tweak(&t.registry_path, &t.registry_name, &t.optimized_value) {
            Ok(msg) => change_with_history(
                msg,
                "performance",
                Some(id),
                &t.name,
                &format!("{:?}", t.safety_tier),
            ),
            Err(msg) => serde_json::json!({ "success": false, "message": msg }),
        }
    } else {
        serde_json::json!({ "success": false, "message": format!("Unknown tweak: {}", id) })
    }
}

fn undo_perf_tweak_sync(id: &str) -> serde_json::Value {
    let tweaks = mod_performance::get_tweaks();
    if let Some(t) = tweaks.iter().find(|t| t.id == id) {
        let result = match load_snapshot(id) {
            Some(Some(v)) => mod_performance::apply_tweak(&t.registry_path, &t.registry_name, &v),
            Some(None) => delete_registry_value(&t.registry_path, &t.registry_name),
            None => Err("No saved original value to restore.".into()),
        };
        match result {
            Ok(msg) => {
                if let Err(message) = delete_snapshot(id) {
                    return serde_json::json!({ "success": false, "message": format!("Restored the setting but could not consume rollback data: {message}") });
                }
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
        // Infer the registry type from the value: a plain unsigned integer is
        // written as REG_DWORD (unquoted), anything else as REG_SZ (quoted +
        // single-quote-escaped). Hardcoding DWord corrupts string-valued tweaks.
        // Only treat the value as a DWORD when it parses as a u32 (the actual
        // REG_DWORD range). An all-digits string that overflows u32 would fail
        // `Set-ItemProperty -Type DWord`, so fall back to REG_SZ for those.
        let (ty, val) = if value.parse::<u32>().is_ok() {
            ("DWord", value.to_string())
        } else {
            ("String", format!("'{}'", value.replace('\'', "''")))
        };
        let ps = format!(
            "try {{ New-Item -Path 'Registry::{}' -Force -ErrorAction SilentlyContinue | Out-Null; Set-ItemProperty -Path 'Registry::{}' -Name '{}' -Value {} -Type {} -Force -ErrorAction Stop; Write-Output 'OK' }} catch {{ Write-Output $_.Exception.Message }}",
            path, path, name, val, ty
        );
        match optimizer_core::powershell(&ps).output() {
            Ok(o) => {
                let result = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if result == "OK" {
                    return serde_json::json!({ "success": true, "message": format!("Applied: {} = {}", name, value) });
                }
                serde_json::json!({ "success": false, "message": result })
            }
            Err(e) => {
                serde_json::json!({ "success": false, "message": format!("Failed to start PowerShell: {e}") })
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    serde_json::json!({ "success": true, "message": format!("Applied: {} = {}", name, value) })
}

// ---------------------------------------------------------------------------
// Change history (file-backed)
// ---------------------------------------------------------------------------

// Serializes read-modify-write of the file-backed history/snapshot stores so
// concurrent apply/undo tasks (run on spawn_blocking worker threads) can't
// clobber each other's writes.
static DATA_FILE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn history_path() -> std::path::PathBuf {
    if crate::portable::is_portable() {
        crate::portable::portable_data_dir("cove-windows-optimizer").join("change_history.json")
    } else {
        directories::ProjectDirs::from("com", "cove", "optimizer")
            .map(|dirs| dirs.data_local_dir().join("change_history.json"))
            .unwrap_or_else(|| std::path::PathBuf::from("change_history.json"))
    }
}

#[tauri::command]
pub fn get_change_history() -> serde_json::Value {
    let path = history_path();
    if path.exists()
        && let Ok(data) = std::fs::read_to_string(&path)
        && let Ok(val) = serde_json::from_str::<serde_json::Value>(&data)
    {
        return val;
    }
    serde_json::json!([])
}

fn append_history(
    module: &str,
    action_id: Option<&str>,
    name: &str,
    tier: &str,
    status: &str,
) -> Result<(), String> {
    let _guard = DATA_FILE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = history_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Could not create history directory: {e}"))?;
    }
    let mut entries: Vec<serde_json::Value> = if path.exists() {
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|d| serde_json::from_str(&d).ok())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    // Derive the next id from the current maximum rather than the entry count,
    // so ids stay unique even if entries are ever pruned/filtered.
    let id = entries
        .iter()
        .filter_map(|e| e.get("id").and_then(|v| v.as_i64()))
        .max()
        .unwrap_or(0)
        + 1;
    entries.push(serde_json::json!({
        "id": id,
        "timestamp": chrono::Local::now().to_rfc3339(),
        "module": module,
        "action_id": action_id,
        "name": name,
        "tier": tier,
        "status": status,
        "can_undo": status == "committed" && matches!(module, "visual" | "performance" | "privacy"),
    }));
    write_json_atomic(&path, &entries).map_err(|e| format!("Could not save change history: {e}"))
}

fn change_with_history(
    message: String,
    module: &str,
    action_id: Option<&str>,
    name: &str,
    tier: &str,
) -> serde_json::Value {
    match append_history(module, action_id, name, tier, "committed") {
        Ok(()) => serde_json::json!({ "success": true, "history_saved": true, "message": message }),
        Err(error) => serde_json::json!({
            "success": true,
            "history_saved": false,
            "message": format!("{message} Warning: {error}; this change will not appear in History."),
        }),
    }
}

// ---------------------------------------------------------------------------
// Pre-apply value snapshots (so undo restores the original, not the new value)
// ---------------------------------------------------------------------------

fn tweak_snapshot_path() -> std::path::PathBuf {
    if crate::portable::is_portable() {
        crate::portable::portable_data_dir("cove-windows-optimizer").join("tweak_snapshots.json")
    } else {
        directories::ProjectDirs::from("com", "cove", "optimizer")
            .map(|dirs| dirs.data_local_dir().join("tweak_snapshots.json"))
            .unwrap_or_else(|| std::path::PathBuf::from("tweak_snapshots.json"))
    }
}

/// Record the value a tweak had BEFORE it was applied. `None` means the registry
/// value did not exist (so undo should delete it rather than write a default).
fn save_snapshot(id: &str, value: Option<&str>) -> Result<(), String> {
    let _guard = DATA_FILE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = tweak_snapshot_path();
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    let mut map: serde_json::Map<String, serde_json::Value> = std::fs::read_to_string(&path)
        .ok()
        .and_then(|d| serde_json::from_str(&d).ok())
        .unwrap_or_default();
    // Each apply records the immediately preceding value for that operation.
    map.insert(
        id.to_string(),
        match value {
            Some(v) => serde_json::Value::String(v.to_string()),
            None => serde_json::Value::Null,
        },
    );
    write_json_atomic(&path, &map).map_err(|e| e.to_string())
}

/// Returns `Some(Some(v))` if a value was saved, `Some(None)` if the value was
/// absent before apply, or `None` if no snapshot exists.
fn load_snapshot(id: &str) -> Option<Option<String>> {
    let _guard = DATA_FILE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = tweak_snapshot_path();
    let map: serde_json::Map<String, serde_json::Value> = std::fs::read_to_string(&path)
        .ok()
        .and_then(|d| serde_json::from_str(&d).ok())?;
    map.get(id).map(|v| {
        if v.is_null() {
            None
        } else {
            v.as_str().map(|s| s.to_string())
        }
    })
}

#[cfg(target_os = "windows")]
fn delete_registry_value(path: &str, name: &str) -> Result<String, String> {
    let ps = format!(
        "try {{ Remove-ItemProperty -Path 'Registry::{}' -Name '{}' -Force -ErrorAction Stop; Write-Output 'OK' }} catch {{ if ($_.Exception.Message -match 'does not exist|cannot find|was not found') {{ Write-Output 'OK' }} else {{ Write-Output $_.Exception.Message }} }}",
        path, name
    );
    let o = optimizer_core::powershell(&ps)
        .output()
        .map_err(|e| e.to_string())?;
    let r = String::from_utf8_lossy(&o.stdout).trim().to_string();
    if r == "OK" {
        Ok(format!("Removed {}", name))
    } else {
        Err(r)
    }
}

#[cfg(not(target_os = "windows"))]
fn delete_registry_value(_path: &str, _name: &str) -> Result<String, String> {
    Ok("[stub] removed".into())
}

// ---------------------------------------------------------------------------
// Startup toggle
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn toggle_startup(id: String, enabled: bool) -> serde_json::Value {
    tokio::task::spawn_blocking(move || {
        let item_name = mod_startup::list_items_v2()
            .ok()
            .and_then(|items| items.into_iter().find(|item| item.id == id))
            .map(|item| item.name)
            .unwrap_or_else(|| id.clone());
        match mod_startup::toggle_by_id(&id, enabled) {
            Ok(msg) => change_with_history(msg, "startup", Some(&id), &item_name, "green"),
            Err(msg) => serde_json::json!({ "success": false, "message": msg }),
        }
    })
    .await
    .unwrap_or_else(|_| join_fallback())
}

// ---------------------------------------------------------------------------
// Service change
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn apply_service_change(id: String) -> serde_json::Value {
    tokio::task::spawn_blocking(move || {
        let tweaks = mod_services::get_tweaks();
        let all: Vec<_> = [tweaks.conservative, tweaks.advanced].concat();
        if let Some(t) = all.iter().find(|t| t.id == id) {
            match mod_services::apply_change(&t.service, &t.optimized) {
                Ok(msg) => change_with_history(msg, "services", Some(&id), &t.name, &t.tier),
                Err(msg) => serde_json::json!({ "success": false, "message": msg }),
            }
        } else {
            serde_json::json!({ "success": false, "message": format!("Unknown service: {}", id) })
        }
    })
    .await
    .unwrap_or_else(|_| join_fallback())
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn run_cleanup(ids: Vec<String>) -> serde_json::Value {
    tokio::task::spawn_blocking(move || {
        let total = ids.len();
        let results = mod_cleanup::clean_targets(&ids);
        let succeeded = results.iter().filter(|(_, ok, _)| *ok).count();
        let items: Vec<serde_json::Value> = results.into_iter().map(|(id, ok, mut msg)| {
            if ok && let Err(error) = append_history("cleanup", Some(&id), &id, "green", "committed") { msg.push_str(&format!(" Warning: {error}")); }
            serde_json::json!({ "id": id, "success": ok, "message": msg })
        }).collect();
        serde_json::json!({ "success": succeeded == total && total > 0, "message": format!("Cleaned {} of {} targets", succeeded, total), "cleaned": succeeded, "results": items })
    }).await.unwrap_or_else(|_| join_fallback())
}

// ---------------------------------------------------------------------------
// Power plan
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn set_power_plan(guid: String) -> serde_json::Value {
    tokio::task::spawn_blocking(move || match mod_power::set_plan(&guid) {
        Ok(msg) => change_with_history(msg.clone(), "power", Some(&guid), &msg, "green"),
        Err(msg) => serde_json::json!({ "success": false, "message": msg }),
    })
    .await
    .unwrap_or_else(|_| join_fallback())
}

#[tauri::command]
pub async fn set_power_timeout(setting: String, minutes: u32) -> serde_json::Value {
    if cfg!(not(target_os = "windows")) {
        return serde_json::json!({ "success": true, "stub": true, "message": format!("[stub] Would set {} to {} min", setting, minutes) });
    }

    let ac_setting = match setting.as_str() {
        "display" => "monitor-timeout-ac",
        "sleep" => "standby-timeout-ac",
        "disk" => "disk-timeout-ac",
        _ => {
            return serde_json::json!({ "success": false, "message": format!("Unknown setting: {}", setting) });
        }
    };
    let minutes = minutes.to_string();
    let dc_setting = match setting.as_str() {
        "display" => "monitor-timeout-dc",
        "sleep" => "standby-timeout-dc",
        "disk" => "disk-timeout-dc",
        _ => "",
    };
    let work_minutes = minutes.clone();
    let (ac, dc) = match tokio::task::spawn_blocking(move || {
        let ac = optimizer_core::silent_cmd("powercfg")
            .args(["/change", ac_setting, &work_minutes])
            .output();
        let dc = optimizer_core::silent_cmd("powercfg")
            .args(["/change", dc_setting, &work_minutes])
            .output();
        (ac, dc)
    })
    .await
    {
        Ok(outputs) => outputs,
        Err(_) => return join_fallback(),
    };
    match (ac, dc) {
        (Ok(ac), Ok(dc)) if ac.status.success() && dc.status.success() => {
            serde_json::json!({ "success": true, "message": format!("{} AC and battery timeout set to {} minutes", setting, minutes) })
        }
        (ac, dc) => {
            let detail = [ac, dc]
                .into_iter()
                .map(|result| match result {
                    Ok(output) => optimizer_core::decode_console_output(&output.stderr)
                        .trim()
                        .to_string(),
                    Err(error) => error.to_string(),
                })
                .filter(|message| !message.is_empty())
                .collect::<Vec<_>>()
                .join("; ");
            serde_json::json!({ "success": false, "message": format!("Could not update both AC and battery timeouts: {detail}") })
        }
    }
}

// ---------------------------------------------------------------------------
// System Restore
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_restore_status() -> serde_json::Value {
    tokio::task::spawn_blocking(|| {
        let status = mod_restore::get_restore_status();
        serde_json::json!({ "known": status.known, "enabled": status.enabled, "message": status.message })
    }).await.unwrap_or_else(|_| join_fallback())
}

#[tauri::command]
pub async fn get_restore_points() -> serde_json::Value {
    tokio::task::spawn_blocking(|| serde_json::json!(mod_restore::list_restore_points_report()))
        .await
        .unwrap_or_else(|_| join_fallback())
}

#[tauri::command]
pub async fn create_restore_point(description: String) -> serde_json::Value {
    tokio::task::spawn_blocking(
        move || match mod_restore::create_restore_point(&description) {
            Ok(msg) => serde_json::json!({ "success": true, "message": msg }),
            Err(msg) => serde_json::json!({ "success": false, "message": msg }),
        },
    )
    .await
    .unwrap_or_else(|_| join_fallback())
}

#[tauri::command]
pub async fn enable_system_protection() -> serde_json::Value {
    tokio::task::spawn_blocking(|| match mod_restore::enable_system_protection() {
        Ok(msg) => serde_json::json!({ "success": true, "message": msg }),
        Err(msg) => serde_json::json!({ "success": false, "message": msg }),
    })
    .await
    .unwrap_or_else(|_| join_fallback())
}

#[tauri::command]
pub async fn launch_system_restore() -> serde_json::Value {
    tokio::task::spawn_blocking(|| match mod_restore::launch_system_restore() {
        Ok(msg) => serde_json::json!({ "success": true, "message": msg }),
        Err(msg) => serde_json::json!({ "success": false, "message": msg }),
    })
    .await
    .unwrap_or_else(|_| join_fallback())
}

// ---------------------------------------------------------------------------
// Bloatware remover
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_bloatware() -> serde_json::Value {
    tokio::task::spawn_blocking(|| {
        serde_json::to_value(mod_bloatware::scan_installed()).unwrap_or_default()
    })
    .await
    .unwrap_or_default()
}

#[tauri::command]
pub async fn remove_bloatware(packages: Vec<String>) -> serde_json::Value {
    tokio::task::spawn_blocking(move || {
        serde_json::to_value(mod_bloatware::remove_apps(&packages)).unwrap_or_default()
    })
    .await
    .unwrap_or_else(|_| join_fallback())
}

// ---------------------------------------------------------------------------
// Uninstaller
// ---------------------------------------------------------------------------

fn program_cache() -> &'static Mutex<HashMap<String, mod_uninstall::InstalledProgram>> {
    static CACHE: OnceLock<Mutex<HashMap<String, mod_uninstall::InstalledProgram>>> =
        OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn delete_snapshot(id: &str) -> Result<(), String> {
    let _guard = DATA_FILE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = tweak_snapshot_path();
    let mut map: serde_json::Map<String, serde_json::Value> = std::fs::read_to_string(&path)
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
        .unwrap_or_default();
    map.remove(id);
    write_json_atomic(&path, &map).map_err(|e| e.to_string())
}

fn write_json_atomic<T: serde::Serialize>(
    path: &std::path::Path,
    value: &T,
) -> std::io::Result<()> {
    use std::io::Write;
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    std::fs::create_dir_all(parent)?;
    let temp = parent.join(format!(".cove-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        serde_json::to_writer_pretty(&mut file, value).map_err(std::io::Error::other)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::Storage::FileSystem::{
                MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
            };
            let from: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
            let to: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            if unsafe {
                MoveFileExW(
                    from.as_ptr(),
                    to.as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
        #[cfg(not(target_os = "windows"))]
        std::fs::rename(&temp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

fn leftover_cache() -> &'static Mutex<HashMap<String, Vec<mod_uninstall::Leftover>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Vec<mod_uninstall::Leftover>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

#[tauri::command]
pub async fn get_installed_programs() -> serde_json::Value {
    tokio::task::spawn_blocking(|| {
        let programs = mod_uninstall::list_programs();
        if let Ok(mut cache) = program_cache().lock() {
            cache.clear();
            cache.extend(programs.iter().cloned().map(|p| (p.id.clone(), p)));
        }
        serde_json::to_value(programs).unwrap_or_default()
    })
    .await
    .unwrap_or_default()
}

#[tauri::command]
pub async fn uninstall_program(program_id: String) -> serde_json::Value {
    tokio::task::spawn_blocking(move || {
        let program = program_cache().lock().ok().and_then(|cache| cache.get(&program_id).cloned());
        let Some(program) = program else {
            return serde_json::json!({ "success": false, "message": "Program selection expired. Refresh the installed-program list." });
        };
        serde_json::to_value(mod_uninstall::run_uninstall(
            &program.uninstall_string,
            &program.quiet_uninstall_string,
        ))
        .unwrap_or_default()
    })
    .await
    .unwrap_or_else(|_| join_fallback())
}

#[tauri::command]
pub async fn scan_leftovers(program_id: String) -> serde_json::Value {
    tokio::task::spawn_blocking(move || {
        let program = program_cache().lock().ok().and_then(|cache| cache.get(&program_id).cloned());
        let Some(program) = program else {
            return serde_json::json!({ "success": false, "message": "Program selection expired. Refresh the installed-program list." });
        };
        let result = mod_uninstall::scan_leftovers(&program.name, &program.publisher, "", "");
        let scan_id = format!("scan-{}", uuid::Uuid::new_v4());
        if let Ok(mut cache) = leftover_cache().lock() {
            cache.insert(scan_id.clone(), result.leftovers.clone());
        }
        serde_json::json!({
            "success": true,
            "scan_id": scan_id,
            "leftovers": result.leftovers,
            "total_size_bytes": result.total_size_bytes,
        })
    })
    .await
    .unwrap_or_else(|_| join_fallback())
}

#[tauri::command]
pub async fn remove_leftovers(scan_id: String, paths: Vec<String>) -> serde_json::Value {
    tokio::task::spawn_blocking(move || {
        let offered = leftover_cache().lock().ok().and_then(|mut cache| cache.remove(&scan_id));
        let Some(offered) = offered else {
            return serde_json::json!({ "success": false, "message": "Leftover scan expired. Run the scan again.", "results": [] });
        };
        let approved: Vec<String> = offered
            .iter()
            .filter(|item| paths.iter().any(|path| path == &item.path))
            .map(|item| item.path.clone())
            .collect();
        let results = mod_uninstall::remove_leftovers(&approved);
        let items: Vec<serde_json::Value> = results
            .into_iter()
            .map(|(path, ok, msg)| serde_json::json!({ "path": path, "success": ok, "message": msg }))
            .collect();
        serde_json::json!({ "success": items.iter().all(|i| i.get("success") == Some(&serde_json::Value::Bool(true))), "results": items })
    })
    .await
    .unwrap_or_else(|_| join_fallback())
}

// ---------------------------------------------------------------------------
// Full system info (Speccy-style)
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_full_sysinfo() -> serde_json::Value {
    tokio::task::spawn_blocking(|| serde_json::to_value(mod_sysinfo::collect()).unwrap_or_default())
        .await
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Temperature monitoring
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_temperatures() -> serde_json::Value {
    tokio::task::spawn_blocking(|| {
        serde_json::to_value(mod_temps::collect_temps()).unwrap_or_default()
    })
    .await
    .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// DISM / SFC scans
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn check_admin_status() -> serde_json::Value {
    let status = mod_sfc::check_admin();
    serde_json::json!({ "is_admin": status.is_admin, "message": status.message })
}

// ---------------------------------------------------------------------------
// Run All Diagnostics (batch scan)
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn run_all_diagnostics() -> serde_json::Value {
    tokio::task::spawn_blocking(|| {
        let health = mod_health::quick_scan();
        let events = serde_json::to_value(mod_eventlog::get_summary()).unwrap_or_default();
        let bsod = mod_bsod::scan_dumps_report();
        let updates = serde_json::to_value(mod_updates::get_status()).unwrap_or_default();
        let activation = get_activation_status_sync();

        let modules = serde_json::json!([
            { "id": "health", "name": "System Health", "severity": match health.score { Some(score) if score >= 90 => "Ok", Some(score) if score >= 70 => "Warning", Some(_) => "Critical", None => "Unknown" } },
            { "id": "eventlog", "name": "Event Logs", "severity": if events.pointer("/system/complete").and_then(|v| v.as_bool()) != Some(true) { "Unknown" } else if events.pointer("/system/critical").and_then(|v| v.as_u64()).unwrap_or(0) > 0 { "Critical" } else if events.pointer("/system/error").and_then(|v| v.as_u64()).unwrap_or(0) > 0 { "Warning" } else { "Ok" } },
            { "id": "bsod", "name": "BSOD Dumps", "severity": if !bsod.complete { "Unknown" } else if !bsod.dumps.is_empty() { "Warning" } else { "Ok" } },
            { "id": "updates", "name": "Windows Update", "severity": if updates.get("complete").and_then(|v| v.as_bool()) != Some(true) { "Unknown" } else if updates.get("pending_updates").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0) > 0 { "Warning" } else { "Ok" } },
            { "id": "activation", "name": "Windows Activation", "severity": if activation.get("status").and_then(|v| v.as_str()) == Some("Error") { "Unknown" } else if activation.get("activated").and_then(|v| v.as_bool()) == Some(true) { "Ok" } else { "Warning" } },
        ]);

        let module_list = modules.as_array().map(|a| a.as_slice()).unwrap_or(&[]);
        let has_critical = module_list.iter().any(|m| m.get("severity").and_then(|s| s.as_str()) == Some("Critical"));
        let has_warning = module_list.iter().any(|m| m.get("severity").and_then(|s| s.as_str()) == Some("Warning"));
        let has_unknown = module_list.iter().any(|m| m.get("severity").and_then(|s| s.as_str()) == Some("Unknown"));
        let overall = if has_critical { "Critical" } else if has_warning { "Warning" } else if has_unknown { "Unknown" } else { "Ok" };

        serde_json::json!({
            "overall_severity": overall,
            "modules": modules,
            "activated": activation.get("activated").and_then(|v| v.as_bool()).unwrap_or(false),
        })
    }).await.unwrap_or_else(|_| join_fallback())
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

                    // apply_tweak_sync logs history per-module with the tweak's real
                    // name + tier, so don't append a second (duplicate) entry here.
                    let result = apply_tweak_sync(module, action_id);
                    let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
                    if success {
                        succeeded += 1;
                    }
                    results.push(serde_json::json!({
                        "action_id": action_id,
                        "display_name": display,
                        "success": success,
                        "message": result.get("message").and_then(|v| v.as_str()).unwrap_or("No result details"),
                    }));
                }

                serde_json::json!({
                    "success": total > 0 && succeeded == total,
                    "partial": succeeded > 0 && succeeded < total,
                    "total": total,
                    "succeeded": succeeded,
                    "failed": total - succeeded,
                    "results": results,
                })
            }
            None => serde_json::json!({ "success": false, "message": format!("Unknown preset: {}", id) }),
        }
    }).await.unwrap_or_else(|_| join_fallback())
}

// ---------------------------------------------------------------------------
// Snapshot / Diff (file-backed)
// ---------------------------------------------------------------------------

fn snapshot_path() -> std::path::PathBuf {
    if crate::portable::is_portable() {
        crate::portable::portable_data_dir("cove-windows-optimizer").join("snapshot.json")
    } else {
        directories::ProjectDirs::from("com", "cove", "optimizer")
            .map(|dirs| dirs.data_local_dir().join("snapshot.json"))
            .unwrap_or_else(|| std::path::PathBuf::from("snapshot.json"))
    }
}

fn system_drive_free_bytes() -> Option<u64> {
    #[cfg(target_os = "windows")]
    {
        let ps = r#"$sd = $env:SystemDrive; (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$sd'" -ErrorAction SilentlyContinue).FreeSpace"#;
        if let Ok(o) = optimizer_core::powershell(ps).output() {
            return String::from_utf8_lossy(&o.stdout).trim().parse().ok();
        }
    }
    None
}

#[tauri::command]
pub async fn take_snapshot() -> serde_json::Value {
    tokio::task::spawn_blocking(|| {
    let health = mod_health::quick_scan();
    let startup_result = mod_startup::list_items_v2();
    let programs = mod_uninstall::list_programs();
    let cleanup = mod_cleanup::scan_targets();
    let events = mod_eventlog::get_summary();
    let bloatware = mod_bloatware::scan_installed();

    let startup_items = startup_result.as_ref().ok().map(|items| items.iter().map(|item| {
        serde_json::json!({ "id": item.id, "name": item.name })
    }).collect::<Vec<_>>());
    let program_items = programs.iter().map(|item| {
        serde_json::json!({ "id": item.id, "name": item.name })
    }).collect::<Vec<_>>();
    let temp_size = if cleanup.iter().all(|target| target.scan_error.is_none()) {
        Some(cleanup.iter().map(|target| target.size_bytes).sum::<u64>())
    } else { None };

    let snapshot = serde_json::json!({
        "timestamp": chrono::Local::now().to_rfc3339(),
        "hostname": hostname::get().map(|h| h.to_string_lossy().to_string()).unwrap_or_default(),
        "health_score": health.score,
        "disk_free": system_drive_free_bytes(),
        "startup_items": startup_items,
        "programs": program_items,
        "bloatware": if bloatware.complete { Some(bloatware.apps.iter().filter(|a| a.installed).map(|a| serde_json::json!({ "id": a.package_name, "name": a.display_name })).collect::<Vec<_>>()) } else { None },
        "temp_size": temp_size,
        "critical_events": if events.system.complete { Some(events.system.critical) } else { None },
        "warning_events": if events.system.complete { Some(events.system.warning) } else { None },
    });

    let path = snapshot_path();
    let _guard = DATA_FILE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if let Err(error) = write_json_atomic(&path, &snapshot) {
        return serde_json::json!({ "success": false, "message": format!("Could not save snapshot: {error}") });
    }

    serde_json::json!({
        "success": true,
        "timestamp": snapshot.get("timestamp").and_then(|v| v.as_str()).unwrap_or(""),
        "hostname": snapshot.get("hostname").and_then(|v| v.as_str()).unwrap_or(""),
    })
    }).await.unwrap_or_else(|_| join_fallback())
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
        None => return serde_json::json!({ "has_previous": false, "error": "The previous snapshot is unreadable." }),
    };

    let health = mod_health::quick_scan();
    let startup = mod_startup::list_items_v2();
    let programs = mod_uninstall::list_programs();
    let cleanup = mod_cleanup::scan_targets();
    let events = mod_eventlog::get_summary();
    let bloatware = mod_bloatware::scan_installed();

    let cur_score = health.score.map(i64::from);
    let prev_score = prev.get("health_score").and_then(|v| v.as_i64());

    let read_items = |value: Option<&serde_json::Value>| -> Option<std::collections::BTreeMap<String, String>> {
        value?.as_array().map(|items| items.iter().filter_map(|item| Some((item.get("id")?.as_str()?.to_lowercase(), item.get("name")?.as_str()?.to_string()))).collect())
    };
    let cur_startup = startup.ok().map(|items| items.into_iter().map(|i| (i.id.to_lowercase(), i.name)).collect::<std::collections::BTreeMap<_,_>>());
    let prev_startup = read_items(prev.get("startup_items"));
    let cur_programs = Some(programs.into_iter().map(|i| (i.id.to_lowercase(), i.name)).collect::<std::collections::BTreeMap<_,_>>());
    let prev_programs = read_items(prev.get("programs"));
    let cur_bloatware = bloatware.complete.then(|| bloatware.apps.into_iter().filter(|a| a.installed).map(|a| (a.package_name.to_lowercase(), a.display_name)).collect::<std::collections::BTreeMap<_,_>>());
    let prev_bloatware = read_items(prev.get("bloatware"));
    let added = |cur: &Option<std::collections::BTreeMap<String,String>>, old: &Option<std::collections::BTreeMap<String,String>>| -> Vec<String> {
        match (cur, old) { (Some(c), Some(o)) => c.iter().filter(|(id, _)| !o.contains_key(*id)).map(|(_, name)| name.clone()).collect(), _ => Vec::new() }
    };
    let removed = |cur: &Option<std::collections::BTreeMap<String,String>>, old: &Option<std::collections::BTreeMap<String,String>>| -> Vec<String> {
        match (cur, old) { (Some(c), Some(o)) => o.iter().filter(|(id, _)| !c.contains_key(*id)).map(|(_, name)| name.clone()).collect(), _ => Vec::new() }
    };

    let cur_temp = cleanup.iter().all(|t| t.scan_error.is_none()).then(|| cleanup.iter().map(|t| t.size_bytes as i64).sum::<i64>());
    let prev_temp = prev.get("temp_size").and_then(|v| v.as_i64());
    let event_complete = events.system.complete;
    let cur_crit = event_complete.then_some(events.system.critical as i64);
    let cur_warn = event_complete.then_some(events.system.warning as i64);
    let cur_free = system_drive_free_bytes().and_then(|v| i64::try_from(v).ok());

    serde_json::json!({
        "has_previous": true,
        "previous_timestamp": prev.get("timestamp").and_then(|v| v.as_str()).unwrap_or(""),
        "changes": {
            "new_startup_items": added(&cur_startup, &prev_startup),
            "removed_startup_items": removed(&cur_startup, &prev_startup),
            "new_programs": added(&cur_programs, &prev_programs),
            "removed_programs": removed(&cur_programs, &prev_programs),
            "new_bloatware": added(&cur_bloatware, &prev_bloatware),
            "health_score_change": cur_score.zip(prev_score).map(|(current, previous)| current - previous),
            "temp_size_change": cur_temp.zip(prev_temp).map(|(current, previous)| current - previous),
            "disk_free_change": cur_free.zip(prev.get("disk_free").and_then(|v| v.as_i64())).map(|(current, previous)| current - previous),
            "critical_event_change": cur_crit.zip(prev.get("critical_events").and_then(|v| v.as_i64())).map(|(current, previous)| current - previous),
            "warning_event_change": cur_warn.zip(prev.get("warning_events").and_then(|v| v.as_i64())).map(|(current, previous)| current - previous),
        },
    })
    }).await.unwrap_or_else(|_| join_fallback())
}

// ---------------------------------------------------------------------------
// Runtimes checker
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_installed_runtimes() -> serde_json::Value {
    tokio::task::spawn_blocking(|| {
        serde_json::to_value(mod_runtimes::collect_runtimes()).unwrap_or_default()
    })
    .await
    .unwrap_or_else(|_| {
        serde_json::json!({
            "dotnet": [], "vcredist": [], "java": [],
            "directx": { "version": "Unknown", "feature_level": "Unknown", "download_url": "" },
            "coverage": {
                "dotnet": { "complete": false, "errors": ["Runtime worker failed."] },
                "vcredist": { "complete": false, "errors": ["Runtime worker failed."] },
                "directx": { "complete": false, "errors": ["Runtime worker failed."] },
                "java": { "complete": false, "errors": ["Runtime worker failed."] }
            }
        })
    })
}

// ---------------------------------------------------------------------------
// Security scan
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_security_status() -> serde_json::Value {
    tokio::task::spawn_blocking(|| {
        let defender = mod_security::get_defender_status();
        serde_json::json!({ "defender": defender, "heuristic_findings": [], "scan_available": true })
    }).await.unwrap_or_else(|_| join_fallback())
}

#[tauri::command]
pub async fn run_heuristic_scan() -> serde_json::Value {
    tokio::task::spawn_blocking(|| {
        serde_json::to_value(mod_security::run_heuristics()).unwrap_or_default()
    })
    .await
    .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Open URL in default browser
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn open_url(url: String) -> serde_json::Value {
    let allowed_settings = matches!(
        url.as_str(),
        "ms-settings:windowsupdate-optionalupdates" | "ms-settings:windowsupdate-action"
    );
    if (!url.starts_with("https://") && !allowed_settings)
        || url.chars().any(|c| c.is_control())
        || url
            .chars()
            .any(|c| matches!(c, '&' | '|' | '<' | '>' | '^' | '`'))
    {
        return serde_json::json!({ "success": false, "message": "Only valid HTTPS URLs can be opened." });
    }
    #[cfg(target_os = "windows")]
    let result = unsafe {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::UI::Shell::ShellExecuteW;
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

        let operation: Vec<u16> = std::ffi::OsStr::new("open")
            .encode_wide()
            .chain(Some(0))
            .collect();
        let target: Vec<u16> = std::ffi::OsStr::new(&url)
            .encode_wide()
            .chain(Some(0))
            .collect();
        ShellExecuteW(
            std::ptr::null_mut(),
            operation.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        ) as isize
            > 32
    };
    #[cfg(not(target_os = "windows"))]
    let result = optimizer_core::silent_cmd("xdg-open")
        .arg(&url)
        .spawn()
        .is_ok();
    serde_json::json!({ "success": result, "message": if result { "Opened URL." } else { "Failed to open URL." } })
}

// ---------------------------------------------------------------------------
// Disk Health
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_disk_health() -> serde_json::Value {
    tokio::task::spawn_blocking(|| {
        serde_json::to_value(mod_diskhealth::collect_drive_health()).unwrap_or_default()
    })
    .await
    .unwrap_or_else(|_| {
        serde_json::json!({
            "complete": false,
            "errors": ["Disk-health worker failed."],
            "drives": []
        })
    })
}

#[tauri::command]
pub async fn get_disk_space(_drive: String) -> serde_json::Value {
    // get_largest_files does a recursive C:\Users scan; keep it off the async runtime thread.
    tokio::task::spawn_blocking(move || {
        serde_json::to_value(mod_diskhealth::get_largest_files(
            &mod_diskhealth::system_drive(),
        ))
        .unwrap_or_default()
    })
    .await
    .unwrap_or_else(|_| {
        serde_json::json!({
            "drive": mod_diskhealth::system_drive(),
            "complete": false,
            "errors": ["Disk-space worker failed."],
            "total_bytes": null,
            "free_bytes": null,
            "largest_files": []
        })
    })
}

#[tauri::command]
pub async fn run_chkdsk(mode: String, _drive: String) -> serde_json::Value {
    tokio::task::spawn_blocking(move || {
        serde_json::to_value(mod_diskhealth::run_chkdsk(
            &mode,
            &mod_diskhealth::system_drive(),
        ))
        .unwrap_or_default()
    })
    .await
    .unwrap_or_else(|_| join_fallback())
}

#[tauri::command]
pub async fn get_last_chkdsk() -> serde_json::Value {
    tokio::task::spawn_blocking(|| {
        serde_json::to_value(mod_diskhealth::get_last_chkdsk()).unwrap_or_default()
    })
    .await
    .unwrap_or_else(|_| join_fallback())
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
                let applied = t.current_value.as_deref() == Some(t.optimized_value.as_str());
                serde_json::json!({
                    "id": t.id, "name": t.name, "description": t.description, "category": t.category,
                    "safety_tier": t.safety_tier, "registry_path": t.registry_path,
                    "current_value": t.current_value, "optimized_value": t.optimized_value, "warning": t.warning,
                    "applied": applied, "can_undo": load_snapshot(&t.id).is_some(),
                })
            })
            .collect()
    }).await.unwrap_or_default()
}

#[tauri::command]
pub async fn apply_performance_tweak(id: String) -> serde_json::Value {
    tokio::task::spawn_blocking(move || apply_perf_tweak_sync(&id))
        .await
        .unwrap_or_else(|_| join_fallback())
}

#[tauri::command]
pub async fn undo_performance_tweak(id: String) -> serde_json::Value {
    tokio::task::spawn_blocking(move || undo_perf_tweak_sync(&id))
        .await
        .unwrap_or_else(|_| join_fallback())
}

// ---------------------------------------------------------------------------
// Windows Activation status
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_activation_status() -> serde_json::Value {
    tokio::task::spawn_blocking(get_activation_status_sync)
        .await
        .unwrap_or_else(|_| join_fallback())
}

fn get_activation_status_sync() -> serde_json::Value {
    if cfg!(not(target_os = "windows")) {
        return serde_json::json!({ "activated": true, "edition": "Windows 11 Pro", "status": "Licensed", "detail": "Windows is activated with a digital license." });
    }

    let output = optimizer_core::powershell(
            "Get-CimInstance -ClassName SoftwareLicensingProduct -Filter \"ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL\" | Where-Object { $_.Name -like 'Windows*' -and $_.Description -like '*Operating System*' } | Sort-Object LicenseStatus -Descending | Select-Object -First 1 Name, LicenseStatus | ConvertTo-Json")
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(stdout.trim()) {
                let status = val
                    .get("LicenseStatus")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let name = val
                    .get("Name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown");
                let (activated, label) = match status {
                    1 => (true, "Licensed"),
                    2 => (false, "Out-of-Box Grace"),
                    3 => (false, "Out-of-Tolerance Grace"),
                    4 => (false, "Non-Genuine Grace"),
                    5 => (false, "Notification"),
                    6 => (false, "Extended Grace"),
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
        _ => {
            serde_json::json!({ "activated": false, "edition": "Unknown", "status": "Error", "detail": "Failed to query activation status." })
        }
    }
}

// ---------------------------------------------------------------------------
// Undo change
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn undo_change(id: i64) -> serde_json::Value {
    tokio::task::spawn_blocking(move || undo_change_sync(id))
        .await
        .unwrap_or_else(|_| join_fallback())
}

fn undo_change_sync(id: i64) -> serde_json::Value {
    let path = history_path();
    let entries: Vec<serde_json::Value> = {
        let _guard = DATA_FILE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        match std::fs::read_to_string(&path)
            .ok()
            .and_then(|d| serde_json::from_str(&d).ok())
        {
            Some(e) => e,
            None => {
                return serde_json::json!({ "success": false, "message": "No readable change history found." });
            }
        }
    };

    let idx = match entries
        .iter()
        .position(|e| e.get("id").and_then(|v| v.as_i64()) == Some(id))
    {
        Some(i) => i,
        None => {
            return serde_json::json!({ "success": false, "message": format!("Change {} not found.", id) });
        }
    };
    if entries[idx].get("status").and_then(|v| v.as_str()) == Some("undone") {
        return serde_json::json!({ "success": false, "message": "This change was already undone." });
    }

    let module = entries[idx]
        .get("module")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let name = entries[idx]
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let action_id = entries[idx]
        .get("action_id")
        .and_then(|v| v.as_str())
        .map(str::to_owned);

    // Reverts that use the saved pre-apply snapshot; dispatched by module + name.
    let result = match module.as_str() {
        "performance" => match mod_performance::get_tweaks().into_iter().find(|t| {
            action_id.as_deref() == Some(t.id.as_str()) || (action_id.is_none() && t.name == name)
        }) {
            Some(t) => undo_perf_tweak_sync(&t.id),
            None => {
                serde_json::json!({ "success": false, "message": format!("Tweak '{}' not found.", name) })
            }
        },
        "visual" => match mod_visual::get_tweaks().into_iter().find(|t| {
            action_id.as_deref() == Some(t.id.as_str()) || (action_id.is_none() && t.name == name)
        }) {
            Some(t) => undo_visual_tweak_sync(&t.id),
            None => {
                serde_json::json!({ "success": false, "message": format!("Tweak '{}' not found.", name) })
            }
        },
        "privacy" => {
            let tweaks = mod_privacy::get_tweaks();
            let all: Vec<_> = [tweaks.basic, tweaks.standard, tweaks.advanced].concat();
            match all.into_iter().find(|t| {
                action_id.as_deref() == Some(t.id.as_str())
                    || (action_id.is_none() && t.name == name)
            }) {
                Some(t) => undo_privacy_tweak_sync(&t.id),
                None => {
                    serde_json::json!({ "success": false, "message": format!("Tweak '{}' not found.", name) })
                }
            }
        }
        "startup" => {
            serde_json::json!({ "success": false, "message": "This legacy startup history entry has no saved before-state and cannot be undone safely." })
        }
        other => serde_json::json!({
            "success": false,
            "message": format!("'{}' changes can't be undone automatically; revert it from its own panel.", other)
        }),
    };

    // On success, flip the original entry to "undone" and persist. (This write
    // also supersedes any extra entry an inner undo appended, so the history
    // shows a single, accurate state.)
    if result
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        let _guard = DATA_FILE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut latest: Vec<serde_json::Value> = match std::fs::read_to_string(&path)
            .ok()
            .and_then(|d| serde_json::from_str(&d).ok())
        {
            Some(entries) => entries,
            None => {
                return serde_json::json!({ "success": false, "changed": true, "message": "The setting was restored, but History could not be reloaded to record it." });
            }
        };
        let Some(latest_idx) = latest
            .iter()
            .position(|e| e.get("id").and_then(|v| v.as_i64()) == Some(id))
        else {
            return serde_json::json!({ "success": false, "changed": true, "message": "The setting was restored, but its History entry disappeared before it could be updated." });
        };
        latest[latest_idx]["status"] = serde_json::Value::String("undone".to_string());
        latest[latest_idx]["can_undo"] = serde_json::Value::Bool(false);
        if let Err(error) = write_json_atomic(&path, &latest) {
            return serde_json::json!({ "success": false, "changed": true, "message": format!("The setting was restored, but History could not be saved: {error}") });
        }
    }
    result
}
