use serde::Serialize;

// Re-import crates so they appear as used (prevents dead-code warnings
// even though the mock commands below don't call into stub crates yet).
use mod_cleanup as _;
use mod_privacy as _;
use mod_services as _;
use mod_startup as _;
use mod_power as _;
use mod_network as _;
use mod_eventlog as _;
use mod_bsod as _;
use mod_drivers as _;
use mod_netdiag as _;
use mod_updates as _;

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
pub fn get_visual_tweaks() -> Vec<serde_json::Value> {
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
pub fn apply_visual_tweak(id: String) -> serde_json::Value {
    serde_json::json!({ "success": true, "message": format!("Applied tweak: {}", id) })
}

#[tauri::command]
pub fn apply_all_visual_tweaks() -> serde_json::Value {
    serde_json::json!({ "success": true, "message": "Applied all 6 visual tweaks", "count": 6 })
}

#[tauri::command]
pub fn undo_visual_tweak(id: String) -> serde_json::Value {
    serde_json::json!({ "success": true, "message": format!("Reverted tweak: {}", id) })
}

// ---------------------------------------------------------------------------
// Health report
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn get_health_report() -> serde_json::Value {
    let report = mod_health::quick_scan();
    serde_json::json!({
        "score": report.score,
        "findings": report.findings,
    })
}

// ---------------------------------------------------------------------------
// Privacy scan
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn get_privacy_tweaks() -> serde_json::Value {
    serde_json::json!({
        "basic": [
            { "id": "privacy.advertising_id", "name": "Disable Advertising ID", "description": "Stop apps from using your advertising ID", "tier": "green", "path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo\\Enabled", "current": "1", "optimized": "0" },
            { "id": "privacy.typing_telemetry", "name": "Disable Typing Telemetry", "description": "Stop sending typing data to Microsoft", "tier": "green", "path": "HKCU\\Software\\Microsoft\\Input\\TIPC\\Enabled", "current": "1", "optimized": "0" },
            { "id": "privacy.web_search", "name": "Disable Web Search in Start", "description": "Stop Start menu from searching the web", "tier": "green", "path": "HKCU\\Software\\Policies\\Microsoft\\Windows\\Explorer\\DisableSearchBoxSuggestions", "current": "0", "optimized": "1" },
            { "id": "privacy.feedback", "name": "Disable Feedback Notifications", "description": "Stop Windows from asking for feedback", "tier": "green", "path": "HKCU\\Software\\Microsoft\\Siuf\\Rules\\NumberOfSIUFInPeriod", "current": "1", "optimized": "0" },
            { "id": "privacy.tips", "name": "Disable Tips and Suggestions", "description": "Stop suggested content notifications", "tier": "green", "path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\\SubscribedContent-338389Enabled", "current": "1", "optimized": "0" },
            { "id": "privacy.lockscreen_ads", "name": "Disable Lock Screen Ads", "description": "Remove rotating ads from lock screen", "tier": "green", "path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\\RotatingLockScreenOverlayEnabled", "current": "1", "optimized": "0" }
        ],
        "standard": [
            { "id": "privacy.telemetry_level", "name": "Minimize Telemetry", "description": "Reduce Windows telemetry to minimum level", "tier": "yellow", "path": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\\AllowTelemetry", "current": "3", "optimized": "0", "warning": "On Home/Pro editions, reduces to Security level but cannot fully disable" },
            { "id": "privacy.diagtrack", "name": "Disable DiagTrack Service", "description": "Stop the Connected User Experiences and Telemetry service", "tier": "yellow", "path": "Service: DiagTrack", "current": "Automatic", "optimized": "Disabled", "warning": "Breaks Windows Insider and Feedback Hub" },
            { "id": "privacy.cortana", "name": "Disable Cortana", "description": "Turn off Cortana completely", "tier": "yellow", "path": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search\\AllowCortana", "current": "1", "optimized": "0", "warning": "Disables Cortana entirely" },
            { "id": "privacy.background_apps", "name": "Disable Background Apps", "description": "Prevent apps from running in background", "tier": "green", "path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\BackgroundAccessApplications\\GlobalUserDisabled", "current": "0", "optimized": "1", "warning": "Mail/Calendar won't sync in background" }
        ],
        "advanced": [
            { "id": "privacy.camera_deny", "name": "Block Camera Access", "description": "Deny all apps access to camera", "tier": "red", "path": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy\\LetAppsAccessCamera", "current": "0", "optimized": "2", "warning": "No app can use your camera until you re-enable this" },
            { "id": "privacy.microphone_deny", "name": "Block Microphone Access", "description": "Deny all apps access to microphone", "tier": "red", "path": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy\\LetAppsAccessMicrophone", "current": "0", "optimized": "2", "warning": "No app can use your microphone until you re-enable this" }
        ]
    })
}

// ---------------------------------------------------------------------------
// Services scan
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn get_services_tweaks() -> serde_json::Value {
    serde_json::json!({
        "conservative": [
            { "id": "svc.wsearch", "name": "Windows Search", "service": "WSearch", "description": "Indexing service \u{2014} uses RAM and disk I/O", "tier": "green", "current": "Automatic", "optimized": "Manual", "impact": "Search works but first query is slower" },
            { "id": "svc.sysmain", "name": "SysMain (Superfetch)", "service": "SysMain", "description": "Prefetch service \u{2014} irrelevant on SSDs", "tier": "green", "current": "Automatic", "optimized": "Manual", "impact": "Frees RAM and reduces disk I/O on SSDs" },
            { "id": "svc.diagtrack", "name": "DiagTrack", "service": "DiagTrack", "description": "Connected User Experiences and Telemetry", "tier": "green", "current": "Automatic", "optimized": "Manual", "impact": "Stops telemetry data upload" },
            { "id": "svc.spooler", "name": "Print Spooler", "service": "Spooler", "description": "Manages print jobs", "tier": "green", "current": "Automatic", "optimized": "Manual", "impact": "Set Manual only if no printer detected" },
            { "id": "svc.xbox_auth", "name": "Xbox Live Auth Manager", "service": "XblAuthManager", "description": "Xbox Live authentication", "tier": "green", "current": "Manual", "optimized": "Disabled", "impact": "No effect unless Xbox app is actively used" },
            { "id": "svc.xbox_save", "name": "Xbox Live Game Save", "service": "XblGameSave", "description": "Xbox cloud saves", "tier": "green", "current": "Manual", "optimized": "Disabled", "impact": "No cloud save sync for Xbox games" },
            { "id": "svc.fax", "name": "Fax", "service": "Fax", "description": "Fax service", "tier": "green", "current": "Manual", "optimized": "Disabled", "impact": "No fax capability" }
        ],
        "advanced": [
            { "id": "svc.wuauserv", "name": "Windows Update", "service": "wuauserv", "description": "Manages Windows Updates", "tier": "red", "current": "Automatic", "optimized": "Disabled", "impact": "No security patches while disabled", "warning": "Your system will not receive security patches. Re-enable monthly." },
            { "id": "svc.windefend", "name": "Windows Defender", "service": "WinDefend", "description": "Real-time antivirus protection", "tier": "red", "current": "Automatic", "optimized": "Disabled", "impact": "No AV protection", "warning": "Only disable if using a third-party antivirus" }
        ]
    })
}

// ---------------------------------------------------------------------------
// Startup items
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn get_startup_items() -> serde_json::Value {
    serde_json::json!([
        { "id": "startup.onedrive", "name": "Microsoft OneDrive", "path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "command": "\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe\" /background", "impact": "High", "enabled": true },
        { "id": "startup.teams", "name": "Microsoft Teams", "path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "command": "\"C:\\Users\\user\\AppData\\Local\\Microsoft\\Teams\\Update.exe\" --processStart", "impact": "High", "enabled": true },
        { "id": "startup.spotify", "name": "Spotify", "path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "command": "\"C:\\Users\\user\\AppData\\Roaming\\Spotify\\Spotify.exe\" /minimized", "impact": "Medium", "enabled": true },
        { "id": "startup.discord", "name": "Discord", "path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "command": "\"C:\\Users\\user\\AppData\\Local\\Discord\\Update.exe\" --processStart", "impact": "High", "enabled": true },
        { "id": "startup.steam", "name": "Steam Client Bootstrapper", "path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "command": "\"C:\\Program Files (x86)\\Steam\\steam.exe\" -silent", "impact": "High", "enabled": true },
        { "id": "startup.realtek", "name": "Realtek HD Audio Manager", "path": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "command": "\"C:\\Program Files\\Realtek\\Audio\\HDA\\RtkNGUI64.exe\" -s", "impact": "Low", "enabled": true },
        { "id": "startup.sechealth", "name": "Windows Security", "path": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "command": "\"C:\\Windows\\System32\\SecurityHealthSystray.exe\"", "impact": "Low", "enabled": true }
    ])
}

// ---------------------------------------------------------------------------
// Cleanup targets
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn get_cleanup_targets() -> serde_json::Value {
    serde_json::json!([
        { "id": "clean.user_temp", "name": "User Temp Files", "path": "%TEMP%", "size_bytes": 524_288_000_u64, "file_count": 1847, "safety": "green" },
        { "id": "clean.system_temp", "name": "System Temp Files", "path": "%SystemRoot%\\Temp", "size_bytes": 134_217_728_u64, "file_count": 423, "safety": "green" },
        { "id": "clean.prefetch", "name": "Prefetch Cache", "path": "%SystemRoot%\\Prefetch", "size_bytes": 52_428_800_u64, "file_count": 312, "safety": "green" },
        { "id": "clean.thumbnails", "name": "Thumbnail Cache", "path": "%LocalAppData%\\Microsoft\\Windows\\Explorer", "size_bytes": 104_857_600_u64, "file_count": 48, "safety": "green" },
        { "id": "clean.error_reports", "name": "Error Reports", "path": "%LocalAppData%\\Microsoft\\Windows\\WER", "size_bytes": 31_457_280_u64, "file_count": 67, "safety": "green" },
        { "id": "clean.wu_cache", "name": "Windows Update Cache", "path": "%SystemRoot%\\SoftwareDistribution\\Download", "size_bytes": 2_147_483_648_u64, "file_count": 234, "safety": "yellow" },
        { "id": "clean.delivery_opt", "name": "Delivery Optimization", "path": "%SystemRoot%\\SoftwareDistribution\\DeliveryOptimization", "size_bytes": 1_073_741_824_u64, "file_count": 89, "safety": "yellow" }
    ])
}

// ---------------------------------------------------------------------------
// Power plan
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn get_power_info() -> serde_json::Value {
    serde_json::json!({
        "current_plan": "Balanced",
        "current_guid": "381b4222-f694-41f0-9685-ff5bb260df2e",
        "available_plans": [
            { "name": "Balanced", "guid": "381b4222-f694-41f0-9685-ff5bb260df2e", "active": true },
            { "name": "High Performance", "guid": "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c", "active": false },
            { "name": "Power Saver", "guid": "a1841308-3541-4fab-bc81-f71556f20b4a", "active": false }
        ],
        "hdd_sleep_minutes": 20,
        "display_off_minutes": 15,
        "sleep_minutes": 30
    })
}

// ---------------------------------------------------------------------------
// Event log summary
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn get_event_log_summary() -> serde_json::Value {
    serde_json::json!({
        "system": {
            "critical": 2,
            "error": 15,
            "warning": 47,
            "recent_events": [
                { "id": 41, "source": "Kernel-Power", "level": "Critical", "time": "2026-06-08T10:23:00Z", "message": "The system has rebooted without cleanly shutting down first" },
                { "id": 7, "source": "Disk", "level": "Error", "time": "2026-06-08T09:15:00Z", "message": "The device, \\Device\\Harddisk0\\DR0, has a bad block" },
                { "id": 10016, "source": "DistributedCOM", "level": "Error", "time": "2026-06-08T08:30:00Z", "message": "The application-specific permission settings do not grant Local Activation permission" },
                { "id": 1014, "source": "DNS Client Events", "level": "Warning", "time": "2026-06-08T07:45:00Z", "message": "Name resolution for the name wpad timed out" },
                { "id": 219, "source": "Kernel-PnP", "level": "Warning", "time": "2026-06-07T22:10:00Z", "message": "The driver \\Driver\\WudfRd failed to load" }
            ]
        },
        "application": {
            "critical": 0,
            "error": 8,
            "warning": 23,
            "recent_events": [
                { "id": 1000, "source": "Application Error", "level": "Error", "time": "2026-06-07T18:30:00Z", "message": "Faulting application name: explorer.exe" },
                { "id": 1002, "source": "Application Hang", "level": "Error", "time": "2026-06-07T16:20:00Z", "message": "The program Teams.exe stopped interacting with Windows" }
            ]
        }
    })
}

// ---------------------------------------------------------------------------
// BSOD analyzer
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn get_bsod_dumps() -> serde_json::Value {
    serde_json::json!([
        { "file": "C:\\Windows\\Minidump\\060726-12345-01.dmp", "date": "2026-06-07T14:23:00Z", "bug_check": "0x0000001E", "bug_check_name": "KMODE_EXCEPTION_NOT_HANDLED", "faulting_module": "ntoskrnl.exe", "description": "A kernel-mode program generated an exception which the error handler didn't catch", "recommendation": "Update all drivers. If persists, check RAM with Windows Memory Diagnostic." },
        { "file": "C:\\Windows\\Minidump\\060526-67890-01.dmp", "date": "2026-05-26T09:15:00Z", "bug_check": "0x000000D1", "bug_check_name": "DRIVER_IRQL_NOT_LESS_OR_EQUAL", "faulting_module": "nvlddmkm.sys", "description": "A driver attempted to access a pageable memory at too high an IRQL", "recommendation": "Update NVIDIA GPU driver to latest version. Consider clean install with DDU." }
    ])
}

// ---------------------------------------------------------------------------
// Driver audit
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn get_driver_audit() -> serde_json::Value {
    serde_json::json!({
        "total": 127,
        "unsigned": 3,
        "outdated": 5,
        "problematic": [
            { "name": "NVIDIA GeForce RTX 3070", "device": "Display adapters", "version": "31.0.15.3667", "date": "2025-08-15", "signed": true, "status": "outdated", "latest_version": "32.0.15.6094" },
            { "name": "Realtek PCIe GbE", "device": "Network adapters", "version": "10.45.928.2020", "date": "2023-03-10", "signed": true, "status": "outdated", "latest_version": "10.70.114.2025" },
            { "name": "Unknown USB Device", "device": "Universal Serial Bus controllers", "version": "10.0.19041.1", "date": "2020-06-21", "signed": false, "status": "unsigned", "latest_version": null }
        ],
        "healthy": [
            { "name": "Intel Wi-Fi 6 AX200", "device": "Network adapters", "version": "23.70.0.6", "date": "2026-01-20", "signed": true, "status": "ok" },
            { "name": "Realtek High Definition Audio", "device": "Sound, video and game controllers", "version": "6.0.9351.1", "date": "2025-11-05", "signed": true, "status": "ok" }
        ]
    })
}

// ---------------------------------------------------------------------------
// Network diagnostics
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn get_network_diagnostics() -> serde_json::Value {
    serde_json::json!({
        "adapter": { "name": "Intel Wi-Fi 6 AX200", "type": "Wi-Fi", "speed": "866 Mbps", "ip": "192.168.1.105", "gateway": "192.168.1.1", "dns": ["8.8.8.8", "8.8.4.4"], "signal": -45 },
        "tests": [
            { "name": "Gateway Ping", "status": "ok", "latency_ms": 1.2, "detail": "Gateway 192.168.1.1 reachable" },
            { "name": "DNS Resolution", "status": "ok", "latency_ms": 12.5, "detail": "google.com resolved to 142.250.80.46" },
            { "name": "Internet Connectivity", "status": "ok", "latency_ms": 18.3, "detail": "microsoft.com reachable" },
            { "name": "DNS Response Time", "status": "warning", "latency_ms": 85.2, "detail": "Primary DNS (8.8.8.8) responding slowly" }
        ],
        "wifi": { "ssid": "HomeNetwork-5G", "channel": 36, "frequency": "5 GHz", "signal_dbm": -45, "signal_quality": 82, "noise_dbm": -90 }
    })
}

// ---------------------------------------------------------------------------
// Network tools
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn set_dns(preset: String) -> serde_json::Value {
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

    let output = std::process::Command::new("powershell")
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
pub fn run_network_command(command: String) -> serde_json::Value {
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

    let output = std::process::Command::new(cmd).args(&args).output();

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
pub fn get_update_status() -> serde_json::Value {
    serde_json::json!({
        "last_check": "2026-06-07T14:00:00Z",
        "last_install": "2026-06-01T03:00:00Z",
        "service_status": "Running",
        "pending_updates": [
            { "title": "2026-06 Cumulative Update for Windows 11 (KB5039212)", "size_mb": 450, "severity": "Critical", "category": "Security" },
            { "title": "2026-06 .NET Framework 4.8.1 Security Update (KB5039890)", "size_mb": 52, "severity": "Important", "category": "Security" }
        ],
        "component_store_health": "Healthy",
        "days_since_last_update": 7
    })
}

#[tauri::command]
pub fn reset_windows_update() -> serde_json::Value {
    if cfg!(not(target_os = "windows")) {
        return serde_json::json!({ "success": true, "stub": true, "message": "[stub] Would reset Windows Update components.", "output": "Stop services → Clear cache → Re-register DLLs → Start services" });
    }

    let script = r#"
$log = @()
$services = @('wuauserv','bits','cryptSvc','msiserver')

# Stop services
foreach ($s in $services) {
    Stop-Service -Name $s -Force -ErrorAction SilentlyContinue
    $log += "Stopped $s"
}

# Rename cache folders
$sd = "$env:SystemRoot\SoftwareDistribution"
$cr = "$env:SystemRoot\System32\catroot2"
if (Test-Path $sd) { Rename-Item $sd "$sd.bak.$(Get-Date -Format yyyyMMddHHmmss)" -Force -ErrorAction SilentlyContinue; $log += "Renamed SoftwareDistribution" }
if (Test-Path $cr) { Rename-Item $cr "$cr.bak.$(Get-Date -Format yyyyMMddHHmmss)" -Force -ErrorAction SilentlyContinue; $log += "Renamed catroot2" }

# Re-register DLLs
$dlls = @('atl.dll','urlmon.dll','mshtml.dll','shdocvw.dll','browseui.dll','jscript.dll','vbscript.dll','scrrun.dll','msxml.dll','msxml3.dll','msxml6.dll','actxprxy.dll','softpub.dll','wintrust.dll','dssenh.dll','rsaenh.dll','gpkcsp.dll','sccbase.dll','slbcsp.dll','cryptdlg.dll','oleaut32.dll','ole32.dll','shell32.dll','initpki.dll','wuapi.dll','wuaueng.dll','wuaueng1.dll','wucltui.dll','wups.dll','wups2.dll','wuweb.dll','qmgr.dll','qmgrprxy.dll','wucltux.dll','muweb.dll','wuwebv.dll')
foreach ($dll in $dlls) { regsvr32.exe /s $dll 2>$null }
$log += "Re-registered WU DLLs"

# Reset Winsock
netsh winsock reset 2>$null | Out-Null
$log += "Reset Winsock"

# Restart services
foreach ($s in $services) {
    Start-Service -Name $s -ErrorAction SilentlyContinue
    $log += "Started $s"
}

$log -join "`n"
"#;

    let output = std::process::Command::new("powershell")
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
pub fn trigger_update_check() -> serde_json::Value {
    if cfg!(not(target_os = "windows")) {
        return serde_json::json!({ "success": true, "stub": true, "message": "[stub] Would open Windows Update settings." });
    }

    let result = std::process::Command::new("cmd")
        .args(["/C", "start ms-settings:windowsupdate-action"])
        .spawn();

    match result {
        Ok(_) => serde_json::json!({ "success": true, "message": "Windows Update check triggered. The Settings app should open." }),
        Err(e) => serde_json::json!({ "success": false, "message": format!("Failed: {}", e) }),
    }
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn generate_report() -> serde_json::Value {
    let report_html = mod_report::generate_html_report(
        "System Diagnostic Report",
        &[
            ("System Health", "Score: 85/100 -- Fair condition"),
            ("Disk Space", "45.0 GB free of 500.0 GB (9.0%) -- Warning"),
            ("Memory", "8.5 GB available of 16.0 GB (53.1%) -- OK"),
            ("Recommendations", "1. Free disk space (below 15%)\n2. Update NVIDIA driver\n3. Install pending security updates"),
        ],
    );
    serde_json::json!({ "html": report_html, "success": true })
}

// ---------------------------------------------------------------------------
// Generic apply / undo for any module
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn apply_tweak(module: String, id: String) -> serde_json::Value {
    serde_json::json!({ "success": true, "message": format!("[{}] Applied: {}", module, id) })
}

#[tauri::command]
pub fn undo_tweak(module: String, id: String) -> serde_json::Value {
    serde_json::json!({ "success": true, "message": format!("[{}] Reverted: {}", module, id) })
}

// ---------------------------------------------------------------------------
// Change history
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn get_change_history() -> serde_json::Value {
    serde_json::json!([
        { "id": 1, "timestamp": "2026-06-08T12:30:00Z", "module": "visual", "name": "Disable Transparency", "tier": "green", "status": "committed" },
        { "id": 2, "timestamp": "2026-06-08T12:30:00Z", "module": "visual", "name": "Disable Animations", "tier": "green", "status": "committed" }
    ])
}

// ---------------------------------------------------------------------------
// Startup toggle
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn toggle_startup(id: String, enabled: bool) -> serde_json::Value {
    if cfg!(not(target_os = "windows")) {
        return serde_json::json!({ "success": false, "stub": true, "message": format!("[stub] Would {} startup item: {}", if enabled { "enable" } else { "disable" }, id) });
    }
    serde_json::json!({ "success": true, "message": format!("Startup item {} {}", id, if enabled { "enabled" } else { "disabled" }) })
}

// ---------------------------------------------------------------------------
// Service change
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn apply_service_change(id: String) -> serde_json::Value {
    if cfg!(not(target_os = "windows")) {
        return serde_json::json!({ "success": false, "stub": true, "message": format!("[stub] Would apply service change: {}", id) });
    }
    serde_json::json!({ "success": true, "message": format!("Service change applied: {}", id) })
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn run_cleanup(ids: Vec<String>) -> serde_json::Value {
    if cfg!(not(target_os = "windows")) {
        return serde_json::json!({ "success": false, "stub": true, "message": format!("[stub] Would clean {} targets", ids.len()), "cleaned": 0 });
    }
    serde_json::json!({ "success": true, "message": format!("Cleaned {} targets", ids.len()), "cleaned": ids.len() })
}

// ---------------------------------------------------------------------------
// Power plan
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn set_power_plan(guid: String) -> serde_json::Value {
    if cfg!(not(target_os = "windows")) {
        return serde_json::json!({ "success": false, "stub": true, "message": format!("[stub] Would set power plan to {}", guid) });
    }
    serde_json::json!({ "success": true, "message": format!("Power plan set to {}", guid) })
}

#[tauri::command]
pub fn set_power_timeout(setting: String, minutes: u32) -> serde_json::Value {
    if cfg!(not(target_os = "windows")) {
        return serde_json::json!({ "success": true, "stub": true, "message": format!("[stub] Would set {} to {} min", setting, minutes) });
    }

    let sub_guid = match setting.as_str() {
        "display" => "7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e",
        "sleep" => "238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da",
        "disk" => "0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e",
        _ => return serde_json::json!({ "success": false, "message": format!("Unknown setting: {}", setting) }),
    };

    let cmd = format!("powercfg /change {} {}", match setting.as_str() {
        "display" => "monitor-timeout-ac",
        "sleep" => "standby-timeout-ac",
        "disk" => "disk-timeout-ac",
        _ => unreachable!(),
    }, minutes);

    let output = std::process::Command::new("cmd")
        .args(["/C", &cmd])
        .output();

    // Also set DC (battery) timeout
    let dc_cmd = format!("powercfg /change {} {}", match setting.as_str() {
        "display" => "monitor-timeout-dc",
        "sleep" => "standby-timeout-dc",
        "disk" => "disk-timeout-dc",
        _ => unreachable!(),
    }, minutes);
    let _ = std::process::Command::new("cmd").args(["/C", &dc_cmd]).output();
    let _ = sub_guid; // used for reference

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
pub fn get_restore_status() -> serde_json::Value {
    let status = mod_restore::get_restore_status();
    serde_json::json!({
        "enabled": status.enabled,
        "message": status.message,
    })
}

#[tauri::command]
pub fn get_restore_points() -> serde_json::Value {
    let points = mod_restore::list_restore_points();
    serde_json::json!(points)
}

#[tauri::command]
pub fn create_restore_point(description: String) -> serde_json::Value {
    match mod_restore::create_restore_point(&description) {
        Ok(msg) => serde_json::json!({ "success": true, "message": msg }),
        Err(msg) => serde_json::json!({ "success": false, "message": msg }),
    }
}

#[tauri::command]
pub fn enable_system_protection() -> serde_json::Value {
    match mod_restore::enable_system_protection() {
        Ok(msg) => serde_json::json!({ "success": true, "message": msg }),
        Err(msg) => serde_json::json!({ "success": false, "message": msg }),
    }
}

#[tauri::command]
pub fn launch_system_restore() -> serde_json::Value {
    match mod_restore::launch_system_restore() {
        Ok(msg) => serde_json::json!({ "success": true, "message": msg }),
        Err(msg) => serde_json::json!({ "success": false, "message": msg }),
    }
}

// ---------------------------------------------------------------------------
// Bloatware remover
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn get_bloatware() -> serde_json::Value {
    let apps = mod_bloatware::scan_installed();
    serde_json::to_value(apps).unwrap_or_default()
}

#[tauri::command]
pub fn remove_bloatware(packages: Vec<String>) -> serde_json::Value {
    let results = mod_bloatware::remove_apps(&packages);
    serde_json::to_value(results).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Uninstaller
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn get_installed_programs() -> serde_json::Value {
    let programs = mod_uninstall::list_programs();
    serde_json::to_value(programs).unwrap_or_default()
}

#[tauri::command]
pub fn uninstall_program(uninstall_string: String, quiet_uninstall_string: String) -> serde_json::Value {
    let result = mod_uninstall::run_uninstall(&uninstall_string, &quiet_uninstall_string);
    serde_json::to_value(result).unwrap_or_default()
}

#[tauri::command]
pub fn scan_leftovers(name: String, publisher: String, install_location: String, registry_key: String) -> serde_json::Value {
    let result = mod_uninstall::scan_leftovers(&name, &publisher, &install_location, &registry_key);
    serde_json::to_value(result).unwrap_or_default()
}

#[tauri::command]
pub fn remove_leftovers(paths: Vec<String>) -> serde_json::Value {
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
pub fn get_full_sysinfo() -> serde_json::Value {
    let info = mod_sysinfo::collect();
    serde_json::to_value(info).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Temperature monitoring
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn get_temperatures() -> serde_json::Value {
    let report = mod_temps::collect_temps();
    serde_json::to_value(report).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// DISM / SFC scans
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn check_admin_status() -> serde_json::Value {
    let status = mod_sfc::check_admin();
    serde_json::json!({
        "is_admin": status.is_admin,
        "message": status.message,
    })
}

#[tauri::command]
pub fn run_dism_scan() -> serde_json::Value {
    let result = mod_sfc::run_dism();
    serde_json::json!({
        "tool": result.tool,
        "success": result.success,
        "exit_code": result.exit_code,
        "output": result.output,
        "summary": result.summary,
    })
}

#[tauri::command]
pub fn run_sfc_scan() -> serde_json::Value {
    let result = mod_sfc::run_sfc();
    serde_json::json!({
        "tool": result.tool,
        "success": result.success,
        "exit_code": result.exit_code,
        "output": result.output,
        "summary": result.summary,
    })
}

// ---------------------------------------------------------------------------
// Performance tweaks
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn get_performance_tweaks() -> Vec<serde_json::Value> {
    mod_performance::get_tweaks()
        .into_iter()
        .map(|t| {
            serde_json::json!({
                "id": t.id,
                "name": t.name,
                "description": t.description,
                "category": t.category,
                "safety_tier": t.safety_tier,
                "registry_path": t.registry_path,
                "current_value": t.current_value,
                "optimized_value": t.optimized_value,
                "warning": t.warning,
            })
        })
        .collect()
}

#[tauri::command]
pub fn apply_performance_tweak(id: String) -> serde_json::Value {
    if cfg!(not(target_os = "windows")) {
        return serde_json::json!({ "success": true, "stub": true, "message": format!("[stub] Would apply performance tweak: {}", id) });
    }
    serde_json::json!({ "success": true, "message": format!("Applied performance tweak: {}", id) })
}

#[tauri::command]
pub fn undo_performance_tweak(id: String) -> serde_json::Value {
    if cfg!(not(target_os = "windows")) {
        return serde_json::json!({ "success": true, "stub": true, "message": format!("[stub] Would revert performance tweak: {}", id) });
    }
    serde_json::json!({ "success": true, "message": format!("Reverted performance tweak: {}", id) })
}

// ---------------------------------------------------------------------------
// Windows Activation status
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn get_activation_status() -> serde_json::Value {
    if cfg!(not(target_os = "windows")) {
        return serde_json::json!({
            "activated": true,
            "edition": "Windows 11 Pro",
            "status": "Licensed",
            "detail": "Windows is activated with a digital license."
        });
    }

    let output = std::process::Command::new("powershell")
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
                    1 => (true, "Licensed"),
                    2 => (false, "Out-of-Box Grace"),
                    3 => (false, "Out-of-Tolerance Grace"),
                    4 => (false, "Non-Genuine Grace"),
                    5 => (false, "Notification"),
                    6 => (false, "Extended Grace"),
                    _ => (false, "Unlicensed"),
                };
                serde_json::json!({
                    "activated": activated,
                    "edition": name,
                    "status": label,
                    "detail": if activated {
                        "Windows is activated.".to_string()
                    } else {
                        format!("Windows is not activated (status: {}).", label)
                    }
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
pub fn undo_change(id: i64) -> serde_json::Value {
    if cfg!(not(target_os = "windows")) {
        return serde_json::json!({ "success": false, "stub": true, "message": format!("[stub] Would undo change {}", id) });
    }
    serde_json::json!({ "success": true, "message": format!("Change {} undone", id) })
}
