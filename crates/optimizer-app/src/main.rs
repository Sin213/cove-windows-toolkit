#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

// Custom window-control commands for the frameless titlebar. Defined as plain
// app commands (like everything else in this app) so they need no capability
// permissions.
#[tauri::command]
fn win_minimize(window: tauri::Window) {
    let _ = window.minimize();
}

#[tauri::command]
fn win_toggle_maximize(window: tauri::Window) {
    if window.is_maximized().unwrap_or(false) {
        let _ = window.unmaximize();
    } else {
        let _ = window.maximize();
    }
}

#[tauri::command]
fn win_close(window: tauri::Window) {
    let _ = window.close();
}

#[tauri::command]
fn win_start_drag(window: tauri::Window) {
    let _ = window.start_dragging();
}

fn init_logging() {
    use tracing_subscriber::{fmt, EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

    let log_dir = directories::ProjectDirs::from("com", "cove", "optimizer")
        .map(|dirs| dirs.data_local_dir().join("logs"))
        .unwrap_or_else(|| std::path::PathBuf::from("logs"));

    let file_appender = tracing_appender::rolling::daily(&log_dir, "cove-optimizer.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    // Leak the guard so it lives for the program's lifetime
    std::mem::forget(_guard);

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(fmt::layer().with_writer(non_blocking).with_ansi(false))
        .init();

    tracing::info!("Cove Windows Toolkit starting -log directory: {}", log_dir.display());
}

fn main() {
    init_logging();

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            // System
            commands::get_system_info,
            // Visual effects
            commands::get_visual_tweaks,
            commands::apply_visual_tweak,
            commands::apply_all_visual_tweaks,
            commands::undo_visual_tweak,
            // Health
            commands::get_health_report,
            // Privacy
            commands::get_privacy_tweaks,
            // Services
            commands::get_services_tweaks,
            // Startup
            commands::get_startup_items,
            // Cleanup
            commands::get_cleanup_targets,
            // Power
            commands::get_power_info,
            // Event log
            commands::get_event_log_summary,
            // BSOD
            commands::get_bsod_dumps,
            // Network diagnostics & tools
            commands::get_network_diagnostics,
            commands::set_dns,
            commands::run_network_command,
            // Windows Update
            commands::get_update_status,
            commands::reset_windows_update,
            commands::trigger_update_check,
            // Report
            commands::generate_report,
            // Generic apply/undo
            commands::apply_tweak,
            commands::undo_tweak,
            // History
            commands::get_change_history,
            // Startup toggle
            commands::toggle_startup,
            // Service change
            commands::apply_service_change,
            // Cleanup
            commands::run_cleanup,
            // Power plan
            commands::set_power_plan,
            commands::set_power_timeout,
            // System Restore
            commands::get_restore_status,
            commands::get_restore_points,
            commands::create_restore_point,
            commands::enable_system_protection,
            commands::launch_system_restore,
            // Bloatware
            commands::get_bloatware,
            commands::remove_bloatware,
            // Uninstaller
            commands::get_installed_programs,
            commands::uninstall_program,
            commands::scan_leftovers,
            commands::remove_leftovers,
            // System info (full)
            commands::get_full_sysinfo,
            // Temperatures
            commands::get_temperatures,
            commands::ensure_lhm_running,
            commands::get_lhm_status,
            // DISM / SFC
            commands::check_admin_status,
            commands::run_dism_scan,
            commands::run_sfc_scan,
            // Undo
            commands::undo_change,
            // Performance tweaks
            commands::get_performance_tweaks,
            commands::apply_performance_tweak,
            commands::undo_performance_tweak,
            // Activation
            commands::get_activation_status,
            // Batch diagnostics
            commands::run_all_diagnostics,
            // Presets
            commands::get_presets,
            commands::run_preset,
            // Snapshot / Diff
            commands::take_snapshot,
            commands::get_machine_diff,
            // Runtimes
            commands::get_installed_runtimes,
            // Open URL
            commands::open_url,
            // Export report
            commands::export_report,
            // Speed test
            commands::run_speed_test,
            // Security
            commands::get_security_status,
            commands::run_defender_scan,
            commands::run_heuristic_scan,
            // Disk Health
            commands::get_disk_health,
            commands::get_disk_space,
            commands::run_chkdsk,
            commands::get_last_chkdsk,
            // Window controls (frameless titlebar)
            win_minimize,
            win_toggle_maximize,
            win_close,
            win_start_drag,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
