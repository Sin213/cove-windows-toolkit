#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod scan;
mod security_scan;

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

/// Tauri sets the Windows window icon from a single flattened RGBA image, which
/// the shell then rescales for the taskbar/title bar - that on-the-fly downscale
/// is what makes the icon look soft even when icon.ico ships crisp dedicated
/// frames (those only drive the Explorer/installer file icon). Pull the proper
/// system-sized HICONs straight from our own exe's icon resource (ExtractIconExW
/// picks the correct 32px/16px frame) and assign them to the window directly.
#[cfg(target_os = "windows")]
fn apply_crisp_window_icon(window: &tauri::WebviewWindow) {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::ExtractIconExW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        SendMessageW, ICON_BIG, ICON_SMALL, WM_SETICON,
    };

    let hwnd = match window.hwnd() {
        Ok(h) => h.0 as *mut core::ffi::c_void,
        Err(_) => return,
    };
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return,
    };
    let mut path: Vec<u16> = exe.as_os_str().encode_wide().collect();
    path.push(0);

    let mut h_large: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut h_small: *mut core::ffi::c_void = core::ptr::null_mut();
    unsafe {
        let n = ExtractIconExW(path.as_ptr(), 0, &mut h_large, &mut h_small, 1);
        if n == 0 || n == u32::MAX {
            return;
        }
        if !h_large.is_null() {
            SendMessageW(hwnd, WM_SETICON, ICON_BIG as usize, h_large as isize);
        }
        if !h_small.is_null() {
            SendMessageW(hwnd, WM_SETICON, ICON_SMALL as usize, h_small as isize);
        }
    }
}

fn main() {
    init_logging();

    tauri::Builder::default()
        .setup(|_app| {
            #[cfg(target_os = "windows")]
            {
                use tauri::Manager;
                if let Some(win) = _app.get_webview_window("main") {
                    apply_crisp_window_icon(&win);
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // System
            commands::get_system_info,
            // Visual effects
            commands::get_visual_tweaks,
            commands::apply_visual_tweak,
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
            // DISM / SFC
            commands::check_admin_status,
            // Live, tab-persistent scans
            scan::start_scan,
            scan::get_scan_progress,
            security_scan::start_security_scan,
            security_scan::get_security_scan,
            security_scan::open_windows_security,
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
