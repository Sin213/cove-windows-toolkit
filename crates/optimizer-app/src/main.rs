#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

fn main() {
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
            // Drivers
            commands::get_driver_audit,
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
            commands::run_dism_scan,
            commands::run_sfc_scan,
            // Undo
            commands::undo_change,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
