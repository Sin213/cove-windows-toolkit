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
            // Network diagnostics
            commands::get_network_diagnostics,
            // Windows Update
            commands::get_update_status,
            // Report
            commands::generate_report,
            // Generic apply/undo
            commands::apply_tweak,
            commands::undo_tweak,
            // History
            commands::get_change_history,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
