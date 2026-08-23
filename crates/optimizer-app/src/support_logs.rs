use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const LOG_FILENAME_PREFIX: &str = "cove-optimizer.log";
const MAX_LOG_FILES: usize = 7;
const SUPPORT_LOG_LIMIT: u64 = 512 * 1024;

static ACTIVE_LOG_DIRECTORY: OnceLock<PathBuf> = OnceLock::new();
static LOG_GUARD: OnceLock<tracing_appender::non_blocking::WorkerGuard> = OnceLock::new();

#[derive(Serialize)]
pub struct SupportLogReport {
    pub report: String,
    pub file_count: usize,
    pub bytes_read: u64,
    pub truncated: bool,
}

fn configured_log_directory() -> PathBuf {
    crate::portable::data_dir("cove-windows-optimizer").join("logs")
}

fn active_log_directory() -> PathBuf {
    ACTIVE_LOG_DIRECTORY
        .get()
        .cloned()
        .unwrap_or_else(configured_log_directory)
}

pub fn init_logging() {
    use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

    let preferred = configured_log_directory();
    let fallback = std::env::temp_dir().join("cove-windows-toolkit-logs");
    let Some((log_dir, file_appender)) = [preferred, fallback].into_iter().find_map(|directory| {
        build_log_appender(&directory)
            .ok()
            .map(|appender| (directory, appender))
    }) else {
        // Diagnostics must never prevent the application from starting.
        return;
    };
    let _ = ACTIVE_LOG_DIRECTORY.set(log_dir.clone());

    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    let _ = LOG_GUARD.set(guard);

    let subscriber = tracing_subscriber::registry()
        .with(EnvFilter::new(
            "optimizer_app=info,cove::ui=info,cove::scan=info,cove::drivers=info",
        ))
        .with(fmt::layer().with_writer(non_blocking).with_ansi(false));
    if subscriber.try_init().is_ok() {
        tracing::info!(
            version = env!("CARGO_PKG_VERSION"),
            portable = crate::portable::is_portable(),
            "Cove Windows Toolkit started"
        );
    }
}

fn build_log_appender(
    directory: &Path,
) -> Result<tracing_appender::rolling::RollingFileAppender, String> {
    std::fs::create_dir_all(directory)
        .map_err(|error| format!("Could not create the log directory: {error}"))?;
    tracing_appender::rolling::RollingFileAppender::builder()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix(LOG_FILENAME_PREFIX)
        .max_log_files(MAX_LOG_FILES)
        .build(directory)
        .map_err(|error| format!("Could not initialize support logging: {error}"))
}

#[tauri::command]
pub fn get_support_logs() -> Result<SupportLogReport, String> {
    let log_dir = active_log_directory();
    std::fs::create_dir_all(&log_dir)
        .map_err(|error| format!("Could not create the log directory: {error}"))?;
    let excerpt = optimizer_core::support_logs::read_recent_logs(
        &log_dir,
        LOG_FILENAME_PREFIX,
        SUPPORT_LOG_LIMIT,
    )?;
    let user_profile = std::env::var_os("USERPROFILE").map(PathBuf::from);
    let clean_logs =
        optimizer_core::support_logs::sanitize_support_text(&excerpt.text, user_profile.as_deref());
    let generated = chrono::Local::now().to_rfc3339();
    let mode = if crate::portable::is_portable() {
        "portable"
    } else {
        "installed / standalone"
    };
    let truncation_notice = if excerpt.truncated {
        "\nNOTICE: Older log content was omitted to keep this report bounded.\n"
    } else {
        ""
    };
    let report = format!(
        concat!(
            "Cove Windows Toolkit support log\n",
            "Generated: {generated}\n",
            "App version: {version}\n",
            "Platform: {os} {arch}\n",
            "Install mode: {mode}\n",
            "Log files: {file_count}\n",
            "Privacy: user profile paths, URLs, and common credential fields are redacted.\n",
            "{truncation_notice}\n",
            "{logs}"
        ),
        generated = generated,
        version = env!("CARGO_PKG_VERSION"),
        os = std::env::consts::OS,
        arch = std::env::consts::ARCH,
        mode = mode,
        file_count = excerpt.file_count,
        truncation_notice = truncation_notice,
        logs = if clean_logs.is_empty() {
            "No log entries have been written yet."
        } else {
            &clean_logs
        },
    );

    Ok(SupportLogReport {
        report,
        file_count: excerpt.file_count,
        bytes_read: excerpt.bytes_read,
        truncated: excerpt.truncated,
    })
}

#[tauri::command]
pub fn record_ui_event(level: String, event: String, message: String) {
    let event = normalize_event_name(&event);
    let detail = sanitize_ui_message(&message);
    match level.to_ascii_lowercase().as_str() {
        "error" => tracing::error!(target: "cove::ui", event = %event, detail = %detail),
        "warn" | "warning" => {
            tracing::warn!(target: "cove::ui", event = %event, detail = %detail)
        }
        _ => tracing::info!(target: "cove::ui", event = %event, detail = %detail),
    }
}

#[tauri::command]
pub fn open_log_folder() -> Result<(), String> {
    let log_dir = active_log_directory();
    std::fs::create_dir_all(&log_dir)
        .map_err(|error| format!("Could not create the log directory: {error}"))?;
    open_directory(&log_dir)
}

fn normalize_event_name(event: &str) -> String {
    let normalized: String = event
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
        .take(64)
        .collect();
    if normalized.is_empty() {
        "ui_event".into()
    } else {
        normalized
    }
}

fn sanitize_ui_message(message: &str) -> String {
    let limited: String = message.chars().take(4_096).collect();
    let single_line = limited
        .replace(['\r', '\n', '\t'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let truncated: String = single_line.chars().take(2_048).collect();
    let user_profile = std::env::var_os("USERPROFILE").map(PathBuf::from);
    optimizer_core::support_logs::sanitize_support_text(&truncated, user_profile.as_deref())
}

#[cfg(target_os = "windows")]
fn open_directory(path: &Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let explorer = optimizer_core::windows_directory().join("explorer.exe");
    std::process::Command::new(explorer)
        .arg(path)
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map(|_| ())
        .map_err(|error| format!("Could not open the log folder: {error}"))
}

#[cfg(not(target_os = "windows"))]
fn open_directory(_path: &Path) -> Result<(), String> {
    Err("Opening the log folder is only supported on Windows.".into())
}
