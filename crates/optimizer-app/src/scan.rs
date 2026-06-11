//! Long-running system scans (SFC / DISM) that live in the backend so they
//! survive UI tab changes, with incremental progress parsed from the tool's
//! piped output. The frontend polls `get_scan_progress`; nothing depends on the
//! panel staying mounted.

use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

#[derive(Clone, Serialize, Default)]
pub struct ScanProgress {
    pub running: bool,
    /// Whether this tool has been started at least once this session.
    pub started: bool,
    pub percent: f32,
    pub phase: String,
    /// The last handful of real output lines (mini-console view).
    pub output_tail: Vec<String>,
    pub done: bool,
    pub success: bool,
    pub summary: String,
    pub exit_code: i32,
}

static SCANS: OnceLock<Mutex<HashMap<String, ScanProgress>>> = OnceLock::new();

fn scans() -> &'static Mutex<HashMap<String, ScanProgress>> {
    SCANS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[tauri::command]
pub fn get_scan_progress(tool: String) -> ScanProgress {
    scans().lock().unwrap().get(&tool).cloned().unwrap_or_default()
}

#[tauri::command]
pub fn start_scan(tool: String) -> serde_json::Value {
    if tool != "sfc" && tool != "dism" && tool != "full" {
        return serde_json::json!({ "success": false, "message": "Unknown tool" });
    }
    {
        let mut g = scans().lock().unwrap();
        if let Some(p) = g.get(&tool) {
            if p.running {
                return serde_json::json!({ "success": false, "message": "A scan is already running." });
            }
        }
        g.insert(
            tool.clone(),
            ScanProgress {
                running: true,
                started: true,
                phase: "Starting…".into(),
                ..Default::default()
            },
        );
    }
    let t = tool.clone();
    std::thread::spawn(move || run_scan_thread(&t));
    serde_json::json!({ "success": true })
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn run_scan_thread(key: &str) {
    match key {
        "dism" => {
            let r = run_one("dism", key, 0.0, 1.0, "");
            finish(key, r.0, r.1, &r.2, r.3);
        }
        "sfc" => {
            let r = run_one("sfc", key, 0.0, 1.0, "");
            finish(key, r.0, r.1, &r.2, r.3);
        }
        "full" => {
            // DISM first (0-50% of the bar), then SFC (50-100%).
            let d = run_one("dism", key, 0.0, 0.5, "DISM");
            let s = run_one("sfc", key, 50.0, 0.5, "SFC");
            let success = d.0 && s.0;
            let summary = format!("DISM — {}   ·   SFC — {}", d.2, s.2);
            finish(key, success, s.1, &summary, s.3);
        }
        _ => {}
    }
}

/// Run a single tool, updating the shared progress under `key`. `base`/`scale`
/// map the tool's 0-100% onto a slice of the bar (for the combined run).
#[cfg(target_os = "windows")]
fn run_one(tool: &str, key: &str, base: f32, scale: f32, label: &str) -> (bool, i32, String, Vec<String>) {
    use std::io::Read;

    let (program, args): (&str, &[&str]) = match tool {
        "sfc" => ("sfc", &["/scannow"]),
        "dism" => ("dism", &["/Online", "/Cleanup-Image", "/RestoreHealth"]),
        _ => return (false, -1, "Unknown tool".into(), Vec::new()),
    };

    let spawned = optimizer_core::silent_cmd(program)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();

    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => return (false, -1, format!("Failed to start {}: {}", program, e), Vec::new()),
    };

    let mut out = match child.stdout.take() {
        Some(o) => o,
        None => return (false, -1, "No output handle.".into(), Vec::new()),
    };

    // sfc.exe emits UTF-16LE; dism is single-byte. Accumulate raw bytes and
    // re-decode so multi-byte units that straddle reads aren't corrupted.
    let is_sfc = tool == "sfc";
    let mut acc: Vec<u8> = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match out.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                acc.extend_from_slice(&buf[..n]);
                let text = decode(&acc, is_sfc);
                update(key, &text, base, scale, label);
            }
            Err(_) => break,
        }
    }

    let status = child.wait();
    let code = status.as_ref().ok().and_then(|s| s.code()).unwrap_or(-1);
    let success = status.as_ref().map(|s| s.success()).unwrap_or(false);
    let final_text = decode(&acc, is_sfc);
    let lines = split_lines(&final_text);
    let summary = summarize(tool, &final_text, code);
    (success, code, summary, lines)
}

#[cfg(not(target_os = "windows"))]
fn run_scan_thread(key: &str) {
    finish(key, true, 0, "[stub] scan completed (not on Windows).", vec!["[stub] scan output".into()]);
}

fn decode(bytes: &[u8], utf16: bool) -> String {
    if utf16 {
        let even = bytes.len() & !1;
        let units: Vec<u16> = bytes[..even]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).to_string()
    }
}

fn split_lines(text: &str) -> Vec<String> {
    text.split(|c| c == '\r' || c == '\n')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// The last percentage value seen in the text (e.g. "4.9%" -> 4.9).
fn last_percent(text: &str) -> Option<f32> {
    let chars: Vec<char> = text.chars().collect();
    let mut last: Option<f32> = None;
    for (i, &c) in chars.iter().enumerate() {
        if c != '%' {
            continue;
        }
        let mut j = i;
        let mut seen_digit = false;
        while j > 0 {
            let p = chars[j - 1];
            if p.is_ascii_digit() {
                seen_digit = true;
                j -= 1;
            } else if p == '.' && seen_digit {
                j -= 1;
            } else {
                break;
            }
        }
        if seen_digit {
            let s: String = chars[j..i].iter().collect();
            if let Ok(v) = s.parse::<f32>() {
                last = Some(v);
            }
        }
    }
    last
}

fn update(key: &str, text: &str, base: f32, scale: f32, label: &str) {
    let segs = split_lines(text);
    let tail: Vec<String> = segs.iter().rev().take(14).rev().cloned().collect();
    let line = segs.last().cloned().unwrap_or_default();
    let pct = last_percent(text);
    let mut g = scans().lock().unwrap();
    if let Some(p) = g.get_mut(key) {
        if let Some(v) = pct {
            p.percent = base + v * scale;
        }
        if !line.is_empty() {
            p.phase = if label.is_empty() { line } else { format!("{} · {}", label, line) };
        }
        p.output_tail = tail;
    }
}

fn finish(tool: &str, success: bool, code: i32, summary: &str, lines: Vec<String>) {
    let tail: Vec<String> = lines.iter().rev().take(14).rev().cloned().collect();
    let mut g = scans().lock().unwrap();
    let p = g.entry(tool.to_string()).or_default();
    p.running = false;
    p.done = true;
    p.started = true;
    p.success = success;
    p.exit_code = code;
    p.summary = summary.to_string();
    if success {
        p.percent = 100.0;
    }
    if !tail.is_empty() {
        p.output_tail = tail;
    }
    p.phase = if success { "Completed".into() } else { "Finished with issues".into() };
}

fn summarize(tool: &str, output: &str, code: i32) -> String {
    let lower = output.to_lowercase();
    if tool == "sfc" {
        if lower.contains("did not find any integrity violations") {
            "No integrity violations found.".into()
        } else if lower.contains("successfully repaired") {
            "Corrupted files were found and successfully repaired.".into()
        } else if lower.contains("unable to fix") {
            "Corrupted files found but could not be repaired. Run DISM first, then SFC again.".into()
        } else if code != 0 {
            format!("SFC finished with exit code {}.", code)
        } else {
            "SFC scan completed.".into()
        }
    } else if lower.contains("no component store corruption")
        || lower.contains("the restore operation completed successfully")
    {
        "Component store is healthy. No repairs needed.".into()
    } else if lower.contains("the component store has been repaired") {
        "Corruption was found and successfully repaired.".into()
    } else if lower.contains("source files could not be found") {
        "Corruption found but repair files are unavailable. Run Windows Update first, then retry.".into()
    } else if code != 0 {
        format!("DISM finished with exit code {}.", code)
    } else {
        "DISM scan completed.".into()
    }
}
