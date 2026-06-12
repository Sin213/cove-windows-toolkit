//! Backend-resident security scans (Defender quick/full + our heuristic scan) so
//! they survive UI tab changes. The heuristic scan reports real step progress;
//! Defender has no public live-progress API, so it reports running + elapsed time
//! and the panel offers an "Open Windows Security" button for the native bar.

use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

#[derive(Clone, Serialize, Default)]
pub struct SecScanState {
    pub running: bool,
    pub started: bool,
    pub kind: String,          // "quick" | "full" | "heuristic"
    pub indeterminate: bool,   // Defender = true (no %); heuristic = false
    pub percent: f32,
    pub step: u32,
    pub total: u32,
    pub phase: String,
    pub elapsed_secs: u64,
    pub done: bool,
    pub success: bool,
    pub threats_found: u32,
    pub findings: serde_json::Value,
    pub message: String,
    #[serde(skip)]
    pub start: Option<Instant>,
}

static STATES: OnceLock<Mutex<HashMap<String, SecScanState>>> = OnceLock::new();

fn states() -> &'static Mutex<HashMap<String, SecScanState>> {
    STATES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn slot_for(kind: &str) -> &'static str {
    if kind == "heuristic" { "heuristic" } else { "defender" }
}

/// Force-finish a security scan on worker panic so `running` never sticks true.
struct SecFinishGuard(String);
impl Drop for SecFinishGuard {
    fn drop(&mut self) {
        let mut g = states().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(st) = g.get_mut(&self.0) {
            if st.running {
                st.running = false;
                st.done = true;
                st.success = false;
                st.phase = "Failed (internal error)".into();
                if st.message.is_empty() {
                    st.message = "The scan ended unexpectedly.".into();
                }
            }
        }
    }
}

#[tauri::command]
pub fn get_security_scan(slot: String) -> SecScanState {
    let g = states().lock().unwrap_or_else(|e| e.into_inner());
    let mut s = g.get(&slot).cloned().unwrap_or_default();
    if s.running {
        if let Some(start) = s.start {
            s.elapsed_secs = start.elapsed().as_secs();
        }
    }
    s
}

#[tauri::command]
pub fn start_security_scan(kind: String) -> serde_json::Value {
    let slot = slot_for(&kind);
    {
        let mut g = states().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = g.get(slot) {
            if s.running {
                return serde_json::json!({ "success": false, "message": "A scan is already running." });
            }
        }
        let st = SecScanState {
            running: true,
            started: true,
            kind: kind.clone(),
            indeterminate: slot == "defender",
            phase: "Starting…".into(),
            findings: serde_json::json!([]),
            start: Some(Instant::now()),
            ..Default::default()
        };
        g.insert(slot.to_string(), st);
    }
    std::thread::spawn(move || {
        let _guard = SecFinishGuard(slot_for(&kind).to_string());
        if slot_for(&kind) == "heuristic" {
            run_heuristic_thread();
        } else {
            run_defender_thread(&kind);
        }
    });
    serde_json::json!({ "success": true })
}

#[tauri::command]
pub fn open_windows_security() -> serde_json::Value {
    #[cfg(target_os = "windows")]
    {
        // The windowsdefender: URI opens the Windows Security app (Virus & threat
        // protection page), which shows Microsoft's real scan progress bar.
        match optimizer_core::silent_cmd("explorer").arg("windowsdefender://threat").spawn() {
            Ok(_) => serde_json::json!({ "success": true }),
            Err(e) => serde_json::json!({ "success": false, "message": e.to_string() }),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        serde_json::json!({ "success": false, "message": "Windows only" })
    }
}

// ---------------------------------------------------------------------------
// Workers
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn run_defender_thread(kind: &str) {
    let scan_flag = if kind == "full" { "FullScan" } else { "QuickScan" };
    let ps = format!(
        "$start = Get-Date; \
         try {{ Start-MpScan -ScanType {} -ErrorAction Stop; \
           $t = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object {{ $_.InitialDetectionTime -ge $start }}).Count; \
           Write-Output \"DONE|$t\" }} \
         catch {{ Write-Output \"FAIL|$($_.Exception.Message)\" }}",
        scan_flag
    );

    let (success, threats, message) = match optimizer_core::silent_cmd("powershell")
        .args(["-NoProfile", "-Command", &ps]).output()
    {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout);
            let last = s.lines().map(str::trim).filter(|l| !l.is_empty()).last().unwrap_or("");
            if let Some(rest) = last.strip_prefix("DONE|") {
                let t: u32 = rest.trim().parse().unwrap_or(0);
                let msg = if t == 0 {
                    "Scan complete — no threats found.".to_string()
                } else {
                    format!("Scan complete — {} threat(s) detected. Review them in Windows Security.", t)
                };
                (true, t, msg)
            } else if let Some(m) = last.strip_prefix("FAIL|") {
                (false, 0, m.to_string())
            } else {
                let err = String::from_utf8_lossy(&o.stderr);
                let m = err.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("Scan failed").to_string();
                (false, 0, m)
            }
        }
        Err(e) => (false, 0, e.to_string()),
    };

    finish_defender(success, threats, &message);
}

#[cfg(not(target_os = "windows"))]
fn run_defender_thread(_kind: &str) {
    finish_defender(true, 0, "[stub] Scan complete — no threats found.");
}

fn finish_defender(success: bool, threats: u32, message: &str) {
    let mut g = states().lock().unwrap_or_else(|e| e.into_inner());
    let st = g.entry("defender".to_string()).or_default();
    if let Some(start) = st.start {
        st.elapsed_secs = start.elapsed().as_secs();
    }
    st.running = false;
    st.done = true;
    st.success = success;
    st.threats_found = threats;
    st.message = message.to_string();
    st.phase = if success { "Completed".into() } else { "Failed".into() };
}

fn run_heuristic_thread() {
    let result = mod_security::run_heuristics_with_progress(|step, total, label| {
        let mut g = states().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(st) = g.get_mut("heuristic") {
            st.step = step;
            st.total = total;
            st.percent = if total > 0 { (step as f32 / total as f32) * 100.0 } else { 0.0 };
            st.phase = label.to_string();
        }
    });

    let count = result.findings.len() as u32;
    let findings = serde_json::to_value(&result.findings).unwrap_or_else(|_| serde_json::json!([]));

    let mut g = states().lock().unwrap_or_else(|e| e.into_inner());
    let st = g.entry("heuristic".to_string()).or_default();
    if let Some(start) = st.start {
        st.elapsed_secs = start.elapsed().as_secs();
    }
    st.running = false;
    st.done = true;
    st.success = true;
    st.percent = 100.0;
    st.findings = findings;
    st.phase = "Completed".into();
    st.message = if count == 0 {
        "No suspicious indicators found.".into()
    } else {
        format!("{} indicator(s) found.", count)
    };
}
