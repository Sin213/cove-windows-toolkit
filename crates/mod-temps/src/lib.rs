use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TempReading {
    pub sensor: String,
    pub category: String,
    pub temperature_c: f64,
    pub max_c: Option<f64>,
    pub critical_c: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TempReport {
    pub readings: Vec<TempReading>,
    pub warnings: Vec<String>,
}

#[cfg(target_os = "windows")]
pub fn collect_temps() -> TempReport {
    let json = run_ps(include_str!("temps.ps1"));
    match serde_json::from_str::<TempReport>(&json) {
        Ok(report) => report,
        Err(e) => {
            eprintln!("temps parse error: {e}\n{json}");
            TempReport {
                readings: Vec::new(),
                warnings: vec![format!("Failed to parse temperature data: {}", e)],
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn collect_temps() -> TempReport {
    TempReport {
        readings: vec![
            TempReading { sensor: "CPU Package".into(), category: "CPU".into(), temperature_c: 52.0, max_c: Some(100.0), critical_c: Some(105.0) },
            TempReading { sensor: "CPU Core #0".into(), category: "CPU".into(), temperature_c: 48.0, max_c: Some(100.0), critical_c: Some(105.0) },
            TempReading { sensor: "CPU Core #1".into(), category: "CPU".into(), temperature_c: 51.0, max_c: Some(100.0), critical_c: Some(105.0) },
            TempReading { sensor: "CPU Core #2".into(), category: "CPU".into(), temperature_c: 49.0, max_c: Some(100.0), critical_c: Some(105.0) },
            TempReading { sensor: "CPU Core #3".into(), category: "CPU".into(), temperature_c: 53.0, max_c: Some(100.0), critical_c: Some(105.0) },
            TempReading { sensor: "GPU Core".into(), category: "GPU".into(), temperature_c: 45.0, max_c: Some(93.0), critical_c: Some(100.0) },
            TempReading { sensor: "GPU Hot Spot".into(), category: "GPU".into(), temperature_c: 58.0, max_c: Some(93.0), critical_c: Some(100.0) },
            TempReading { sensor: "Samsung SSD 980 PRO".into(), category: "Disk".into(), temperature_c: 38.0, max_c: Some(70.0), critical_c: Some(75.0) },
            TempReading { sensor: "WD Blue SN570".into(), category: "Disk".into(), temperature_c: 35.0, max_c: Some(70.0), critical_c: Some(75.0) },
        ],
        warnings: Vec::new(),
    }
}

#[cfg(target_os = "windows")]
fn run_ps(script: &str) -> String {
    use std::process::Command;
    let out = Command::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .output();
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        Err(e) => format!("{{\"readings\":[],\"warnings\":[\"{}\"]}}", e),
    }
}
