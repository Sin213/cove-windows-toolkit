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
    pub lhm_status: String,
}

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use wmi::{COMLibrary, WMIConnection};

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct WmiSensor {
        name: String,
        parent: String,
        value: f64,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct AcpiThermalZone {
        current_temperature: u32,
    }

    fn round1(v: f64) -> f64 {
        (v * 10.0).round() / 10.0
    }

    fn classify(name: &str, parent: &str) -> &'static str {
        let nl = name.to_lowercase();
        let pl = parent.to_lowercase();

        // GPU keywords checked BEFORE CPU to prevent AMD Radeon misclassification
        let gpu_kw = ["radeon", "nvidia", "gpu", "video", "hot spot", "junction", "edge"];
        if gpu_kw.iter().any(|k| pl.contains(k) || nl.contains(k)) {
            return "GPU";
        }

        let cpu_kw = ["cpu", "processor", "amd", "intel", "core", "ccd", "tctl", "tdie", "package"];
        if cpu_kw.iter().any(|k| pl.contains(k) || nl.contains(k)) {
            return "CPU";
        }

        let disk_kw = ["hdd", "ssd", "nvme", "disk", "storage", "drive", "assembly"];
        if disk_kw.iter().any(|k| pl.contains(k) || nl.contains(k)) {
            return "Disk";
        }

        "Other"
    }

    fn default_thresholds(cat: &str) -> (Option<f64>, Option<f64>) {
        match cat {
            "CPU" => (Some(95.0), Some(105.0)),
            "GPU" => (Some(93.0), Some(100.0)),
            "Disk" => (Some(70.0), Some(75.0)),
            _ => (None, None),
        }
    }

    fn try_wmi_namespace(ns: &str) -> Option<Vec<WmiSensor>> {
        let com = COMLibrary::new().ok()?;
        let conn = WMIConnection::with_namespace_path(ns, com.into()).ok()?;
        let sensors: Vec<WmiSensor> = conn.raw_query(
            "SELECT Name, Parent, Value FROM Sensor WHERE SensorType = 'Temperature'"
        ).ok()?;
        if sensors.is_empty() { None } else { Some(sensors) }
    }

    fn probe_lhm() -> Option<Vec<TempReading>> {
        let sensors = try_wmi_namespace("root\\LibreHardwareMonitor")
            .or_else(|| try_wmi_namespace("root\\OpenHardwareMonitor"))?;

        let mut readings = Vec::new();
        for s in &sensors {
            let cat = classify(&s.name, &s.parent);
            if cat == "Disk" {
                continue;
            }
            let (max_c, critical_c) = default_thresholds(cat);
            readings.push(TempReading {
                sensor: s.name.clone(),
                category: cat.to_string(),
                temperature_c: round1(s.value),
                max_c,
                critical_c,
            });
        }
        Some(readings)
    }

    fn probe_nvidia_smi() -> Vec<TempReading> {
        let out = optimizer_core::silent_cmd("nvidia-smi")
            .args(["--query-gpu=temperature.gpu,name", "--format=csv,noheader,nounits"])
            .output();
        let output = match out {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
            _ => return Vec::new(),
        };
        let mut readings = Vec::new();
        for line in output.lines() {
            let parts: Vec<&str> = line.split(',').map(str::trim).collect();
            if parts.len() >= 2 {
                if let Ok(temp) = parts[0].parse::<f64>() {
                    readings.push(TempReading {
                        sensor: parts[1].to_string(),
                        category: "GPU".into(),
                        temperature_c: round1(temp),
                        max_c: Some(93.0),
                        critical_c: Some(100.0),
                    });
                }
            }
        }
        readings
    }

    fn probe_acpi() -> Vec<TempReading> {
        let com = match COMLibrary::new() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        let conn = match WMIConnection::with_namespace_path("root\\wmi", com.into()) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        let zones: Vec<AcpiThermalZone> = match conn.raw_query(
            "SELECT CurrentTemperature FROM MSAcpi_ThermalZoneTemperature"
        ) {
            Ok(z) => z,
            Err(_) => return Vec::new(),
        };

        let mut readings = Vec::new();
        for z in &zones {
            if z.current_temperature > 0 {
                let temp_c = round1((z.current_temperature as f64 - 2732.0) / 10.0);
                if temp_c > 0.0 && temp_c < 150.0 {
                    readings.push(TempReading {
                        sensor: "CPU (ACPI)".into(),
                        category: "CPU".into(),
                        temperature_c: temp_c,
                        max_c: Some(95.0),
                        critical_c: Some(105.0),
                    });
                }
            }
        }
        readings
    }

    pub fn collect_temps_impl() -> TempReport {
        if let Some(readings) = probe_lhm() {
            return TempReport {
                readings,
                warnings: Vec::new(),
                lhm_status: "active".into(),
            };
        }

        // LHM not available - fall back to individual probes
        let mut readings = Vec::new();

        readings.extend(probe_nvidia_smi());
        readings.extend(probe_acpi());

        let mut warnings = Vec::new();

        let has_cpu = readings.iter().any(|r| r.category == "CPU");
        let has_gpu = readings.iter().any(|r| r.category == "GPU");

        if !has_cpu && !has_gpu {
            warnings.push(
                "CPU and GPU temps require Libre Hardware Monitor (free, lightweight). \
                 Disk temps are read directly from drive firmware.".into()
            );
        } else if !has_cpu {
            warnings.push("CPU temp requires Libre Hardware Monitor (free, lightweight).".into());
        } else if !has_gpu {
            warnings.push("GPU temp requires Libre Hardware Monitor or manufacturer software.".into());
        }

        if readings.is_empty() {
            warnings.push(
                "No temperature sensors detected. Install Libre Hardware Monitor (free) \
                 for CPU, GPU, and disk temps.".into()
            );
        }

        TempReport {
            readings,
            warnings,
            lhm_status: "not_found".into(),
        }
    }
}

#[cfg(target_os = "windows")]
pub fn collect_temps() -> TempReport {
    windows::collect_temps_impl()
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
        lhm_status: "active".into(),
    }
}

// ---------------------------------------------------------------------------
// LHM launcher - find, detect, and launch LibreHardwareMonitor
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
pub mod lhm_launcher {
    use std::path::{Path, PathBuf};

    pub fn is_lhm_running() -> bool {
        use sysinfo::System;
        let mut sys = System::new();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        sys.processes().values().any(|p| {
            let name = p.name().to_string_lossy().to_lowercase();
            name == "librehardwaremonitor.exe" || name == "librehardwaremonitor"
        })
    }

    pub fn find_lhm_exe(resource_dir: &Path) -> Option<PathBuf> {
        let bundled = resource_dir.join("lhm").join("LibreHardwareMonitor.exe");
        if bundled.exists() {
            return Some(bundled);
        }

        let program_files = std::env::var("ProgramFiles").unwrap_or_default();
        if !program_files.is_empty() {
            let pf = PathBuf::from(&program_files)
                .join("LibreHardwareMonitor")
                .join("LibreHardwareMonitor.exe");
            if pf.exists() {
                return Some(pf);
            }
        }

        let program_files_x86 = std::env::var("ProgramFiles(x86)").unwrap_or_default();
        if !program_files_x86.is_empty() {
            let pf86 = PathBuf::from(&program_files_x86)
                .join("LibreHardwareMonitor")
                .join("LibreHardwareMonitor.exe");
            if pf86.exists() {
                return Some(pf86);
            }
        }

        None
    }

    pub fn launch_lhm(exe_path: &Path) -> Result<(), String> {
        // LHM is a WinForms GUI app - CREATE_NO_WINDOW only hides consoles.
        // Use PowerShell Start-Process -WindowStyle Hidden to suppress the window.
        optimizer_core::silent_cmd("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!("Start-Process '{}' -WindowStyle Hidden", exe_path.display()),
            ])
            .spawn()
            .map(|_| ())
            .map_err(|e| format!("Failed to launch LHM: {}", e))
    }

    pub fn ensure_lhm_running(resource_dir: &Path) -> Result<String, String> {
        if is_lhm_running() {
            return Ok("active".into());
        }

        let exe = match find_lhm_exe(resource_dir) {
            Some(p) => p,
            None => return Ok("not_found".into()),
        };

        launch_lhm(&exe)?;
        std::thread::sleep(std::time::Duration::from_secs(2));

        if is_lhm_running() {
            Ok("active".into())
        } else {
            Ok("starting".into())
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub mod lhm_launcher {
    use std::path::{Path, PathBuf};

    pub fn is_lhm_running() -> bool {
        true
    }

    pub fn find_lhm_exe(_resource_dir: &Path) -> Option<PathBuf> {
        Some(PathBuf::from("/mock/LibreHardwareMonitor.exe"))
    }

    pub fn launch_lhm(_exe_path: &Path) -> Result<(), String> {
        Ok(())
    }

    pub fn ensure_lhm_running(_resource_dir: &Path) -> Result<String, String> {
        Ok("active".into())
    }
}
