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

    const LHM_ZIP: &[u8] = include_bytes!("../resources/LibreHardwareMonitor.zip");

    fn lhm_dir() -> Option<std::path::PathBuf> {
        let local_app = std::env::var("LOCALAPPDATA").ok()?;
        Some(std::path::PathBuf::from(local_app).join("CoveToolkit").join("lhm"))
    }

    fn extract_lhm_if_needed() -> Option<std::path::PathBuf> {
        let dir = lhm_dir()?;
        if dir.join("LibreHardwareMonitorLib.dll").exists() {
            return Some(dir);
        }

        let zip_path = std::env::temp_dir().join("cove-lhm-bundle.zip");
        std::fs::write(&zip_path, LHM_ZIP).ok()?;
        std::fs::create_dir_all(&dir).ok()?;

        let output = optimizer_core::silent_cmd("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "Expand-Archive -Path '{}' -DestinationPath '{}' -Force",
                    zip_path.display(),
                    dir.display()
                ),
            ])
            .output()
            .ok()?;

        let _ = std::fs::remove_file(&zip_path);

        if output.status.success() && dir.join("LibreHardwareMonitorLib.dll").exists() {
            Some(dir)
        } else {
            None
        }
    }

    // Load LibreHardwareMonitorLib.dll directly via PowerShell - no GUI, no tray icon
    const LHM_SENSOR_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$lhmDir = $args[0]
Add-Type -Path "$lhmDir\LibreHardwareMonitorLib.dll"
$computer = [LibreHardwareMonitor.Hardware.Computer]::new()
$computer.IsCpuEnabled = $true
$computer.IsGpuEnabled = $true
$computer.IsMotherboardEnabled = $true
$computer.IsStorageEnabled = $false
$computer.Open()

$readings = @()
foreach ($hw in $computer.Hardware) {
    $hw.Update()
    foreach ($sub in $hw.SubHardware) { $sub.Update() }
    foreach ($sensor in $hw.Sensors) {
        if ($sensor.SensorType -ne [LibreHardwareMonitor.Hardware.SensorType]::Temperature) { continue }
        if (-not $sensor.Value) { continue }
        $val = [math]::Round($sensor.Value, 1)
        if ($val -le 0 -or $val -ge 150) { continue }

        $ht = $hw.HardwareType.ToString()
        $cat = 'Other'
        $maxC = $null; $critC = $null
        if ($ht -match 'Cpu') { $cat = 'CPU'; $maxC = 95.0; $critC = 105.0 }
        elseif ($ht -match 'Gpu') { $cat = 'GPU'; $maxC = 93.0; $critC = 100.0 }

        $readings += @{
            sensor = $sensor.Name
            category = $cat
            temperature_c = $val
            max_c = $maxC
            critical_c = $critC
        }
    }
}
$computer.Close()

@{ readings = $readings; warnings = @(); lhm_status = 'active' } | ConvertTo-Json -Depth 3 -Compress
"#;

    fn probe_lhm_dll() -> Option<TempReport> {
        let dir = extract_lhm_if_needed()?;

        let output = optimizer_core::silent_cmd("powershell")
            .args([
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-Command",
                LHM_SENSOR_SCRIPT,
                &dir.display().to_string(),
            ])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let json = String::from_utf8_lossy(&output.stdout);
        serde_json::from_str::<TempReport>(json.trim()).ok()
    }

    fn round1(v: f64) -> f64 {
        (v * 10.0).round() / 10.0
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
        use wmi::{COMLibrary, WMIConnection};

        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct AcpiThermalZone {
            current_temperature: u32,
        }

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
        // Primary: load LHM DLL directly (no GUI, no tray icon)
        if let Some(report) = probe_lhm_dll() {
            if !report.readings.is_empty() {
                return report;
            }
        }

        // Fallback: nvidia-smi + ACPI
        let mut readings = Vec::new();
        readings.extend(probe_nvidia_smi());
        readings.extend(probe_acpi());

        let mut warnings = Vec::new();
        let has_cpu = readings.iter().any(|r| r.category == "CPU");
        let has_gpu = readings.iter().any(|r| r.category == "GPU");

        if !has_cpu && !has_gpu {
            warnings.push(
                "CPU and GPU temps unavailable. Run as Administrator for full sensor access.".into()
            );
        } else if !has_cpu {
            warnings.push("CPU temp unavailable. Run as Administrator for full sensor access.".into());
        } else if !has_gpu {
            warnings.push("GPU temp unavailable via fallback probes.".into());
        }

        if readings.is_empty() {
            warnings.push("No temperature sensors detected. Run as Administrator for full access.".into());
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

// No longer launches LHM GUI - the DLL is loaded directly in collect_temps
pub mod lhm_launcher {
    pub fn is_lhm_running() -> bool {
        false
    }

    pub fn ensure_lhm_running() -> Result<String, String> {
        Ok("active".into())
    }
}
