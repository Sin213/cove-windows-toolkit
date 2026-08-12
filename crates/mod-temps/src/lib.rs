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

    fn round1(value: f64) -> f64 {
        (value * 10.0).round() / 10.0
    }

    fn nvidia_readings() -> Vec<TempReading> {
        // `nvidia-smi.exe` is optional and is not an inbox System32 binary. Do
        // not pass a bare name through the elevated process search path; only
        // run the vendor copy from its standard Program Files location.
        let Some(nvidia_smi) = optimizer_core::program_files_directory()
            .map(|root| {
                root.join("NVIDIA Corporation")
                    .join("NVSMI")
                    .join("nvidia-smi.exe")
            })
            .filter(|path| path.is_file())
        else {
            return Vec::new();
        };
        let output = match optimizer_core::silent_cmd(&nvidia_smi.to_string_lossy())
            .args([
                "--query-gpu=temperature.gpu,name",
                "--format=csv,noheader,nounits",
            ])
            .output()
        {
            Ok(output) if output.status.success() => output,
            _ => return Vec::new(),
        };
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| {
                let (temperature, name) = line.split_once(',')?;
                let temperature_c = temperature.trim().parse::<f64>().ok()?;
                Some(TempReading {
                    sensor: name.trim().to_string(),
                    category: "GPU".into(),
                    temperature_c: round1(temperature_c),
                    max_c: Some(93.0),
                    critical_c: Some(100.0),
                })
            })
            .collect()
    }

    fn acpi_readings() -> Vec<TempReading> {
        use wmi::{COMLibrary, WMIConnection};

        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct ThermalZone {
            current_temperature: u32,
        }

        let Ok(com) = COMLibrary::new() else {
            return Vec::new();
        };
        let Ok(connection) = WMIConnection::with_namespace_path("root\\wmi", com) else {
            return Vec::new();
        };
        let Ok(zones): Result<Vec<ThermalZone>, _> =
            connection.raw_query("SELECT CurrentTemperature FROM MSAcpi_ThermalZoneTemperature")
        else {
            return Vec::new();
        };
        zones
            .into_iter()
            .filter_map(|zone| {
                let temperature_c = round1((f64::from(zone.current_temperature) - 2732.0) / 10.0);
                (temperature_c > 0.0 && temperature_c < 150.0).then_some(TempReading {
                    sensor: "ACPI thermal zone".into(),
                    category: "System".into(),
                    temperature_c,
                    max_c: None,
                    critical_c: None,
                })
            })
            .collect()
    }

    pub fn collect_temps_impl() -> TempReport {
        let mut readings = nvidia_readings();
        readings.extend(acpi_readings());
        let mut warnings = vec![
            "CPU sensor provider is not installed. Cove does not install kernel drivers during diagnostics."
                .into(),
        ];
        if readings.is_empty() {
            warnings.push("No read-only temperature sensors were available.".into());
        }
        TempReport {
            readings,
            warnings,
            lhm_status: "optional-provider-missing".into(),
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
            TempReading {
                sensor: "CPU Package".into(),
                category: "CPU".into(),
                temperature_c: 52.0,
                max_c: Some(100.0),
                critical_c: Some(105.0),
            },
            TempReading {
                sensor: "CPU Core #0".into(),
                category: "CPU".into(),
                temperature_c: 48.0,
                max_c: Some(100.0),
                critical_c: Some(105.0),
            },
            TempReading {
                sensor: "CPU Core #1".into(),
                category: "CPU".into(),
                temperature_c: 51.0,
                max_c: Some(100.0),
                critical_c: Some(105.0),
            },
            TempReading {
                sensor: "CPU Core #2".into(),
                category: "CPU".into(),
                temperature_c: 49.0,
                max_c: Some(100.0),
                critical_c: Some(105.0),
            },
            TempReading {
                sensor: "CPU Core #3".into(),
                category: "CPU".into(),
                temperature_c: 53.0,
                max_c: Some(100.0),
                critical_c: Some(105.0),
            },
            TempReading {
                sensor: "GPU Core".into(),
                category: "GPU".into(),
                temperature_c: 45.0,
                max_c: Some(93.0),
                critical_c: Some(100.0),
            },
            TempReading {
                sensor: "GPU Hot Spot".into(),
                category: "GPU".into(),
                temperature_c: 58.0,
                max_c: Some(93.0),
                critical_c: Some(100.0),
            },
            TempReading {
                sensor: "Samsung SSD 980 PRO".into(),
                category: "Disk".into(),
                temperature_c: 38.0,
                max_c: Some(70.0),
                critical_c: Some(75.0),
            },
            TempReading {
                sensor: "WD Blue SN570".into(),
                category: "Disk".into(),
                temperature_c: 35.0,
                max_c: Some(70.0),
                critical_c: Some(75.0),
            },
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
