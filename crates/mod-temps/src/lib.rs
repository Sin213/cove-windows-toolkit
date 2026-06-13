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

    // This LHM build reads CPU temperatures exclusively through the PawnIO kernel
    // driver (the embedded WinRing0 path is gone, and Win11's Vulnerable Driver
    // Blocklist blocks WinRing0 anyway). PawnIO must therefore be installed on the
    // machine or CPU sensors come back empty. We bundle the official signed setup
    // (namazso.eu, github.com/namazso/PawnIO.Setup) and install it on first run.
    const PAWNIO_SETUP: &[u8] = include_bytes!("../resources/PawnIO_setup.exe");

    /// True if the PawnIO kernel driver service is registered on this machine.
    fn pawnio_installed() -> bool {
        optimizer_core::silent_cmd("sc")
            .args(["query", "PawnIO"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Outcome of ensuring the PawnIO driver is present.
    enum PawnIo {
        /// Driver was already installed before this call.
        AlreadyPresent,
        /// Driver was just installed this run. A fresh install reports exit 3010
        /// (reboot-required), so CPU sensors may not read until Cove (or the PC)
        /// is restarted.
        JustInstalled,
    }

    /// Message shown when the driver was just installed but CPU temps aren't
    /// readable yet (the fresh driver needs a restart to come up).
    const RESTART_MSG: &str =
        "CPU temperature driver (PawnIO) was just installed. Restart Cove to enable CPU temperature readings.";

    /// Install the bundled PawnIO driver if it isn't already present. Requires
    /// admin (the app ships with a requireAdministrator manifest). The silent
    /// switch `-install -silent` is the official one — winget installs
    /// namazso.PawnIO unattended with exactly this.
    fn ensure_pawnio_installed() -> Result<PawnIo, String> {
        if pawnio_installed() {
            return Ok(PawnIo::AlreadyPresent);
        }
        let setup = std::env::temp_dir().join("cove-pawnio-setup.exe");
        std::fs::write(&setup, PAWNIO_SETUP)
            .map_err(|e| format!("Failed to stage PawnIO installer: {e}"))?;
        let result = optimizer_core::silent_cmd(&setup.to_string_lossy())
            .args(["-install", "-silent"])
            .output();
        let _ = std::fs::remove_file(&setup);
        let output = result.map_err(|e| format!("Failed to run PawnIO installer: {e}"))?;
        // A fresh install exits 3010 (reboot-required); trust the service
        // registration as the real signal rather than the exit code alone.
        if pawnio_installed() {
            Ok(PawnIo::JustInstalled)
        } else {
            Err(format!(
                "PawnIO installer ran but the driver is not registered (exit {:?}). CPU temperature requires the PawnIO driver.",
                output.status.code()
            ))
        }
    }

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

    fn build_sensor_script(lhm_dir: &str) -> String {
        format!(r#"
$ErrorActionPreference = 'Stop'
$lhmDir = '{lhm_dir}'

# LHM P/Invokes PawnIOLib.dll to reach the kernel driver. After a fresh install
# the PawnIO dir is on the machine PATH, but this process inherited the app's
# PATH from launch (pre-install), so prepend it here to resolve on the first run.
$pawnioDir = Join-Path $env:ProgramFiles 'PawnIO'
if (Test-Path $pawnioDir) {{ $env:PATH = "$pawnioDir;$env:PATH" }}

[System.Reflection.Assembly]::LoadFrom("$lhmDir\LibreHardwareMonitorLib.dll") | Out-Null

$computer = [LibreHardwareMonitor.Hardware.Computer]::new()
$computer.IsCpuEnabled = $true
$computer.IsGpuEnabled = $true
$computer.IsMotherboardEnabled = $true
$computer.IsStorageEnabled = $false
$computer.Open()

$readings = @()
foreach ($hw in $computer.Hardware) {{
    $hw.Update()
    foreach ($sub in $hw.SubHardware) {{ $sub.Update() }}
    foreach ($sensor in $hw.Sensors) {{
        if ($sensor.SensorType -ne [LibreHardwareMonitor.Hardware.SensorType]::Temperature) {{ continue }}
        if (-not $sensor.Value) {{ continue }}
        $val = [math]::Round($sensor.Value, 1)
        if ($val -le 0 -or $val -ge 150) {{ continue }}

        $ht = $hw.HardwareType.ToString()
        $cat = 'Other'
        $maxC = $null; $critC = $null
        if ($ht -match 'Cpu') {{ $cat = 'CPU'; $maxC = 95.0; $critC = 105.0 }}
        elseif ($ht -match 'Gpu') {{ $cat = 'GPU'; $maxC = 93.0; $critC = 100.0 }}

        $readings += @{{
            sensor = $sensor.Name
            category = $cat
            temperature_c = $val
            max_c = $maxC
            critical_c = $critC
        }}
    }}
}}
$computer.Close()

@{{ readings = $readings; warnings = @(); lhm_status = 'active' }} | ConvertTo-Json -Depth 3 -Compress
"#, lhm_dir = lhm_dir)
    }

    fn probe_lhm_dll() -> Result<TempReport, String> {
        let dir = extract_lhm_if_needed()
            .ok_or_else(|| "Failed to extract sensor library".to_string())?;

        let dir_str = dir.display().to_string();
        let dll_path = dir.join("LibreHardwareMonitorLib.dll");

        if !dll_path.exists() {
            return Err(format!("DLL not found at: {}", dll_path.display()));
        }

        let script = build_sensor_script(&dir_str);

        let output = optimizer_core::silent_cmd("powershell")
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &script])
            .output()
            .map_err(|e| format!("PowerShell failed: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Sensor query failed (dir={}): {}", dir_str, stderr.trim()));
        }

        let json = String::from_utf8_lossy(&output.stdout);
        serde_json::from_str::<TempReport>(json.trim())
            .map_err(|e| format!("JSON parse error: {} - raw: {}", e, json.trim()))
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
        // CPU temps need the PawnIO driver; install it on first run if missing.
        // Keep the outcome so we can explain an empty CPU result instead of failing
        // silently (the classic "works only on the dev's machine" symptom).
        let (just_installed, pawnio_err) = match ensure_pawnio_installed() {
            Ok(PawnIo::AlreadyPresent) => (false, None),
            Ok(PawnIo::JustInstalled) => (true, None),
            Err(e) => (false, Some(e)),
        };

        // Explain an absent CPU reading: a failed install, or a just-installed
        // driver that needs a restart to come up.
        let cpu_note = |readings: &[TempReading]| -> Option<String> {
            if readings.iter().any(|r| r.category == "CPU") {
                None
            } else if let Some(pe) = &pawnio_err {
                Some(pe.clone())
            } else if just_installed {
                Some(RESTART_MSG.to_string())
            } else {
                None
            }
        };

        match probe_lhm_dll() {
            Ok(report) if !report.readings.is_empty() => return report,
            Ok(_) => {
                // DLL loaded but reported no sensors - fall through to fallbacks
            }
            Err(e) => {
                eprintln!("LHM DLL probe failed: {}", e);
                // Try fallbacks, but include the error so user can report it
                let mut fallback = try_fallback_probes();
                if fallback.readings.is_empty() {
                    fallback.warnings.push(format!("Sensor library error: {}", e));
                }
                if let Some(note) = cpu_note(&fallback.readings) {
                    fallback.warnings.push(note);
                }
                return fallback;
            }
        }

        let mut fallback = try_fallback_probes();
        if let Some(note) = cpu_note(&fallback.readings) {
            fallback.warnings.push(note);
        }
        fallback
    }

    fn try_fallback_probes() -> TempReport {
        let mut readings = Vec::new();
        readings.extend(probe_nvidia_smi());
        readings.extend(probe_acpi());

        let warnings = if readings.is_empty() {
            vec!["No temperature sensors detected.".into()]
        } else {
            Vec::new()
        };

        TempReport {
            readings,
            warnings,
            lhm_status: "fallback".into(),
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
