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
    /// State of the CPU sensor provider, which the panel uses to decide whether
    /// to offer the driver opt-in. One of [`CPU_PROVIDER_ACTIVE`],
    /// [`CPU_PROVIDER_DRIVER_MISSING`], or [`CPU_PROVIDER_ERROR`].
    pub lhm_status: String,
}

/// CPU sensors are readable.
pub const CPU_PROVIDER_ACTIVE: &str = "active";
/// The kernel-mode sensor driver is not installed; the UI may offer to install it.
pub const CPU_PROVIDER_DRIVER_MISSING: &str = "driver-missing";
/// The driver is present but the provider could not be queried.
pub const CPU_PROVIDER_ERROR: &str = "provider-error";

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use std::sync::OnceLock;

    use std::path::{Path, PathBuf};

    /// Sensor library used to read CPU (and, where available, GPU/motherboard)
    /// temperatures. MPL-2.0; see THIRD-PARTY-NOTICES.md.
    const LHM_BUNDLE: &[u8] = include_bytes!("../resources/LibreHardwareMonitor.zip");
    /// Signed installer for the PawnIO kernel driver the sensor library needs to
    /// reach CPU registers. Only ever run from [`install_cpu_driver`], which is
    /// reachable exclusively through an explicit user action.
    const PAWNIO_SETUP: &[u8] = include_bytes!("../resources/PawnIO_setup.exe");

    fn round1(value: f64) -> f64 {
        (value * 10.0).round() / 10.0
    }

    /// A staging directory under `%SystemRoot%\Temp`, which only administrators
    /// can write to. The per-user temp directory is writable by medium-integrity
    /// processes, so staging an executable or a DLL there and then running or
    /// loading it from this elevated process would hand out an escalation.
    fn admin_only_staging_dir(name: &str) -> Result<PathBuf, String> {
        let directory = optimizer_core::windows_directory().join("Temp").join(name);
        std::fs::create_dir_all(&directory)
            .map_err(|error| format!("Could not create {}: {error}", directory.display()))?;
        Ok(directory)
    }

    /// True when the PawnIO kernel driver service is registered on this machine.
    /// Cove never installs it implicitly - see [`install_cpu_driver`].
    pub fn pawnio_installed() -> bool {
        optimizer_core::silent_cmd("sc")
            .args(["query", "PawnIO"])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Unpack the sensor library next to nothing else, into the admin-only
    /// staging directory. Returns the directory holding
    /// `LibreHardwareMonitorLib.dll`.
    fn ensure_lhm_extracted() -> Result<PathBuf, String> {
        let directory = admin_only_staging_dir("cove-lhm")?;
        if directory.join("LibreHardwareMonitorLib.dll").is_file() {
            return Ok(directory);
        }
        let archive = directory.join("bundle.zip");
        std::fs::write(&archive, LHM_BUNDLE)
            .map_err(|error| format!("Could not stage the sensor library: {error}"))?;
        let output = optimizer_core::powershell(&format!(
            "Expand-Archive -Path '{}' -DestinationPath '{}' -Force",
            archive.display(),
            directory.display()
        ))
        .output()
        .map_err(|error| format!("Could not unpack the sensor library: {error}"))?;
        let _ = std::fs::remove_file(&archive);
        if !directory.join("LibreHardwareMonitorLib.dll").is_file() {
            return Err(format!(
                "The sensor library did not unpack: {}",
                optimizer_core::decode_console_output(&output.stderr).trim()
            ));
        }
        Ok(directory)
    }

    fn sensor_script(lhm_directory: &Path) -> String {
        format!(
            r#"
$ErrorActionPreference = 'Stop'
# LHM P/Invokes PawnIOLib.dll to reach the driver. This process inherited its
# PATH at launch, which may predate the driver install, so resolve it here.
$pawnio = Join-Path $env:ProgramFiles 'PawnIO'
if (Test-Path $pawnio) {{ $env:PATH = "$pawnio;$env:PATH" }}
[System.Reflection.Assembly]::LoadFrom('{dir}\LibreHardwareMonitorLib.dll') | Out-Null
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
        $value = [math]::Round($sensor.Value, 1)
        if ($value -le 0 -or $value -ge 150) {{ continue }}
        $type = $hw.HardwareType.ToString()
        $category = 'Other'; $max = $null; $critical = $null
        if ($type -match 'Cpu') {{ $category = 'CPU'; $max = 95.0; $critical = 105.0 }}
        elseif ($type -match 'Gpu') {{ $category = 'GPU'; $max = 93.0; $critical = 100.0 }}
        $readings += @{{ sensor = $sensor.Name; category = $category; temperature_c = $value; max_c = $max; critical_c = $critical }}
    }}
}}
$computer.Close()
@($readings) | ConvertTo-Json -Depth 3 -Compress
"#,
            dir = lhm_directory.display()
        )
    }

    /// Read sensors through the library. Requires the driver; callers check
    /// [`pawnio_installed`] first so a missing driver is reported as an opt-in
    /// prompt rather than an error.
    fn probe_lhm() -> Result<Vec<TempReading>, String> {
        let directory = ensure_lhm_extracted()?;
        // Needs -ExecutionPolicy Bypass to load the assembly, so the plain
        // helper does not fit; prepend the UTF-8 prelude by hand.
        let output = optimizer_core::silent_cmd("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                &format!(
                    "{}{}",
                    optimizer_core::PS_PRELUDE,
                    sensor_script(&directory)
                ),
            ])
            .output()
            .map_err(|error| format!("Could not run the sensor query: {error}"))?;
        if !output.status.success() {
            return Err(optimizer_core::decode_console_output(&output.stderr)
                .trim()
                .to_string());
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let text = text.trim();
        if text.is_empty() {
            return Ok(Vec::new());
        }
        // A single sensor serializes as an object rather than an array.
        serde_json::from_str::<Vec<TempReading>>(text)
            .or_else(|_| serde_json::from_str::<TempReading>(text).map(|one| vec![one]))
            .map_err(|error| format!("Could not read the sensor output: {error}"))
    }

    /// Cached so the panel's 3-second auto-refresh does not spawn a PowerShell
    /// host and re-open every sensor on each tick.
    fn cpu_provider_readings() -> Result<Vec<TempReading>, String> {
        type Cached =
            std::sync::Mutex<Option<(std::time::Instant, Result<Vec<TempReading>, String>)>>;
        const CACHE_FOR: std::time::Duration = std::time::Duration::from_secs(5);
        static CACHE: OnceLock<Cached> = OnceLock::new();

        let cache = CACHE.get_or_init(|| std::sync::Mutex::new(None));
        {
            let guard = cache.lock().unwrap_or_else(|error| error.into_inner());
            if let Some((fetched_at, result)) = guard.as_ref()
                && fetched_at.elapsed() < CACHE_FOR
            {
                return result.clone();
            }
        }
        let result = probe_lhm();
        let mut guard = cache.lock().unwrap_or_else(|error| error.into_inner());
        *guard = Some((std::time::Instant::now(), result.clone()));
        result
    }

    /// Install the bundled PawnIO driver. This is the only path that installs
    /// anything, and it must only ever be reached from an explicit user action -
    /// diagnostics never call it.
    pub fn install_cpu_driver() -> Result<String, String> {
        if pawnio_installed() {
            return Ok("The CPU sensor driver is already installed.".into());
        }
        let directory = admin_only_staging_dir("cove-pawnio")?;
        let setup = directory.join("PawnIO_setup.exe");
        std::fs::write(&setup, PAWNIO_SETUP)
            .map_err(|error| format!("Could not stage the driver installer: {error}"))?;
        // `-install -silent` is the vendor's unattended switch pair.
        let result = optimizer_core::silent_cmd(&setup.to_string_lossy())
            .args(["-install", "-silent"])
            .output();
        let _ = std::fs::remove_file(&setup);
        let output = result.map_err(|error| format!("Could not run the installer: {error}"))?;
        // A fresh install reports 3010 (reboot pending), so trust the service
        // registration rather than the exit code.
        if pawnio_installed() {
            Ok("CPU sensor driver installed. Restart Cove to read CPU temperatures.".into())
        } else {
            Err(format!(
                "The installer finished (exit {:?}) but the driver is not registered.",
                output.status.code()
            ))
        }
    }

    /// Absolute locations the NVIDIA driver installs `nvidia-smi.exe` into.
    /// Never resolved through the process search path: this runs elevated, and a
    /// bare name would be a writable-directory hijack. Since driver R450 the
    /// installer drops it in System32; the Program Files copy only exists on
    /// older drivers, so checking only there missed nearly every current
    /// machine and silently dropped GPU temperatures.
    fn nvidia_smi_path() -> Option<std::path::PathBuf> {
        let system32 = optimizer_core::system_executable("nvidia-smi.exe");
        let legacy = optimizer_core::program_files_directory().map(|root| {
            root.join("NVIDIA Corporation")
                .join("NVSMI")
                .join("nvidia-smi.exe")
        });
        [Some(system32), legacy]
            .into_iter()
            .flatten()
            .find(|path| path.is_file())
    }

    fn nvidia_readings() -> Vec<TempReading> {
        let Some(nvidia_smi) = nvidia_smi_path() else {
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

    /// Disk temperatures come from the storage driver's reliability counters,
    /// which `mod-diskhealth` already reads. The query costs a PowerShell round
    /// trip, so it is cached: the temps panel can auto-refresh every 3 seconds
    /// and disk temperatures move far slower than that.
    fn disk_readings() -> Vec<TempReading> {
        use std::sync::Mutex;
        use std::time::{Duration, Instant};

        type Cached = Mutex<Option<(Instant, Vec<TempReading>)>>;

        const CACHE_FOR: Duration = Duration::from_secs(20);
        static CACHE: OnceLock<Cached> = OnceLock::new();

        let cache = CACHE.get_or_init(|| Mutex::new(None));
        {
            let guard = cache.lock().unwrap_or_else(|error| error.into_inner());
            if let Some((fetched_at, readings)) = guard.as_ref()
                && fetched_at.elapsed() < CACHE_FOR
            {
                return readings.clone();
            }
        }

        let readings: Vec<TempReading> = mod_diskhealth::collect_drive_health()
            .drives
            .into_iter()
            .filter_map(|drive| {
                let temperature_c = f64::from(drive.temperature_c?);
                (temperature_c > 0.0 && temperature_c < 150.0).then(|| TempReading {
                    sensor: if drive.model.trim().is_empty() {
                        "Disk".to_string()
                    } else {
                        drive.model.trim().to_string()
                    },
                    category: "Disk".into(),
                    temperature_c: round1(temperature_c),
                    max_c: Some(70.0),
                    critical_c: Some(75.0),
                })
            })
            .collect();

        let mut guard = cache.lock().unwrap_or_else(|error| error.into_inner());
        *guard = Some((Instant::now(), readings.clone()));
        readings
    }

    pub fn collect_temps_impl() -> TempReport {
        let mut readings = Vec::new();
        let mut warnings = Vec::new();

        // CPU (and often GPU/motherboard) sensors, if the operator opted into
        // the driver. Never installed here.
        let status = if pawnio_installed() {
            match cpu_provider_readings() {
                Ok(provider_readings) if !provider_readings.is_empty() => {
                    readings.extend(provider_readings);
                    CPU_PROVIDER_ACTIVE
                }
                Ok(_) => {
                    warnings.push(
                        "The CPU sensor provider is installed but reported no sensors.".into(),
                    );
                    CPU_PROVIDER_ERROR
                }
                Err(error) => {
                    warnings.push(format!("CPU sensor provider error: {error}"));
                    CPU_PROVIDER_ERROR
                }
            }
        } else {
            warnings.push(
                "CPU temperatures need a kernel-mode sensor driver. Cove can install the signed \
                 PawnIO driver for you - it never installs one on its own."
                    .into(),
            );
            CPU_PROVIDER_DRIVER_MISSING
        };

        // The provider already covers the GPU on most machines; only fall back
        // to nvidia-smi when it did not report one.
        if !readings.iter().any(|reading| reading.category == "GPU") {
            readings.extend(nvidia_readings());
        }
        readings.extend(acpi_readings());
        readings.extend(disk_readings());

        if readings.is_empty() {
            warnings
                .push("No read-only temperature sensors were available on this machine.".into());
        }
        TempReport {
            readings,
            warnings,
            lhm_status: status.into(),
        }
    }
}

#[cfg(target_os = "windows")]
pub fn collect_temps() -> TempReport {
    windows::collect_temps_impl()
}

/// Install the bundled CPU sensor driver. Call only in response to an explicit
/// user action: this is the one place in Cove that installs a kernel driver.
#[cfg(target_os = "windows")]
pub fn install_cpu_sensor_driver() -> Result<String, String> {
    windows::install_cpu_driver()
}

#[cfg(not(target_os = "windows"))]
pub fn install_cpu_sensor_driver() -> Result<String, String> {
    Err("The CPU sensor driver is only available on Windows.".into())
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
