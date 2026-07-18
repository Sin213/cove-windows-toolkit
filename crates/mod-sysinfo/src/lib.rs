use serde::{Deserialize, Serialize};

mod link;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FullSystemInfo {
    #[serde(default)]
    pub complete: bool,
    #[serde(default)]
    pub errors: Vec<String>,
    pub os: OsInfo,
    pub cpu: CpuInfo,
    pub ram: RamInfo,
    pub motherboard: MotherboardInfo,
    pub graphics: Vec<GpuInfo>,
    pub monitors: Vec<MonitorInfo>,
    pub storage: Vec<DriveInfo>,
    pub audio: Vec<AudioDevice>,
    pub network: Vec<NetworkAdapter>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OsInfo {
    pub name: String,
    pub version: String,
    pub build: String,
    pub arch: String,
    pub install_date: String,
    pub last_boot: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CpuInfo {
    pub name: String,
    pub cores: u32,
    pub threads: u32,
    pub base_clock_mhz: u32,
    pub max_clock_mhz: u32,
    pub architecture: String,
    pub temperature_c: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RamInfo {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub speed_mhz: u32,
    pub slots_used: u32,
    pub slots_total: u32,
    pub ram_type: String,
    pub modules: Vec<RamModule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RamModule {
    pub capacity_bytes: u64,
    pub speed_mhz: u32,
    pub manufacturer: String,
    pub part_number: String,
    pub slot: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MotherboardInfo {
    pub manufacturer: String,
    pub product: String,
    pub serial: String,
    pub bios_vendor: String,
    pub bios_version: String,
    pub bios_date: String,
    #[serde(default)]
    pub product_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GpuInfo {
    pub name: String,
    pub driver_version: String,
    pub vram_bytes: u64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MonitorInfo {
    pub name: String,
    pub resolution: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DriveInfo {
    pub model: String,
    pub interface_type: String,
    pub media_type: String,
    pub size_bytes: u64,
    pub partitions: Vec<PartitionInfo>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PartitionInfo {
    pub letter: String,
    pub label: String,
    pub size_bytes: u64,
    pub free_bytes: u64,
    pub filesystem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AudioDevice {
    pub name: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkAdapter {
    pub name: String,
    pub adapter_type: String,
    pub mac: String,
    pub speed: String,
    pub ip: String,
    pub status: String,
}

#[cfg(target_os = "windows")]
pub fn collect() -> FullSystemInfo {
    let json = run_ps(include_str!("gather.ps1"));
    match serde_json::from_str::<FullSystemInfo>(&json) {
        Ok(mut info) => {
            enrich(&mut info);
            info
        }
        Err(e) => {
            eprintln!("sysinfo parse error: {e}\n{json}");
            FullSystemInfo {
                complete: false,
                errors: vec![format!("System information parse failed: {e}")],
                ..Default::default()
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn collect() -> FullSystemInfo {
    let mut info = stub_info();
    enrich(&mut info);
    info
}

/// Post-processing applied to collected data on every platform.
fn enrich(info: &mut FullSystemInfo) {
    info.motherboard.product_url =
        link::motherboard_product_url(&info.motherboard.manufacturer, &info.motherboard.product);
}

#[cfg(target_os = "windows")]
fn run_ps(script: &str) -> String {
    let out = optimizer_core::powershell(script).output();
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        Err(e) => format!("{{\"error\":\"{e}\"}}"),
    }
}

#[cfg(not(target_os = "windows"))]
fn stub_info() -> FullSystemInfo {
    FullSystemInfo {
        complete: true,
        errors: Vec::new(),
        os: OsInfo {
            name: "Windows 11 Pro".into(),
            version: "23H2".into(),
            build: "22631.2506".into(),
            arch: "64-bit".into(),
            install_date: "2024-01-15".into(),
            last_boot: "2026-06-09T08:30:00".into(),
        },
        cpu: CpuInfo {
            name: "Intel Core i7-12700K".into(),
            cores: 12,
            threads: 20,
            base_clock_mhz: 3600,
            max_clock_mhz: 5000,
            architecture: "x64".into(),
            temperature_c: Some(52.0),
        },
        ram: RamInfo {
            total_bytes: 34_359_738_368,
            available_bytes: 18_000_000_000,
            speed_mhz: 3200,
            slots_used: 2,
            slots_total: 4,
            ram_type: "DDR4".into(),
            modules: vec![
                RamModule {
                    capacity_bytes: 17_179_869_184,
                    speed_mhz: 3200,
                    manufacturer: "Corsair".into(),
                    part_number: "CMK32GX4M2E3200C16".into(),
                    slot: "DIMM 1".into(),
                },
                RamModule {
                    capacity_bytes: 17_179_869_184,
                    speed_mhz: 3200,
                    manufacturer: "Corsair".into(),
                    part_number: "CMK32GX4M2E3200C16".into(),
                    slot: "DIMM 3".into(),
                },
            ],
        },
        motherboard: MotherboardInfo {
            manufacturer: "ASUSTeK COMPUTER INC.".into(),
            product: "PRIME B650M-A AX6 II".into(),
            serial: "XXXXXXXXXXXX".into(),
            bios_vendor: "American Megatrends Inc.".into(),
            bios_version: "3067".into(),
            bios_date: "2025-08-15".into(),
            product_url: None,
        },
        graphics: vec![GpuInfo {
            name: "NVIDIA GeForce RTX 3070".into(),
            driver_version: "537.70".into(),
            vram_bytes: 8_589_934_592,
            status: "OK".into(),
        }],
        monitors: vec![MonitorInfo {
            name: "Generic PnP Monitor".into(),
            resolution: "2560x1440@165Hz".into(),
        }],
        storage: vec![DriveInfo {
            model: "Samsung SSD 980 PRO 1TB".into(),
            interface_type: "NVMe".into(),
            media_type: "SSD".into(),
            size_bytes: 1_000_204_886_016,
            status: "OK".into(),
            partitions: vec![
                PartitionInfo {
                    letter: "C:".into(),
                    label: "Windows".into(),
                    size_bytes: 500_000_000_000,
                    free_bytes: 185_000_000_000,
                    filesystem: "NTFS".into(),
                },
                PartitionInfo {
                    letter: "D:".into(),
                    label: "Data".into(),
                    size_bytes: 499_000_000_000,
                    free_bytes: 320_000_000_000,
                    filesystem: "NTFS".into(),
                },
            ],
        }],
        audio: vec![AudioDevice {
            name: "Realtek High Definition Audio".into(),
            status: "OK".into(),
        }],
        network: vec![
            NetworkAdapter {
                name: "Intel Wi-Fi 6 AX200".into(),
                adapter_type: "Wi-Fi".into(),
                mac: "A4:BB:6D:0C:3E:91".into(),
                speed: "866 Mbps".into(),
                ip: "192.168.1.105".into(),
                status: "Connected".into(),
            },
            NetworkAdapter {
                name: "Intel I225-V".into(),
                adapter_type: "Ethernet".into(),
                mac: "9C:2F:9D:B1:44:E2".into(),
                speed: "2.5 Gbps".into(),
                ip: "".into(),
                status: "Disconnected".into(),
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn motherboard_deserializes_without_product_url() {
        // Shape of the object gather.ps1 emits: no product_url field.
        let json = r#"{
            "manufacturer": "ASUSTeK COMPUTER INC.",
            "product": "PRIME B650M-A AX6 II",
            "serial": "123",
            "bios_vendor": "American Megatrends Inc.",
            "bios_version": "3067",
            "bios_date": "2025-08-15"
        }"#;
        let mb: MotherboardInfo = serde_json::from_str(json).unwrap();
        assert_eq!(mb.product_url, None);
    }

    #[test]
    fn motherboard_serializes_none_as_null() {
        let v = serde_json::to_value(MotherboardInfo::default()).unwrap();
        assert!(v["product_url"].is_null());
    }

    #[test]
    fn full_sysinfo_roundtrip_with_product_url() {
        let info = FullSystemInfo {
            motherboard: MotherboardInfo {
                product_url: Some("https://example.com/board/".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: FullSystemInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.motherboard.product_url.as_deref(),
            Some("https://example.com/board/")
        );
    }
}
