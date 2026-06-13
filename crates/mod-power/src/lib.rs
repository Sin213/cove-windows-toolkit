use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct PowerPlan {
    pub name: String,
    pub guid: String,
    pub active: bool,
}

#[derive(Serialize)]
pub struct PowerInfo {
    pub current_plan: String,
    pub current_guid: String,
    pub available_plans: Vec<PowerPlan>,
    pub display_off_minutes: u32,
    pub sleep_minutes: u32,
    pub hdd_sleep_minutes: u32,
}

#[cfg(target_os = "windows")]
pub fn get_info() -> PowerInfo {
    

    let mut info = PowerInfo {
        current_plan: "Unknown".into(),
        current_guid: String::new(),
        available_plans: Vec::new(),
        display_off_minutes: 0,
        sleep_minutes: 0,
        hdd_sleep_minutes: 0,
    };

    // List plans
    if let Ok(o) = optimizer_core::silent_cmd("powercfg").args(["/list"]).output() {
        let stdout = String::from_utf8_lossy(&o.stdout);
        for line in stdout.lines() {
            if let Some(guid_start) = line.find('(')
                && let Some(guid_end) = line.find(')') {
                    let name = line[guid_start + 1..guid_end].trim().to_string();
                    if let Some(g_start) = line.find(": ") {
                        let rest = &line[g_start + 2..];
                        let guid = rest.split_whitespace().next().unwrap_or("").trim().to_string();
                        let active = line.contains('*');
                        if active {
                            info.current_plan = name.clone();
                            info.current_guid = guid.clone();
                        }
                        info.available_plans.push(PowerPlan { name, guid, active });
                    }
                }
        }
    }


    // Display timeout
    if let Ok(o) = optimizer_core::silent_cmd("powercfg").args(["/query", "SCHEME_CURRENT", "7516b95f-f776-4464-8c53-06167f40cc99", "3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e"]).output() {
        info.display_off_minutes = parse_powercfg_timeout(&String::from_utf8_lossy(&o.stdout));
    }

    // Sleep timeout
    if let Ok(o) = optimizer_core::silent_cmd("powercfg").args(["/query", "SCHEME_CURRENT", "238c9fa8-0aad-41ed-83f4-97be242c8f20", "29f6c1db-86da-48c5-9fdb-f2b67b1f44da"]).output() {
        info.sleep_minutes = parse_powercfg_timeout(&String::from_utf8_lossy(&o.stdout));
    }

    // Turn-off-hard-disk timeout (disk subgroup, DISKIDLE setting)
    if let Ok(o) = optimizer_core::silent_cmd("powercfg").args(["/query", "SCHEME_CURRENT", "0012ee47-9041-4b5d-9b77-535fba8b1442", "6738e2c4-e8a5-4a42-b16a-e040e769756e"]).output() {
        info.hdd_sleep_minutes = parse_powercfg_timeout(&String::from_utf8_lossy(&o.stdout));
    }

    info
}

#[cfg(not(target_os = "windows"))]
pub fn get_info() -> PowerInfo {
    PowerInfo {
        current_plan: "N/A".into(),
        current_guid: String::new(),
        available_plans: Vec::new(),
        display_off_minutes: 0,
        sleep_minutes: 0,
        hdd_sleep_minutes: 0,
    }
}

fn parse_powercfg_timeout(output: &str) -> u32 {
    // The "Current AC Power Setting Index:" label is localized on non-English
    // Windows, so we cannot match on it. For a range setting, powercfg always
    // emits its 0x hex values in a fixed order regardless of language:
    //   Minimum / Maximum / increment possible, then Current AC, then Current DC.
    // The AC value (what we want) is therefore the second-to-last 0x value.
    let hexes: Vec<u32> = output
        .lines()
        .filter_map(|l| {
            l.find("0x")
                .and_then(|i| u32::from_str_radix(l[i + 2..].trim(), 16).ok())
        })
        .collect();
    if hexes.len() >= 2 {
        return hexes[hexes.len() - 2] / 60;
    }
    0
}

#[cfg(target_os = "windows")]
pub fn set_plan(guid: &str) -> Result<String, String> {
    
    let o = optimizer_core::silent_cmd("powercfg").args(["/setactive", guid]).output()
        .map_err(|e| e.to_string())?;
    if o.status.success() {
        Ok(format!("Power plan set to {}", guid))
    } else {
        Err(String::from_utf8_lossy(&o.stderr).trim().to_string())
    }
}

#[cfg(not(target_os = "windows"))]
pub fn set_plan(_guid: &str) -> Result<String, String> {
    Ok("[stub] Power plan set".into())
}
