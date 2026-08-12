use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloatwareApp {
    pub package_name: String,
    pub display_name: String,
    pub publisher: String,
    pub category: String,
    pub installed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloatwareReport {
    pub complete: bool,
    pub error: Option<String>,
    pub apps: Vec<BloatwareApp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveResult {
    pub package_name: String,
    pub success: bool,
    pub message: String,
}

pub const BLOATWARE_LIST: &[(&str, &str, &str)] = &[
    // Games
    ("Microsoft.BingWeather", "MSN Weather", "games_and_ads"),
    ("Microsoft.GamingApp", "Xbox", "games_and_ads"),
    (
        "Microsoft.XboxApp",
        "Xbox Console Companion",
        "games_and_ads",
    ),
    (
        "Microsoft.XboxGameOverlay",
        "Xbox Game Bar",
        "games_and_ads",
    ),
    (
        "Microsoft.XboxGamingOverlay",
        "Xbox Game Bar",
        "games_and_ads",
    ),
    (
        "Microsoft.XboxIdentityProvider",
        "Xbox Identity Provider",
        "games_and_ads",
    ),
    (
        "Microsoft.XboxSpeechToTextOverlay",
        "Xbox Speech To Text",
        "games_and_ads",
    ),
    (
        "king.com.CandyCrushSaga",
        "Candy Crush Saga",
        "games_and_ads",
    ),
    (
        "king.com.CandyCrushSodaSaga",
        "Candy Crush Soda Saga",
        "games_and_ads",
    ),
    (
        "Microsoft.MicrosoftSolitaireCollection",
        "Solitaire Collection",
        "games_and_ads",
    ),
    ("SpotifyAB.SpotifyMusic", "Spotify", "games_and_ads"),
    ("Disney.37853FC22B2CE", "Disney+", "games_and_ads"),
    ("BytedancePte.Ltd.TikTok", "TikTok", "games_and_ads"),
    ("Facebook.Facebook", "Facebook", "games_and_ads"),
    ("Facebook.Instagram", "Instagram", "games_and_ads"),
    ("FACEBOOK.317180B0BB486", "Messenger", "games_and_ads"),
    ("Clipchamp.Clipchamp", "Clipchamp", "games_and_ads"),
    // Communication
    ("Microsoft.People", "People", "communication"),
    (
        "microsoft.windowscommunicationsapps",
        "Mail and Calendar",
        "communication",
    ),
    ("Microsoft.SkypeApp", "Skype", "communication"),
    ("Microsoft.YourPhone", "Phone Link", "communication"),
    (
        "MicrosoftTeams",
        "Microsoft Teams (personal)",
        "communication",
    ),
    ("MSTeams", "Microsoft Teams (new)", "communication"),
    // Media
    ("Microsoft.ZuneMusic", "Groove Music", "media"),
    ("Microsoft.ZuneVideo", "Movies & TV", "media"),
    (
        "Microsoft.MixedReality.Portal",
        "Mixed Reality Portal",
        "media",
    ),
    ("Microsoft.3DBuilder", "3D Builder", "media"),
    ("Microsoft.Microsoft3DViewer", "3D Viewer", "media"),
    ("Microsoft.Print3D", "Print 3D", "media"),
    // Utilities (safe to remove)
    ("Microsoft.BingNews", "MSN News", "utilities"),
    ("Microsoft.BingFinance", "MSN Money", "utilities"),
    ("Microsoft.BingSports", "MSN Sports", "utilities"),
    ("Microsoft.BingTravel", "MSN Travel", "utilities"),
    ("Microsoft.BingHealthAndFitness", "MSN Health", "utilities"),
    ("Microsoft.BingFoodAndDrink", "MSN Food", "utilities"),
    ("Microsoft.GetHelp", "Get Help", "utilities"),
    ("Microsoft.Getstarted", "Tips", "utilities"),
    ("Microsoft.WindowsFeedbackHub", "Feedback Hub", "utilities"),
    ("Microsoft.WindowsMaps", "Maps", "utilities"),
    ("Microsoft.MicrosoftOfficeHub", "Office Hub", "utilities"),
    (
        "Microsoft.MicrosoftStickyNotes",
        "Sticky Notes",
        "utilities",
    ),
    ("Microsoft.OneConnect", "Paid Wi-Fi & Cellular", "utilities"),
    ("Microsoft.Wallet", "Microsoft Pay", "utilities"),
    (
        "Microsoft.PowerAutomateDesktop",
        "Power Automate",
        "utilities",
    ),
    ("Microsoft.Todos", "Microsoft To Do", "utilities"),
    (
        "MicrosoftCorporationII.QuickAssist",
        "Quick Assist",
        "utilities",
    ),
    // OEM
    (
        "DellInc.DellSupportAssistforPCs",
        "Dell SupportAssist",
        "oem",
    ),
    ("E046963F.LenovoCompanion", "Lenovo Vantage", "oem"),
    ("AcerIncorporated.AcerCare", "Acer Care Center", "oem"),
    ("HPInc.HPSupportAssistant", "HP Support Assistant", "oem"),
    ("McAfee.McAfeeSecurityAdvisorWin10", "McAfee", "oem"),
    ("NortonLifeLock.NortonSecurity", "Norton Security", "oem"),
];

#[cfg(any(target_os = "windows", test))]
fn package_is_installed(installed: &[String], approved: &str) -> bool {
    installed
        .iter()
        .any(|installed_name| installed_name.eq_ignore_ascii_case(approved))
}

#[cfg(target_os = "windows")]
pub fn scan_installed() -> BloatwareReport {
    let script = r#"
$ErrorActionPreference = 'Stop'
$packages = @(Get-AppxPackage -AllUsers -ErrorAction Stop | Select-Object -ExpandProperty Name)
$provisioned = @(Get-AppxProvisionedPackage -Online -ErrorAction Stop | Select-Object -ExpandProperty DisplayName)
[pscustomobject]@{ packages = @($packages + $provisioned | Sort-Object -Unique) } | ConvertTo-Json -Compress
"#;
    let installed = match optimizer_core::powershell(script).output() {
        Ok(output) if output.status.success() => {
            let value: serde_json::Value = match serde_json::from_slice(&output.stdout) {
                Ok(value) => value,
                Err(error) => {
                    return failed_report(format!("Could not parse AppX inventory: {error}"));
                }
            };
            value
                .get("packages")
                .and_then(|v| v.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        }
        Ok(output) => {
            let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return failed_report(if detail.is_empty() {
                "AppX inventory query failed".into()
            } else {
                detail
            });
        }
        Err(error) => {
            return failed_report(format!("Could not start AppX inventory query: {error}"));
        }
    };

    let apps = BLOATWARE_LIST
        .iter()
        .map(|(pkg, name, cat)| {
            // AppX package-name casing can vary across machines/locales, so match
            // case-insensitively to avoid reporting an installed app as absent.
            let is_installed = package_is_installed(&installed, pkg);
            BloatwareApp {
                package_name: pkg.to_string(),
                display_name: name.to_string(),
                publisher: "".to_string(),
                category: cat.to_string(),
                installed: is_installed,
            }
        })
        .collect();
    BloatwareReport {
        complete: true,
        error: None,
        apps,
    }
}

#[cfg(target_os = "windows")]
fn failed_report(error: String) -> BloatwareReport {
    BloatwareReport {
        complete: false,
        error: Some(error),
        apps: BLOATWARE_LIST
            .iter()
            .map(|(pkg, name, cat)| BloatwareApp {
                package_name: pkg.to_string(),
                display_name: name.to_string(),
                publisher: String::new(),
                category: cat.to_string(),
                installed: false,
            })
            .collect(),
    }
}

#[cfg(not(target_os = "windows"))]
pub fn scan_installed() -> BloatwareReport {
    let apps = BLOATWARE_LIST
        .iter()
        .enumerate()
        .map(|(i, (pkg, name, cat))| BloatwareApp {
            package_name: pkg.to_string(),
            display_name: name.to_string(),
            publisher: "".to_string(),
            category: cat.to_string(),
            installed: i < 15,
        })
        .collect();
    BloatwareReport {
        complete: true,
        error: None,
        apps,
    }
}

#[cfg(target_os = "windows")]
pub fn remove_apps(packages: &[String]) -> Vec<RemoveResult> {
    packages.iter().map(|pkg| {
        let Some((approved, _, _)) = BLOATWARE_LIST
            .iter()
            .find(|(approved, _, _)| approved.eq_ignore_ascii_case(pkg))
        else {
            return RemoveResult {
                package_name: pkg.clone(),
                success: false,
                message: "Refused: package was not issued by the bloatware inventory.".into(),
            };
        };
        let approved = approved.replace('\'', "''");
        let script = format!(
            "$ErrorActionPreference='Stop'; \
             Get-AppxPackage -AllUsers | Where-Object {{ $_.Name -eq '{}' }} | Remove-AppxPackage -AllUsers -ErrorAction Stop; \
             Get-AppxProvisionedPackage -Online | Where-Object {{ $_.DisplayName -eq '{}' }} | Remove-AppxProvisionedPackage -Online -ErrorAction Stop | Out-Null; \
             if (Get-AppxPackage -AllUsers | Where-Object {{ $_.Name -eq '{}' }}) {{ throw 'Installed package is still present' }}; \
             if (Get-AppxProvisionedPackage -Online | Where-Object {{ $_.DisplayName -eq '{}' }}) {{ throw 'Provisioned package is still present' }}",
            approved, approved, approved, approved,
        );
        let output = optimizer_core::powershell(&script).output();

        match output {
            Ok(o) if o.status.success() => RemoveResult {
                package_name: pkg.clone(),
                success: true,
                message: "Removed".to_string(),
            },
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr).to_string();
                if stderr.contains("not found") || stderr.contains("does not exist") {
                    RemoveResult { package_name: pkg.clone(), success: true, message: "Already removed".to_string() }
                } else {
                    RemoveResult { package_name: pkg.clone(), success: false, message: stderr.lines().next().unwrap_or("Unknown error").to_string() }
                }
            }
            Err(e) => RemoveResult { package_name: pkg.clone(), success: false, message: e.to_string() },
        }
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::package_is_installed;

    #[test]
    fn installed_package_matching_is_case_insensitive_but_not_substring_based() {
        let installed = vec![
            "microsoft.bingweather".to_string(),
            "Contoso.Microsoft.GamingApp.Helper".to_string(),
        ];

        assert!(package_is_installed(&installed, "Microsoft.BingWeather"));
        assert!(!package_is_installed(&installed, "Microsoft.GamingApp"));
    }
}

#[cfg(not(target_os = "windows"))]
pub fn remove_apps(packages: &[String]) -> Vec<RemoveResult> {
    packages
        .iter()
        .map(|pkg| RemoveResult {
            package_name: pkg.clone(),
            success: true,
            message: "[stub] Would remove".to_string(),
        })
        .collect()
}
