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
pub struct RemoveResult {
    pub package_name: String,
    pub success: bool,
    pub message: String,
}

pub const BLOATWARE_LIST: &[(&str, &str, &str)] = &[
    // Games
    ("Microsoft.BingWeather", "MSN Weather", "games_and_ads"),
    ("Microsoft.GamingApp", "Xbox", "games_and_ads"),
    ("Microsoft.XboxApp", "Xbox Console Companion", "games_and_ads"),
    ("Microsoft.XboxGameOverlay", "Xbox Game Bar", "games_and_ads"),
    ("Microsoft.XboxGamingOverlay", "Xbox Game Bar", "games_and_ads"),
    ("Microsoft.XboxIdentityProvider", "Xbox Identity Provider", "games_and_ads"),
    ("Microsoft.XboxSpeechToTextOverlay", "Xbox Speech To Text", "games_and_ads"),
    ("king.com.CandyCrushSaga", "Candy Crush Saga", "games_and_ads"),
    ("king.com.CandyCrushSodaSaga", "Candy Crush Soda Saga", "games_and_ads"),
    ("Microsoft.MicrosoftSolitaireCollection", "Solitaire Collection", "games_and_ads"),
    ("SpotifyAB.SpotifyMusic", "Spotify", "games_and_ads"),
    ("Disney.37853FC22B2CE", "Disney+", "games_and_ads"),
    ("BytedancePte.Ltd.TikTok", "TikTok", "games_and_ads"),
    ("Facebook.Facebook", "Facebook", "games_and_ads"),
    ("Facebook.Instagram", "Instagram", "games_and_ads"),
    ("FACEBOOK.317180B0BB486", "Messenger", "games_and_ads"),
    ("Clipchamp.Clipchamp", "Clipchamp", "games_and_ads"),
    // Communication
    ("Microsoft.People", "People", "communication"),
    ("microsoft.windowscommunicationsapps", "Mail and Calendar", "communication"),
    ("Microsoft.SkypeApp", "Skype", "communication"),
    ("Microsoft.YourPhone", "Phone Link", "communication"),
    ("MicrosoftTeams", "Microsoft Teams (personal)", "communication"),
    ("MSTeams", "Microsoft Teams (new)", "communication"),
    // Media
    ("Microsoft.ZuneMusic", "Groove Music", "media"),
    ("Microsoft.ZuneVideo", "Movies & TV", "media"),
    ("Microsoft.MixedReality.Portal", "Mixed Reality Portal", "media"),
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
    ("Microsoft.MicrosoftStickyNotes", "Sticky Notes", "utilities"),
    ("Microsoft.OneConnect", "Paid Wi-Fi & Cellular", "utilities"),
    ("Microsoft.Wallet", "Microsoft Pay", "utilities"),
    ("Microsoft.PowerAutomateDesktop", "Power Automate", "utilities"),
    ("Microsoft.Todos", "Microsoft To Do", "utilities"),
    ("MicrosoftCorporationII.QuickAssist", "Quick Assist", "utilities"),
    // OEM
    ("DellInc.DellSupportAssistforPCs", "Dell SupportAssist", "oem"),
    ("E046963F.LenovoCompanion", "Lenovo Vantage", "oem"),
    ("AcerIncorporated.AcerCare", "Acer Care Center", "oem"),
    ("HPInc.HPSupportAssistant", "HP Support Assistant", "oem"),
    ("McAfee.McAfeeSecurityAdvisorWin10", "McAfee", "oem"),
    ("NortonLifeLock.NortonSecurity", "Norton Security", "oem"),
];

#[cfg(target_os = "windows")]
pub fn scan_installed() -> Vec<BloatwareApp> {
    let script = r#"
$packages = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
$provisioned = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PackageName
$all = @($packages) + @($provisioned | ForEach-Object { ($_ -split '_')[0] })
$all | Sort-Object -Unique | ConvertTo-Json -Compress
"#;
    let json = run_ps(script);
    let installed: Vec<String> = serde_json::from_str(&json).unwrap_or_default();

    BLOATWARE_LIST.iter().map(|(pkg, name, cat)| {
        let is_installed = installed.iter().any(|i| i.contains(pkg));
        BloatwareApp {
            package_name: pkg.to_string(),
            display_name: name.to_string(),
            publisher: "".to_string(),
            category: cat.to_string(),
            installed: is_installed,
        }
    }).collect()
}

#[cfg(not(target_os = "windows"))]
pub fn scan_installed() -> Vec<BloatwareApp> {
    BLOATWARE_LIST.iter().enumerate().map(|(i, (pkg, name, cat))| {
        BloatwareApp {
            package_name: pkg.to_string(),
            display_name: name.to_string(),
            publisher: "".to_string(),
            category: cat.to_string(),
            installed: i < 15,
        }
    }).collect()
}

#[cfg(target_os = "windows")]
pub fn remove_apps(packages: &[String]) -> Vec<RemoveResult> {
    packages.iter().map(|pkg| {
        let script = format!(
            "Get-AppxPackage -AllUsers -Name '{}' | Remove-AppxPackage -AllUsers -ErrorAction Stop; Get-AppxProvisionedPackage -Online | Where-Object {{ $_.PackageName -match '{}' }} | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue",
            pkg.replace('\'', "''"),
            pkg.replace('\'', "''"),
        );
        let output = optimizer_core::silent_cmd("powershell")
            .args(["-NoProfile", "-Command", &script])
            .output();

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

#[cfg(not(target_os = "windows"))]
pub fn remove_apps(packages: &[String]) -> Vec<RemoveResult> {
    packages.iter().map(|pkg| RemoveResult {
        package_name: pkg.clone(),
        success: true,
        message: "[stub] Would remove".to_string(),
    }).collect()
}

#[cfg(target_os = "windows")]
fn run_ps(script: &str) -> String {
    
    match optimizer_core::silent_cmd("powershell").args(["-NoProfile", "-Command", script]).output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        Err(_) => "[]".to_string(),
    }
}
