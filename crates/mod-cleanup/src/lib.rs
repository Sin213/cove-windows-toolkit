use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct CleanupTarget {
    pub id: String,
    pub name: String,
    pub path: String,
    pub size_bytes: u64,
    pub file_count: u64,
    pub safety: String,
    pub scan_error: Option<String>,
}

#[cfg(target_os = "windows")]
pub fn scan_targets() -> Vec<CleanupTarget> {
    let windows = optimizer_core::windows_directory();
    let local = directories::BaseDirs::new().map(|dirs| dirs.data_local_dir().to_path_buf());
    let targets: Vec<(&str, &str, String, &str)> = vec![
        (
            "clean.user_temp",
            "User Temp Files",
            local
                .as_ref()
                .map(|p| p.join("Temp"))
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            "green",
        ),
        (
            "clean.system_temp",
            "System Temp Files",
            windows.join("Temp").to_string_lossy().into(),
            "green",
        ),
        (
            "clean.prefetch",
            "Prefetch Cache",
            windows.join("Prefetch").to_string_lossy().into(),
            "green",
        ),
        (
            "clean.thumbnails",
            "Thumbnail Cache",
            local
                .as_ref()
                .map(|p| p.join(r"Microsoft\Windows\Explorer"))
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            "green",
        ),
        (
            "clean.error_reports",
            "Error Reports",
            local
                .as_ref()
                .map(|p| p.join(r"Microsoft\Windows\WER"))
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            "green",
        ),
        (
            "clean.wu_cache",
            "Windows Update Cache",
            windows
                .join(r"SoftwareDistribution\Download")
                .to_string_lossy()
                .into(),
            "yellow",
        ),
        (
            "clean.delivery_opt",
            "Delivery Optimization",
            windows
                .join(r"SoftwareDistribution\DeliveryOptimization")
                .to_string_lossy()
                .into(),
            "yellow",
        ),
    ];

    targets
        .into_iter()
        .map(|(id, name, path, safety)| {
            let measurement = measure_dir(&path);
            let (size, count, scan_error) = match measurement {
                Ok((size, count)) => (size, count, None),
                Err(error) => (0, 0, Some(error)),
            };
            CleanupTarget {
                id: id.to_string(),
                name: name.to_string(),
                path,
                size_bytes: size,
                file_count: count,
                safety: safety.to_string(),
                scan_error,
            }
        })
        .collect()
}

#[cfg(not(target_os = "windows"))]
pub fn scan_targets() -> Vec<CleanupTarget> {
    Vec::new()
}

#[cfg(target_os = "windows")]
fn measure_dir(path: &str) -> Result<(u64, u64), String> {
    // Escape single quotes so profile paths containing an apostrophe
    // (e.g. C:\Users\O'Brien\...) don't break the single-quoted PS strings.
    let safe = path.replace('\'', "''");
    let ps = format!(
        r#"
if (-not (Test-Path -LiteralPath '{}')) {{ Write-Output '0|0'; exit }}
$ErrorActionPreference='Stop'
$files = Get-ChildItem -LiteralPath '{}' -Recurse -File -Force -ErrorAction Stop
$size = ($files | Measure-Object -Property Length -Sum).Sum
$count = ($files | Measure-Object).Count
if ($null -eq $size) {{ $size = 0 }}
Write-Output "$size|$count"
"#,
        safe, safe
    );

    if let Ok(o) = optimizer_core::powershell(&ps).output() {
        let line = String::from_utf8_lossy(&o.stdout).trim().to_string();
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() >= 2 {
            let size: u64 = parts[0].trim().parse().unwrap_or(0);
            let count: u64 = parts[1].trim().parse().unwrap_or(0);
            return Ok((size, count));
        }
    }
    Err("Could not measure this cleanup target.".into())
}

#[cfg(target_os = "windows")]
pub fn clean_targets(ids: &[String]) -> Vec<(String, bool, String)> {
    let all = scan_targets();
    let mut results = Vec::new();

    for id in ids {
        if let Some(target) = all.iter().find(|t| &t.id == id) {
            let path = &target.path;
            match clean_directory(path) {
                Ok(msg) => results.push((id.clone(), true, msg)),
                Err(msg) => results.push((id.clone(), false, msg)),
            }
        } else {
            results.push((id.clone(), false, "Target not found".into()));
        }
    }
    results
}

#[cfg(not(target_os = "windows"))]
pub fn clean_targets(_ids: &[String]) -> Vec<(String, bool, String)> {
    Vec::new()
}

#[cfg(target_os = "windows")]
fn clean_directory(path: &str) -> Result<String, String> {
    // Escape single quotes so profile paths containing an apostrophe
    // (e.g. C:\Users\O'Brien\...) don't break the single-quoted PS strings.
    let safe = path.replace('\'', "''");
    let ps = format!(
        r#"
if (-not (Test-Path -LiteralPath '{}')) {{ Write-Output 'PATH_MISSING'; exit }}
$ErrorActionPreference='Stop'
$before = (Get-ChildItem -LiteralPath '{}' -Recurse -File -Force -ErrorAction Stop | Measure-Object -Property Length -Sum).Sum
if ($null -eq $before) {{ $before = 0 }}
Get-ChildItem -LiteralPath '{}' -Recurse -File -Force -ErrorAction Stop | Remove-Item -Force -ErrorAction Stop
$after = (Get-ChildItem -LiteralPath '{}' -Recurse -File -Force -ErrorAction Stop | Measure-Object -Property Length -Sum).Sum
if ($null -eq $after) {{ $after = 0 }}
$freed = $before - $after
Write-Output "OK|$freed"
"#,
        safe, safe, safe, safe
    );

    let o = optimizer_core::powershell(&ps)
        .output()
        .map_err(|e| e.to_string())?;
    let line = String::from_utf8_lossy(&o.stdout).trim().to_string();
    if let Some(value) = line.strip_prefix("OK|") {
        let freed: u64 = value.trim().parse().unwrap_or(0);
        let mb = freed / (1024 * 1024);
        Ok(format!("Cleaned {} MB", mb))
    } else {
        Err("Path not found or inaccessible".into())
    }
}
