use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct CleanupTarget {
    pub id: String,
    pub name: String,
    pub path: String,
    pub size_bytes: u64,
    pub file_count: u64,
    pub safety: String,
}

#[cfg(target_os = "windows")]
pub fn scan_targets() -> Vec<CleanupTarget> {
    let targets: Vec<(&str, &str, String, &str)> = vec![
        ("clean.user_temp", "User Temp Files", expand_env("%TEMP%"), "green"),
        ("clean.system_temp", "System Temp Files", expand_env("%SystemRoot%\\Temp"), "green"),
        ("clean.prefetch", "Prefetch Cache", expand_env("%SystemRoot%\\Prefetch"), "green"),
        ("clean.thumbnails", "Thumbnail Cache", expand_env("%LocalAppData%\\Microsoft\\Windows\\Explorer"), "green"),
        ("clean.error_reports", "Error Reports", expand_env("%LocalAppData%\\Microsoft\\Windows\\WER"), "green"),
        ("clean.wu_cache", "Windows Update Cache", expand_env("%SystemRoot%\\SoftwareDistribution\\Download"), "yellow"),
        ("clean.delivery_opt", "Delivery Optimization", expand_env("%SystemRoot%\\SoftwareDistribution\\DeliveryOptimization"), "yellow"),
    ];

    targets.into_iter().map(|(id, name, path, safety)| {
        let (size, count) = measure_dir(&path);
        CleanupTarget {
            id: id.to_string(),
            name: name.to_string(),
            path,
            size_bytes: size,
            file_count: count,
            safety: safety.to_string(),
        }
    }).collect()
}

#[cfg(not(target_os = "windows"))]
pub fn scan_targets() -> Vec<CleanupTarget> {
    Vec::new()
}

#[cfg(target_os = "windows")]
fn expand_env(path: &str) -> String {
    let mut result = path.to_string();
    for var in ["%TEMP%", "%SystemRoot%", "%LocalAppData%", "%ProgramData%"] {
        let name = var.trim_matches('%');
        if let Ok(val) = std::env::var(name) {
            result = result.replace(var, &val);
        }
    }
    result
}

#[cfg(target_os = "windows")]
fn measure_dir(path: &str) -> (u64, u64) {
    

    // Escape single quotes so profile paths containing an apostrophe
    // (e.g. C:\Users\O'Brien\...) don't break the single-quoted PS strings.
    let safe = path.replace('\'', "''");
    let ps = format!(
        r#"
if (-not (Test-Path '{}')) {{ Write-Output '0|0'; exit }}
$files = Get-ChildItem -Path '{}' -Recurse -File -Force -ErrorAction SilentlyContinue
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
            return (size, count);
        }
    }
    (0, 0)
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
if (-not (Test-Path '{}')) {{ Write-Output 'PATH_MISSING'; exit }}
$before = (Get-ChildItem -Path '{}' -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
if ($null -eq $before) {{ $before = 0 }}
Get-ChildItem -Path '{}' -Recurse -File -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
$after = (Get-ChildItem -Path '{}' -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
if ($null -eq $after) {{ $after = 0 }}
$freed = $before - $after
Write-Output "OK|$freed"
"#,
        safe, safe, safe, safe
    );

    let o = optimizer_core::powershell(&ps).output()
        .map_err(|e| e.to_string())?;
    let line = String::from_utf8_lossy(&o.stdout).trim().to_string();
    if line.starts_with("OK|") {
        let freed: u64 = line[3..].trim().parse().unwrap_or(0);
        let mb = freed / (1024 * 1024);
        Ok(format!("Cleaned {} MB", mb))
    } else {
        Err("Path not found or inaccessible".into())
    }
}
