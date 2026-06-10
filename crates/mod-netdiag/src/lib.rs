use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct AdapterInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub adapter_type: String,
    pub speed: String,
    pub ip: String,
    pub gateway: String,
    pub dns: Vec<String>,
    pub status: String,
    pub signal: Option<i32>,
}

#[derive(Serialize, Clone)]
pub struct TestResult {
    pub name: String,
    pub status: String,
    pub latency_ms: Option<f64>,
    pub detail: String,
}

#[derive(Serialize, Clone)]
pub struct WifiInfo {
    pub ssid: String,
    pub channel: u32,
    pub frequency: String,
    pub signal_dbm: i32,
    pub signal_quality: u32,
}

#[derive(Serialize)]
pub struct NetDiagReport {
    pub adapter: Option<AdapterInfo>,
    pub tests: Vec<TestResult>,
    pub wifi: Option<WifiInfo>,
}

#[cfg(target_os = "windows")]
pub fn run_diagnostics() -> NetDiagReport {
    let adapter = get_primary_adapter();
    let tests = run_connectivity_tests();
    let wifi = get_wifi_info();

    NetDiagReport { adapter, tests, wifi }
}

#[cfg(not(target_os = "windows"))]
pub fn run_diagnostics() -> NetDiagReport {
    NetDiagReport { adapter: None, tests: Vec::new(), wifi: None }
}

#[cfg(target_os = "windows")]
fn get_primary_adapter() -> Option<AdapterInfo> {
    use std::process::Command;
    let ps = r#"
$a = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
if (-not $a) { exit 0 }
$cfg = Get-NetIPConfiguration -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue
$dns = ($cfg.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses }) -join ','
$ip = if ($cfg.IPv4Address) { $cfg.IPv4Address.IPAddress } else { '' }
$gw = if ($cfg.IPv4DefaultGateway) { $cfg.IPv4DefaultGateway.NextHop } else { '' }
$speed = "$([math]::Round($a.LinkSpeed.Replace(' Gbps','000').Replace(' Mbps','').Replace(' Kbps','') / 1, 0)) Mbps"
try { $speed = "$($a.LinkSpeed)" } catch {}
Write-Output "$($a.Name)|$($a.InterfaceDescription)|$speed|$ip|$gw|$dns|$($a.Status)"
"#;

    if let Ok(o) = Command::new("powershell").args(["-NoProfile", "-Command", ps]).output() {
        let line = String::from_utf8_lossy(&o.stdout).trim().to_string();
        let p: Vec<&str> = line.split('|').collect();
        if p.len() >= 7 {
            let dns: Vec<String> = p[5].split(',').filter(|s| !s.is_empty()).map(|s| s.trim().to_string()).collect();
            return Some(AdapterInfo {
                name: p[0].trim().to_string(),
                adapter_type: if p[1].to_lowercase().contains("wi-fi") || p[1].to_lowercase().contains("wireless") { "Wi-Fi".into() } else { "Ethernet".into() },
                speed: p[2].trim().to_string(),
                ip: p[3].trim().to_string(),
                gateway: p[4].trim().to_string(),
                dns,
                status: p[6].trim().to_string(),
                signal: None,
            });
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn run_connectivity_tests() -> Vec<TestResult> {

    let mut tests = Vec::new();

    // Gateway ping
    let ps_gw = r#"
$gw = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | Select-Object -First 1).IPv4DefaultGateway.NextHop
if ($gw) {
    $r = Test-Connection -ComputerName $gw -Count 1 -ErrorAction SilentlyContinue
    if ($r) { Write-Output "ok|$([math]::Round($r.Latency, 1))|$gw reachable" }
    else { Write-Output "fail|0|$gw unreachable" }
} else { Write-Output "fail|0|No default gateway" }
"#;
    tests.push(run_single_test("Gateway Ping", ps_gw));

    // DNS resolution
    let ps_dns = r#"
$sw = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $r = Resolve-DnsName google.com -Type A -ErrorAction Stop | Select-Object -First 1
    $sw.Stop()
    Write-Output "ok|$($sw.ElapsedMilliseconds)|Resolved google.com to $($r.IPAddress)"
} catch {
    $sw.Stop()
    Write-Output "fail|$($sw.ElapsedMilliseconds)|DNS resolution failed"
}
"#;
    tests.push(run_single_test("DNS Resolution", ps_dns));

    // Internet connectivity
    let ps_inet = r#"
$sw = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $r = Test-Connection -ComputerName microsoft.com -Count 1 -ErrorAction Stop
    $sw.Stop()
    Write-Output "ok|$($r.Latency)|microsoft.com reachable"
} catch {
    $sw.Stop()
    Write-Output "fail|$($sw.ElapsedMilliseconds)|Internet unreachable"
}
"#;
    tests.push(run_single_test("Internet Connectivity", ps_inet));

    tests
}

#[cfg(target_os = "windows")]
fn run_single_test(name: &str, ps_script: &str) -> TestResult {
    use std::process::Command;

    if let Ok(o) = Command::new("powershell").args(["-NoProfile", "-Command", ps_script]).output() {
        let line = String::from_utf8_lossy(&o.stdout).trim().to_string();
        let p: Vec<&str> = line.splitn(3, '|').collect();
        if p.len() >= 3 {
            return TestResult {
                name: name.to_string(),
                status: p[0].trim().to_string(),
                latency_ms: p[1].trim().parse().ok(),
                detail: p[2].trim().to_string(),
            };
        }
    }
    TestResult { name: name.to_string(), status: "fail".into(), latency_ms: None, detail: "Test failed to execute".into() }
}

#[cfg(target_os = "windows")]
fn get_wifi_info() -> Option<WifiInfo> {
    use std::process::Command;

    let o = Command::new("netsh").args(["wlan", "show", "interfaces"]).output().ok()?;
    let stdout = String::from_utf8_lossy(&o.stdout);
    if !stdout.contains("SSID") { return None; }

    let mut ssid = String::new();
    let mut channel = 0u32;
    let mut signal = 0u32;

    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("SSID") && !line.starts_with("BSSID") {
            ssid = line.split(':').nth(1).unwrap_or("").trim().to_string();
        } else if line.starts_with("Channel") {
            channel = line.split(':').nth(1).unwrap_or("").trim().parse().unwrap_or(0);
        } else if line.starts_with("Signal") {
            signal = line.split(':').nth(1).unwrap_or("").trim().trim_end_matches('%').parse().unwrap_or(0);
        }
    }

    if ssid.is_empty() { return None; }
    let freq = if channel > 14 { "5 GHz" } else { "2.4 GHz" };
    let dbm = (signal as i32) / 2 - 100;

    Some(WifiInfo { ssid, channel, frequency: freq.into(), signal_dbm: dbm, signal_quality: signal })
}
