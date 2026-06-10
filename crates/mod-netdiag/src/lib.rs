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

// ---------------------------------------------------------------------------
// Speed test
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct SpeedTestResult {
    pub download_mbps: f64,
    pub test_url: String,
    pub bytes_downloaded: u64,
    pub duration_ms: u64,
    pub status: String,
}

#[cfg(target_os = "windows")]
pub fn run_speed_test() -> SpeedTestResult {
    

    let ps = r#"
$url = 'http://speedtest.tele2.net/10MB.zip'
$tmp = "$env:TEMP\cove_speedtest.tmp"
try {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing -ErrorAction Stop
    $sw.Stop()
    $size = (Get-Item $tmp -ErrorAction SilentlyContinue).Length
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    if ($null -eq $size) { $size = 0 }
    $ms = $sw.ElapsedMilliseconds
    $mbps = if ($ms -gt 0) { [math]::Round(($size * 8) / ($ms * 1000), 2) } else { 0 }
    Write-Output "OK|$mbps|$size|$ms|$url"
} catch {
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    Write-Output "FAIL|0|0|0|$url|$($_.Exception.Message)"
}
"#;

    if let Ok(o) = optimizer_core::silent_cmd("powershell").args(["-NoProfile", "-Command", ps]).output() {
        let line = String::from_utf8_lossy(&o.stdout).trim().to_string();
        let p: Vec<&str> = line.split('|').collect();
        if p.len() >= 5 && p[0] == "OK" {
            return SpeedTestResult {
                download_mbps: p[1].parse().unwrap_or(0.0),
                bytes_downloaded: p[2].parse().unwrap_or(0),
                duration_ms: p[3].parse().unwrap_or(0),
                test_url: p[4].to_string(),
                status: "ok".into(),
            };
        }
    }

    SpeedTestResult {
        download_mbps: 0.0, bytes_downloaded: 0, duration_ms: 0,
        test_url: "http://speedtest.tele2.net/10MB.zip".into(),
        status: "fail".into(),
    }
}

#[cfg(not(target_os = "windows"))]
pub fn run_speed_test() -> SpeedTestResult {
    SpeedTestResult {
        download_mbps: 0.0, bytes_downloaded: 0, duration_ms: 0,
        test_url: String::new(), status: "stub".into(),
    }
}

#[cfg(target_os = "windows")]
fn get_primary_adapter() -> Option<AdapterInfo> {
    
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

    if let Ok(o) = optimizer_core::silent_cmd("powershell").args(["-NoProfile", "-Command", ps]).output() {
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
    

    if let Ok(o) = optimizer_core::silent_cmd("powershell").args(["-NoProfile", "-Command", ps_script]).output() {
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
    

    let o = optimizer_core::silent_cmd("netsh").args(["wlan", "show", "interfaces"]).output().ok()?;
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
