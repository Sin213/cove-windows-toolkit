use serde::{Deserialize, Serialize};

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

#[derive(Serialize, Deserialize, Clone)]
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
    pub complete: bool,
    pub errors: Vec<String>,
    pub adapter: Option<AdapterInfo>,
    pub tests: Vec<TestResult>,
    pub wifi: Option<WifiInfo>,
}

#[cfg(target_os = "windows")]
pub fn run_diagnostics() -> NetDiagReport {
    let mut errors = Vec::new();
    let adapter = get_primary_adapter().unwrap_or_else(|error| {
        errors.push(error);
        None
    });
    let tests = run_connectivity_tests().unwrap_or_else(|error| {
        errors.push(error);
        Vec::new()
    });
    // netsh's WLAN labels are localized and cannot be parsed reliably. Keep the
    // field unknown until a native WLAN API implementation is available.
    let wifi = None;
    NetDiagReport {
        complete: errors.is_empty(),
        errors,
        adapter,
        tests,
        wifi,
    }
}

#[cfg(not(target_os = "windows"))]
pub fn run_diagnostics() -> NetDiagReport {
    NetDiagReport {
        complete: false,
        errors: vec!["Network diagnostics are unavailable on this platform.".into()],
        adapter: None,
        tests: Vec::new(),
        wifi: None,
    }
}

#[derive(Serialize)]
pub struct SpeedTestResult {
    pub download_mbps: f64,
    pub test_url: String,
    pub bytes_downloaded: u64,
    pub duration_ms: u64,
    pub status: String,
    /// Why the test failed, when it did. Empty on success.
    pub message: String,
}

#[cfg(target_os = "windows")]
pub fn run_speed_test() -> SpeedTestResult {
    let ps = r#"
$ErrorActionPreference = 'Stop'
$url = 'https://speed.cloudflare.com/__down?bytes=10000000'
$limit = 10000000
# Windows PowerShell 5.1 does not load System.Net.Http by default, so the type
# literal below fails to resolve ("Unable to find type") unless the assembly is
# requested explicitly. Without this the test failed on every machine.
Add-Type -AssemblyName System.Net.Http
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$client = [System.Net.Http.HttpClient]::new()
$cancel = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(20))
try {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $resp = $client.GetAsync($url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cancel.Token).GetAwaiter().GetResult()
    $resp.EnsureSuccessStatusCode() | Out-Null
    $stream = $resp.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
    $buffer = New-Object byte[] 65536
    [long]$size = 0
    while ($size -lt $limit) {
      $want = [Math]::Min($buffer.Length, $limit - $size)
      $read = $stream.ReadAsync($buffer, 0, $want, $cancel.Token).GetAwaiter().GetResult()
      if ($read -eq 0) { break }
      $size += $read
    }
    $sw.Stop()
    if ($size -ne $limit) { throw "Server returned only $size of $limit bytes" }
    $ms = $sw.ElapsedMilliseconds
    if ($ms -le 0) { throw 'Invalid elapsed time' }
    $mbps = [math]::Round(($size * 8) / ($ms * 1000), 2)
    @{ status='ok'; download_mbps=$mbps; bytes_downloaded=$size; duration_ms=$ms; test_url=$url } | ConvertTo-Json -Compress
} catch {
    @{ status='fail'; download_mbps=0; bytes_downloaded=0; duration_ms=0; test_url=$url; message=[string]$_.Exception.Message } | ConvertTo-Json -Compress
} finally {
    $client.Dispose(); $cancel.Dispose()
}
"#;
    let failed = |message: String| SpeedTestResult {
        download_mbps: 0.0,
        bytes_downloaded: 0,
        duration_ms: 0,
        test_url: String::new(),
        status: "fail".into(),
        message,
    };

    let output = match optimizer_core::powershell(ps).output() {
        Ok(output) => output,
        Err(error) => return failed(format!("Could not start the speed test: {error}")),
    };
    let Ok(result) = serde_json::from_slice::<serde_json::Value>(&output.stdout) else {
        // The script only ever prints JSON, so unparsable output means it never
        // ran (execution policy, missing host). Keep stderr for the support log.
        return failed(format!(
            "The speed test produced no usable result: {}",
            optimizer_core::decode_console_output(&output.stderr).trim()
        ));
    };
    if result.get("status").and_then(|v| v.as_str()) != Some("ok") {
        return failed(
            result
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("The download did not complete.")
                .to_string(),
        );
    }
    SpeedTestResult {
        download_mbps: result
            .get("download_mbps")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0),
        bytes_downloaded: result
            .get("bytes_downloaded")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        duration_ms: result
            .get("duration_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        test_url: result
            .get("test_url")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        status: "ok".into(),
        message: String::new(),
    }
}

#[cfg(not(target_os = "windows"))]
pub fn run_speed_test() -> SpeedTestResult {
    SpeedTestResult {
        download_mbps: 0.0,
        bytes_downloaded: 0,
        duration_ms: 0,
        test_url: String::new(),
        status: "stub".into(),
        message: String::new(),
    }
}

#[cfg(target_os = "windows")]
fn get_primary_adapter() -> Result<Option<AdapterInfo>, String> {
    let ps = r#"
$ErrorActionPreference='Stop'
$route = Get-NetRoute -DestinationPrefix @('0.0.0.0/0','::/0') -ErrorAction Stop | Where-Object State -eq 'Alive' | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1
if (-not $route) { @{adapter=$null} | ConvertTo-Json -Compress; exit }
$a = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction Stop
$cfg = Get-NetIPConfiguration -InterfaceIndex $a.ifIndex -ErrorAction Stop
$dns = @($cfg.DNSServer | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ })
$ips = @($cfg.IPv4Address.IPAddress) + @($cfg.IPv6Address.IPAddress) | Where-Object { $_ }
$gateways = @($cfg.IPv4DefaultGateway.NextHop) + @($cfg.IPv6DefaultGateway.NextHop) | Where-Object { $_ }
@{adapter=@{name=$a.Name; description=$a.InterfaceDescription; speed=[string]$a.LinkSpeed; ip=($ips -join ', '); gateway=($gateways -join ', '); dns=$dns; status=[string]$a.Status}} | ConvertTo-Json -Depth 4 -Compress
"#;
    let output = optimizer_core::powershell(ps)
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())?;
    let Some(adapter) = value.get("adapter").filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let description = adapter
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    Ok(Some(AdapterInfo {
        name: adapter
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        adapter_type: if description.to_ascii_lowercase().contains("wireless")
            || description.to_ascii_lowercase().contains("wi-fi")
        {
            "Wi-Fi".into()
        } else {
            "Ethernet".into()
        },
        speed: adapter
            .get("speed")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        ip: adapter
            .get("ip")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        gateway: adapter
            .get("gateway")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        dns: adapter
            .get("dns")
            .and_then(|v| v.as_array())
            .map(|values| {
                values
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
        status: adapter
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown")
            .to_string(),
        signal: None,
    }))
}

#[cfg(target_os = "windows")]
fn run_connectivity_tests() -> Result<Vec<TestResult>, String> {
    let ps = r#"
# Gateway ping - use .NET to avoid console popup
$gw = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | Select-Object -First 1).IPv4DefaultGateway.NextHop
if ($gw) {
    try {
        $pinger = New-Object System.Net.NetworkInformation.Ping
        $reply = $pinger.Send($gw, 2000)
        if ($reply.Status -eq 'Success') {
            $tests += [pscustomobject]@{name='Gateway Ping';status='ok';latency_ms=$reply.RoundtripTime;detail="$gw replied"}
        } else {
            $tests += [pscustomobject]@{name='Gateway Ping';status='unknown';latency_ms=$null;detail="No ICMP reply from $gw ($($reply.Status)); the gateway may block ping"}
        }
    } catch { $tests += [pscustomobject]@{name='Gateway Ping';status='unknown';latency_ms=$null;detail=$_.Exception.Message} }
} else { $tests += [pscustomobject]@{name='Gateway Ping';status='fail';latency_ms=$null;detail='No default gateway'} }

# DNS resolution
try {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $resolved = [System.Net.Dns]::GetHostAddresses('example.com') | Select-Object -First 1
    $sw.Stop()
    $tests += [pscustomobject]@{name='DNS Resolution';status='ok';latency_ms=$sw.ElapsedMilliseconds;detail="Resolved example.com to $($resolved.IPAddressToString)"}
} catch {
    $tests += [pscustomobject]@{name='DNS Resolution';status='fail';latency_ms=$null;detail='DNS resolution failed'}
}

# Internet connectivity
try {
    $sw2 = [System.Diagnostics.Stopwatch]::StartNew()
    $web = Invoke-WebRequest -Uri 'http://www.msftconnecttest.com/connecttest.txt' -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
    $sw2.Stop()
    if ($web.StatusCode -eq 200 -and $web.Content.Trim() -eq 'Microsoft Connect Test') {
        $tests += [pscustomobject]@{name='Internet Connectivity';status='ok';latency_ms=$sw2.ElapsedMilliseconds;detail='Connected'}
    } else {
        $tests += [pscustomobject]@{name='Internet Connectivity';status='fail';latency_ms=$sw2.ElapsedMilliseconds;detail='Unexpected response; a captive portal may be intercepting traffic'}
    }
} catch {
    $tests += [pscustomobject]@{name='Internet Connectivity';status='fail';latency_ms=$null;detail='Internet check failed'}
}
$tests | ConvertTo-Json -Compress
"#;
    let output = optimizer_core::powershell(&format!("$tests=@();{ps}"))
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())
}

#[cfg(target_os = "windows")]
#[allow(dead_code)]
fn get_wifi_info() -> Option<WifiInfo> {
    let o = optimizer_core::silent_cmd("netsh")
        .args(["wlan", "show", "interfaces"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&o.stdout);
    if !stdout.contains("SSID") {
        return None;
    }

    let mut ssid = String::new();
    let mut channel = 0u32;
    let mut signal = 0u32;

    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("SSID") && !line.starts_with("BSSID") {
            ssid = line.split(':').nth(1).unwrap_or("").trim().to_string();
        } else if line.contains('%') {
            // The signal-strength line is "<label> : NN%". The label is localized
            // on non-English Windows, but the "NN%" value is not, and it is the only
            // line in this section that contains a percent sign. Matching the value
            // instead of the English "Signal" label keeps this locale-independent.
            if let Some(rest) = line.split(':').nth(1) {
                signal = rest
                    .trim()
                    .trim_end_matches('%')
                    .trim()
                    .parse()
                    .unwrap_or(signal);
            }
        } else if line.starts_with("Channel") {
            channel = line
                .split(':')
                .nth(1)
                .unwrap_or("")
                .trim()
                .parse()
                .unwrap_or(0);
        }
    }

    if ssid.is_empty() {
        return None;
    }
    let freq = if channel > 14 { "5 GHz" } else { "2.4 GHz" };
    let dbm = (signal as i32) / 2 - 100;
    Some(WifiInfo {
        ssid,
        channel,
        frequency: freq.into(),
        signal_dbm: dbm,
        signal_quality: signal,
    })
}
