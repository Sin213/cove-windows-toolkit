import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import "./NetDiagPanel.css";

interface Adapter {
  name: string;
  type: string;
  mac: string;
  ipv4: string | null;
  ipv6: string | null;
  gateway: string | null;
  dns: string[];
  speed: string | null;
  status: string;
}

interface TestResult {
  name: string;
  status: string;
  latency_ms: number | null;
  detail: string;
}

interface WifiInfo {
  ssid: string;
  signal_percent: number;
  channel: number;
  frequency: string;
  security: string;
}

interface NetDiagData {
  adapters: Adapter[];
  tests: TestResult[];
  wifi: WifiInfo | null;
}

interface ActionResult {
  success: boolean;
  message: string;
  output?: string;
}

interface SpeedTestResult {
  download_mbps: number;
  test_url: string;
  bytes_downloaded: number;
  duration_ms: number;
  status: string;
}

const DNS_PRESETS = [
  { id: "auto", label: "Automatic (DHCP)", primary: "", secondary: "", desc: "Use your router/ISP default" },
  { id: "cloudflare", label: "Cloudflare", primary: "1.1.1.1", secondary: "1.0.0.1", desc: "Fast, privacy-focused" },
  { id: "google", label: "Google", primary: "8.8.8.8", secondary: "8.8.4.4", desc: "Reliable, widely used" },
  { id: "quad9", label: "Quad9", primary: "9.9.9.9", secondary: "149.112.112.112", desc: "Security-focused, blocks malware" },
  { id: "opendns", label: "OpenDNS", primary: "208.67.222.222", secondary: "208.67.220.220", desc: "Cisco, with content filtering" },
];

const NET_COMMANDS = [
  { id: "flush_dns", label: "Flush DNS Cache", icon: "🗑", desc: "Clear cached DNS lookups" },
  { id: "release_ip", label: "Release IP", icon: "↓", desc: "Release current DHCP lease" },
  { id: "renew_ip", label: "Renew IP", icon: "↑", desc: "Request a new IP from DHCP" },
  { id: "reset_winsock", label: "Reset Winsock", icon: "🔄", desc: "Reset Windows socket catalog (reboot required)" },
  { id: "reset_tcp", label: "Reset TCP/IP", icon: "⟳", desc: "Reset IP stack to defaults (reboot required)" },
];

export default function NetDiagPanel() {
  const [data, setData] = useState<NetDiagData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [dnsPreset, setDnsPreset] = useState("auto");
  const [settingDns, setSettingDns] = useState(false);
  const [runningCmd, setRunningCmd] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; message: string } | null>(null);
  const [cmdOutput, setCmdOutput] = useState<string | null>(null);
  const [speedTesting, setSpeedTesting] = useState(false);
  const [speedResult, setSpeedResult] = useState<SpeedTestResult | null>(null);

  const load = () => {
    setLoading(true);
    setError(null);
    invoke<NetDiagData>("get_network_diagnostics")
      .then((d) => {
        setData(d);
        detectCurrentDns(d);
      })
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
  }, []);

  const detectCurrentDns = (d: NetDiagData) => {
    const active = d.adapters.find((a) => a.status === "Connected");
    if (!active?.dns?.length) return;
    const primary = active.dns[0];
    const match = DNS_PRESETS.find((p) => p.primary === primary);
    if (match) setDnsPreset(match.id);
  };

  const handleDnsChange = async (preset: string) => {
    setDnsPreset(preset);
    setSettingDns(true);
    setFeedback(null);
    setCmdOutput(null);
    try {
      const res = await invoke<ActionResult>("set_dns", { preset });
      setFeedback({ type: res.success ? "success" : "error", message: res.message });
    } catch (e) {
      setFeedback({ type: "error", message: String(e) });
    } finally {
      setSettingDns(false);
    }
  };

  const handleCommand = async (command: string) => {
    setRunningCmd(command);
    setFeedback(null);
    setCmdOutput(null);
    try {
      const res = await invoke<ActionResult>("run_network_command", { command });
      setFeedback({ type: res.success ? "success" : "error", message: res.message });
      if (res.output) setCmdOutput(res.output);
      if (res.success && (command === "renew_ip" || command === "flush_dns")) {
        setTimeout(load, 1500);
      }
    } catch (e) {
      setFeedback({ type: "error", message: String(e) });
    } finally {
      setRunningCmd(null);
    }
  };

  if (loading) return <div className="panel-loading">Running network diagnostics...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;
  if (!data) return null;

  const activeAdapter = data.adapters.find((a) => a.status === "Connected");

  return (
    <div className="netdiag-panel">
      {/* Active adapter card */}
      {activeAdapter && (
        <div className="adapter-card">
          <div className="adapter-header">
            <span className="adapter-name">{activeAdapter.name}</span>
            <span className="adapter-type">{activeAdapter.type}</span>
            <span className="adapter-connected">Connected</span>
          </div>
          <div className="adapter-grid">
            <div className="adapter-field">
              <span className="field-label">IPv4</span>
              <span className="field-value">{activeAdapter.ipv4 || "N/A"}</span>
            </div>
            <div className="adapter-field">
              <span className="field-label">Gateway</span>
              <span className="field-value">{activeAdapter.gateway || "N/A"}</span>
            </div>
            <div className="adapter-field">
              <span className="field-label">DNS</span>
              <span className="field-value">{activeAdapter.dns.join(", ") || "N/A"}</span>
            </div>
            <div className="adapter-field">
              <span className="field-label">Speed</span>
              <span className="field-value">{activeAdapter.speed || "N/A"}</span>
            </div>
            <div className="adapter-field">
              <span className="field-label">MAC</span>
              <span className="field-value mono">{activeAdapter.mac}</span>
            </div>
          </div>
        </div>
      )}

      {/* Speed test */}
      <div className="speed-test-section">
        <div className="speed-test-header">
          <h3>Speed Test</h3>
          <button
            className="speed-test-btn"
            disabled={speedTesting}
            onClick={async () => {
              setSpeedTesting(true);
              setSpeedResult(null);
              try {
                const res = await invoke<SpeedTestResult>("run_speed_test");
                setSpeedResult(res);
              } catch (e) {
                console.error("Speed test failed:", e);
              } finally {
                setSpeedTesting(false);
              }
            }}
          >
            {speedTesting ? "Testing..." : "Run Speed Test"}
          </button>
        </div>
        {speedTesting && (
          <div className="speed-testing-msg">Downloading test file... this may take a few seconds.</div>
        )}
        {speedResult && speedResult.status === "ok" && (
          <div className="speed-result">
            <div className="speed-value">{speedResult.download_mbps} <span className="speed-unit">Mbps</span></div>
            <div className="speed-detail">
              Downloaded {(speedResult.bytes_downloaded / (1024 * 1024)).toFixed(1)} MB in {(speedResult.duration_ms / 1000).toFixed(1)}s
            </div>
          </div>
        )}
        {speedResult && speedResult.status !== "ok" && (
          <div className="speed-fail">Speed test failed. Check your internet connection.</div>
        )}
      </div>

      {/* Wi-Fi info */}
      {data.wifi && (
        <div className="wifi-card">
          <h3>Wi-Fi</h3>
          <div className="wifi-grid">
            <div className="wifi-field">
              <span className="field-label">SSID</span>
              <span className="field-value">{data.wifi.ssid}</span>
            </div>
            <div className="wifi-field">
              <span className="field-label">Signal</span>
              <span className="field-value">{data.wifi.signal_percent}%</span>
            </div>
            <div className="wifi-field">
              <span className="field-label">Channel</span>
              <span className="field-value">{data.wifi.channel}</span>
            </div>
            <div className="wifi-field">
              <span className="field-label">Security</span>
              <span className="field-value">{data.wifi.security}</span>
            </div>
          </div>
        </div>
      )}

      {/* DNS Preset */}
      <div className="net-tools-section">
        <h3>DNS Server</h3>
        <div className="dns-grid">
          {DNS_PRESETS.map((p) => (
            <button
              key={p.id}
              className={`dns-card ${dnsPreset === p.id ? "active" : ""}`}
              onClick={() => handleDnsChange(p.id)}
              disabled={settingDns}
            >
              <span className="dns-label">{p.label}</span>
              {p.primary && <span className="dns-ips">{p.primary}, {p.secondary}</span>}
              <span className="dns-desc">{p.desc}</span>
              {dnsPreset === p.id && <span className="dns-active-badge">Active</span>}
            </button>
          ))}
        </div>
      </div>

      {/* Network commands */}
      <div className="net-tools-section">
        <h3>Network Tools</h3>
        <div className="net-cmd-grid">
          {NET_COMMANDS.map((c) => (
            <button
              key={c.id}
              className="net-cmd-btn"
              onClick={() => handleCommand(c.id)}
              disabled={runningCmd !== null}
            >
              <span className="cmd-icon">{c.icon}</span>
              <div className="cmd-text">
                <span className="cmd-label">
                  {runningCmd === c.id ? "Running..." : c.label}
                </span>
                <span className="cmd-desc">{c.desc}</span>
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Feedback */}
      {feedback && (
        <div className={`net-feedback feedback-${feedback.type}`}>
          {feedback.message}
        </div>
      )}
      {cmdOutput && (
        <pre className="net-cmd-output">{cmdOutput}</pre>
      )}

      {/* Test results */}
      <div className="tests-section">
        <div className="tests-header">
          <h3>Diagnostic Tests</h3>
          <button className="rerun-btn" onClick={load}>Re-run</button>
        </div>
        <div className="tests-list">
          {data.tests.map((test, i) => (
            <div key={i} className="test-row">
              <span className={`test-indicator indicator-${test.status}`}>
                {test.status === "pass" ? "✔" : test.status === "warn" ? "⚠" : "✖"}
              </span>
              <div className="test-info">
                <span className="test-name">{test.name}</span>
                <span className="test-detail">{test.detail}</span>
              </div>
              {test.latency_ms !== null && (
                <span className="test-latency">{test.latency_ms}ms</span>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Other adapters */}
      {data.adapters.filter((a) => a.status !== "Connected").length > 0 && (
        <div className="other-adapters">
          <h3>Other Adapters</h3>
          {data.adapters
            .filter((a) => a.status !== "Connected")
            .map((a) => (
              <div key={a.name} className="adapter-row-small">
                <span className="adapter-name-small">{a.name}</span>
                <span className="adapter-type-small">{a.type}</span>
                <span className="adapter-status-small">{a.status}</span>
              </div>
            ))}
        </div>
      )}
    </div>
  );
}
