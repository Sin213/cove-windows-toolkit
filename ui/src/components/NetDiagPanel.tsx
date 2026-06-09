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

export default function NetDiagPanel() {
  const [data, setData] = useState<NetDiagData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    invoke<NetDiagData>("get_network_diagnostics")
      .then(setData)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  if (loading)
    return <div className="panel-loading">Running network diagnostics...</div>;
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

      {/* Test results */}
      <div className="tests-section">
        <h3>Diagnostic Tests</h3>
        <div className="tests-list">
          {data.tests.map((test, i) => (
            <div key={i} className="test-row">
              <span className={`test-indicator indicator-${test.status}`}>
                {test.status === "pass"
                  ? "✔"
                  : test.status === "warn"
                    ? "⚠"
                    : "✖"}
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
