import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import "./SecurityPanel.css";

interface DefenderStatus {
  real_time_enabled: boolean;
  definitions_age_days: number;
  last_scan: string;
  last_scan_type: string;
}

interface Finding {
  severity: string;
  title: string;
  detail: string;
  category: string;
}

interface SecurityData {
  defender: DefenderStatus;
  heuristic_findings: Finding[];
  scan_available: boolean;
}

interface ScanResult {
  success: boolean;
  threats_found: number;
  message: string;
}

interface HeuristicResult {
  findings: Finding[];
  scan_time_ms: number;
}

const SEV_ICON: Record<string, string> = {
  Critical: "✖",
  Warning: "⚠",
  Info: "ℹ",
};

const SEV_ORDER = ["Critical", "Warning", "Info"];

export default function SecurityPanel() {
  const [data, setData] = useState<SecurityData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [heuristicFindings, setHeuristicFindings] = useState<Finding[]>([]);
  const [heuristicTime, setHeuristicTime] = useState<number | null>(null);
  const [heuristicRunning, setHeuristicRunning] = useState(false);

  useEffect(() => {
    invoke<SecurityData>("get_security_status")
      .then(setData)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const handleDefenderScan = async (scanType: string) => {
    setScanning(scanType);
    setScanResult(null);
    try {
      const result = await invoke<ScanResult>("run_defender_scan", { scanType });
      setScanResult(result);
    } catch (e) {
      console.error("Scan failed:", e);
    } finally {
      setScanning(null);
    }
  };

  const handleHeuristic = async () => {
    setHeuristicRunning(true);
    setHeuristicFindings([]);
    setHeuristicTime(null);
    try {
      const result = await invoke<HeuristicResult>("run_heuristic_scan");
      setHeuristicFindings(result.findings);
      setHeuristicTime(result.scan_time_ms);
    } catch (e) {
      console.error("Heuristic scan failed:", e);
    } finally {
      setHeuristicRunning(false);
    }
  };

  if (loading) return <div className="panel-loading">Checking security status...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;
  if (!data) return null;

  const d = data.defender;

  const formatDate = (iso: string) => {
    try {
      return new Date(iso).toLocaleString();
    } catch {
      return iso;
    }
  };

  const grouped = SEV_ORDER.map((sev) => ({
    severity: sev,
    findings: heuristicFindings.filter((f) => f.severity === sev),
  })).filter((g) => g.findings.length > 0);

  return (
    <div className="security-panel">
      {/* Defender status */}
      <div className="defender-status">
        <div className="defender-stat">
          <span className="defender-stat-label">Real-time Protection</span>
          <span className={`defender-stat-value ${d.real_time_enabled ? "status-good" : "status-bad"}`}>
            {d.real_time_enabled ? "ON" : "OFF"}
          </span>
        </div>
        <div className="defender-stat">
          <span className="defender-stat-label">Definitions</span>
          <span className={`defender-stat-value ${d.definitions_age_days > 3 ? "status-warn" : "status-good"}`}>
            {d.definitions_age_days === 0 ? "Up to date" : `${d.definitions_age_days} day${d.definitions_age_days !== 1 ? "s" : ""} old`}
          </span>
        </div>
        <div className="defender-stat">
          <span className="defender-stat-label">Last Scan</span>
          <span className="defender-stat-value">{formatDate(d.last_scan)}</span>
        </div>
        <div className="defender-stat">
          <span className="defender-stat-label">Scan Type</span>
          <span className="defender-stat-value">{d.last_scan_type}</span>
        </div>
      </div>

      {/* Defender scan buttons */}
      <div className="defender-actions">
        <button
          className="scan-btn primary"
          onClick={() => handleDefenderScan("quick")}
          disabled={!!scanning}
        >
          {scanning === "quick" ? "Scanning..." : "Quick Scan"}
        </button>
        <button
          className="scan-btn"
          onClick={() => handleDefenderScan("full")}
          disabled={!!scanning}
        >
          {scanning === "full" ? "Scanning..." : "Full Scan"}
        </button>
      </div>

      {/* Scan result banner */}
      {scanResult && (
        <div className={`scan-result-banner ${scanResult.threats_found > 0 ? "threats" : "clean"}`}>
          <span>{scanResult.threats_found > 0 ? "⚠" : "✔"}</span>
          <span>{scanResult.message}</span>
        </div>
      )}

      {/* Heuristic section */}
      <div className="heuristic-section">
        <div className="heuristic-header">
          <h3>Heuristic Scan</h3>
          <button
            className="scan-btn"
            onClick={handleHeuristic}
            disabled={heuristicRunning}
          >
            {heuristicRunning ? "Scanning..." : "Run Heuristic Scan"}
          </button>
        </div>

        {heuristicFindings.length === 0 && heuristicTime === null && (
          <div className="no-findings">
            Click "Run Heuristic Scan" to check for suspicious processes, persistence, integrity issues, and browser extensions.
          </div>
        )}

        {heuristicFindings.length === 0 && heuristicTime !== null && (
          <div className="no-findings">
            No suspicious activity detected.
          </div>
        )}

        {grouped.map((group) => (
          <div key={group.severity} className="findings-group">
            <div className={`findings-group-title sev-${group.severity.toLowerCase()}`}>
              <span>{SEV_ICON[group.severity]}</span>
              <span>{group.severity} ({group.findings.length})</span>
            </div>
            {group.findings.map((f, i) => (
              <div key={i} className="finding-item">
                <span className={`finding-icon sev-${f.severity.toLowerCase()}`}>
                  {SEV_ICON[f.severity]}
                </span>
                <div className="finding-content">
                  <div className="finding-title">{f.title}</div>
                  <div className="finding-detail">{f.detail}</div>
                </div>
                <span className="finding-category">{f.category}</span>
              </div>
            ))}
          </div>
        ))}

        {heuristicTime !== null && (
          <div className="scan-time">Scan completed in {heuristicTime}ms</div>
        )}
      </div>
    </div>
  );
}
