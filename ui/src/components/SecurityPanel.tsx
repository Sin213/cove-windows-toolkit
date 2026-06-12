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

interface SecScan {
  running: boolean;
  started: boolean;
  kind: string;
  indeterminate: boolean;
  percent: number;
  step: number;
  total: number;
  phase: string;
  elapsed_secs: number;
  done: boolean;
  success: boolean;
  threats_found: number;
  findings: Finding[];
  message: string;
}

const SEV_ICON: Record<string, string> = { Critical: "✖", Warning: "⚠", Info: "ℹ" };
const SEV_ORDER = ["Critical", "Warning", "Info"];

function fmtElapsed(s: number) {
  const m = Math.floor(s / 60);
  const sec = s % 60;
  return `${m}:${sec.toString().padStart(2, "0")}`;
}

export default function SecurityPanel() {
  const [data, setData] = useState<SecurityData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [defScan, setDefScan] = useState<SecScan | null>(null);
  const [heurScan, setHeurScan] = useState<SecScan | null>(null);

  const pollDef = async () => {
    try {
      setDefScan(await invoke<SecScan>("get_security_scan", { slot: "defender" }));
    } catch {
      /* ignore */
    }
  };
  const pollHeur = async () => {
    try {
      setHeurScan(await invoke<SecScan>("get_security_scan", { slot: "heuristic" }));
    } catch {
      /* ignore */
    }
  };

  useEffect(() => {
    invoke<SecurityData>("get_security_status")
      .then(setData)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
    pollDef();
    pollHeur();
  }, []);

  const anyRunning = !!defScan?.running || !!heurScan?.running;
  useEffect(() => {
    if (!anyRunning) return;
    const id = setInterval(() => {
      pollDef();
      pollHeur();
    }, 500);
    return () => clearInterval(id);
  }, [anyRunning]);

  const startScan = async (kind: string) => {
    setError(null);
    try {
      const res = await invoke<{ success: boolean; message?: string }>("start_security_scan", { kind });
      if (!res.success) {
        setError(res.message || "Could not start scan.");
        return;
      }
      if (kind === "heuristic") pollHeur();
      else pollDef();
    } catch (e) {
      setError(String(e));
    }
  };

  const openDefender = () => invoke("open_windows_security").catch(() => {});

  if (loading) return <div className="panel-loading">Checking security status...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;
  if (!data) return null;

  const d = data.defender;

  const formatDate = (iso: string) => {
    if (!iso || Number.isNaN(Date.parse(iso))) return iso || "Unknown";
    return new Date(iso).toLocaleString();
  };

  const busy = !!defScan?.running || !!heurScan?.running;
  const heurFindings: Finding[] = (heurScan?.done ? heurScan.findings : []) || [];
  const grouped = SEV_ORDER.map((sev) => ({
    severity: sev,
    findings: heurFindings.filter((f) => f.severity === sev),
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
        <button className="scan-btn primary" onClick={() => startScan("quick")} disabled={busy}>
          Quick Scan
        </button>
        <button className="scan-btn" onClick={() => startScan("full")} disabled={busy}>
          Full Scan
        </button>
        <button className="scan-btn" onClick={openDefender}>
          Open Windows Security
        </button>
      </div>

      {/* Defender scan live / result */}
      {defScan?.started && defScan.running && (
        <div className="scan-card">
          <div className="scan-phase">
            Running {defScan.kind === "full" ? "full" : "quick"} scan… {fmtElapsed(defScan.elapsed_secs)} elapsed
          </div>
          <div className="scan-bar">
            <div className="scan-bar-indet" />
          </div>
          <div className="scan-hint">
            Windows Defender doesn't report a live percentage, so this shows elapsed time. The scan keeps
            running even if you switch tabs, and the result appears here when it finishes.
          </div>
        </div>
      )}
      {defScan?.started && defScan.done && (
        <div className={`scan-result-banner ${defScan.threats_found > 0 ? "threats" : defScan.success ? "clean" : "threats"}`}>
          <span>{defScan.threats_found > 0 ? "⚠" : defScan.success ? "✔" : "✖"}</span>
          <span>{defScan.message}</span>
        </div>
      )}

      {/* Heuristic section */}
      <div className="heuristic-section">
        <div className="heuristic-header">
          <h3>Heuristic Scan</h3>
          <button className="scan-btn" onClick={() => startScan("heuristic")} disabled={busy}>
            {heurScan?.running ? "Scanning…" : "Run Heuristic Scan"}
          </button>
        </div>

        {heurScan?.running && (
          <div className="scan-live">
            <div className="scan-bar">
              <div className="scan-bar-fill" style={{ width: `${heurScan.percent}%` }} />
            </div>
            <div className="scan-phase">
              {heurScan.total > 0 ? `Step ${heurScan.step} of ${heurScan.total} · ` : ""}
              {heurScan.phase}
            </div>
          </div>
        )}

        {!heurScan?.started && (
          <div className="no-findings">
            Click "Run Heuristic Scan" to check for suspicious processes, hosts-file tampering, and browser
            extensions.
          </div>
        )}

        {heurScan?.done && grouped.length === 0 && (
          <div className="no-findings">No suspicious activity detected.</div>
        )}

        {grouped.map((group) => (
          <div key={group.severity} className="findings-group">
            <div className={`findings-group-title sev-${group.severity.toLowerCase()}`}>
              <span>{SEV_ICON[group.severity]}</span>
              <span>
                {group.severity} ({group.findings.length})
              </span>
            </div>
            {group.findings.map((f, i) => (
              <div key={i} className="finding-item">
                <span className={`finding-icon sev-${f.severity.toLowerCase()}`}>{SEV_ICON[f.severity]}</span>
                <div className="finding-content">
                  <div className="finding-title">{f.title}</div>
                  <div className="finding-detail">{f.detail}</div>
                </div>
                <span className="finding-category">{f.category}</span>
              </div>
            ))}
          </div>
        ))}

        {heurScan?.done && <div className="scan-time">{heurScan.message}</div>}
      </div>
    </div>
  );
}
