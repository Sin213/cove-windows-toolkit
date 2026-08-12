import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "../lib/tauri";
import "./SecurityPanel.css";

interface DefenderStatus {
  real_time_enabled: boolean;
  definitions_age_days: number;
  last_scan: string;
  last_scan_type: string;
  known: boolean;
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

type SecurityScanKind = "quick" | "full" | "heuristic";

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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function responseMessage(value: unknown, fallback: string): string {
  return isRecord(value) && typeof value.message === "string" ? value.message : fallback;
}

function isSecurityData(value: unknown): value is SecurityData {
  if (!isRecord(value) || !isRecord(value.defender)) return false;
  const defender = value.defender;
  return (
    typeof defender.real_time_enabled === "boolean" &&
    typeof defender.definitions_age_days === "number" &&
    typeof defender.last_scan === "string" &&
    typeof defender.last_scan_type === "string" &&
    typeof defender.known === "boolean" &&
    Array.isArray(value.heuristic_findings) &&
    typeof value.scan_available === "boolean"
  );
}

function startingScan(kind: SecurityScanKind): SecScan {
  return {
    running: true,
    started: true,
    kind,
    indeterminate: kind !== "heuristic",
    percent: 0,
    step: 0,
    total: 0,
    phase: "Starting...",
    elapsed_secs: 0,
    done: false,
    success: false,
    threats_found: 0,
    findings: [],
    message: "",
  };
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
  const [loadError, setLoadError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [defScan, setDefScan] = useState<SecScan | null>(null);
  const [heurScan, setHeurScan] = useState<SecScan | null>(null);
  const [startingKind, setStartingKind] = useState<SecurityScanKind | null>(null);
  const mountedRef = useRef(true);
  const statusGenerationRef = useRef(0);
  const startInFlightRef = useRef(false);
  const pollInFlightRef = useRef({ defender: false, heuristic: false });
  const pollGenerationRef = useRef({ defender: 0, heuristic: 0 });

  const pollDef = useCallback(async () => {
    if (pollInFlightRef.current.defender) return;
    pollInFlightRef.current.defender = true;
    const generation = ++pollGenerationRef.current.defender;
    try {
      const scan = await invoke<SecScan>("get_security_scan", { slot: "defender" });
      if (mountedRef.current && generation === pollGenerationRef.current.defender) {
        setDefScan(scan);
      }
    } catch {
      /* ignore */
    } finally {
      pollInFlightRef.current.defender = false;
    }
  }, []);
  const pollHeur = useCallback(async () => {
    if (pollInFlightRef.current.heuristic) return;
    pollInFlightRef.current.heuristic = true;
    const generation = ++pollGenerationRef.current.heuristic;
    try {
      const scan = await invoke<SecScan>("get_security_scan", { slot: "heuristic" });
      if (mountedRef.current && generation === pollGenerationRef.current.heuristic) {
        setHeurScan(scan);
      }
    } catch {
      /* ignore */
    } finally {
      pollInFlightRef.current.heuristic = false;
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    const statusGeneration = ++statusGenerationRef.current;
    const pollGenerations = pollGenerationRef.current;
    invoke<unknown>("get_security_status")
      .then((status) => {
        if (!isSecurityData(status)) {
          throw new Error(
            responseMessage(status, "The backend returned an invalid security-status response.")
          );
        }
        if (mountedRef.current && statusGeneration === statusGenerationRef.current) {
          setData(status);
        }
      })
      .catch((e) => {
        if (mountedRef.current && statusGeneration === statusGenerationRef.current) {
          setLoadError(String(e));
        }
      })
      .finally(() => {
        if (mountedRef.current && statusGeneration === statusGenerationRef.current) {
          setLoading(false);
        }
      });
    queueMicrotask(pollDef);
    queueMicrotask(pollHeur);
    return () => {
      mountedRef.current = false;
      statusGenerationRef.current += 1;
      pollGenerations.defender += 1;
      pollGenerations.heuristic += 1;
    };
  }, [pollDef, pollHeur]);

  const anyRunning = !!defScan?.running || !!heurScan?.running;
  useEffect(() => {
    if (!anyRunning) return;
    const id = window.setInterval(() => {
      void pollDef();
      void pollHeur();
    }, 500);
    return () => clearInterval(id);
  }, [anyRunning, pollDef, pollHeur]);

  const startScan = async (kind: SecurityScanKind) => {
    if (startInFlightRef.current || anyRunning) return;
    startInFlightRef.current = true;
    setStartingKind(kind);
    setActionError(null);
    try {
      const res = await invoke<{ success: boolean; message?: string }>("start_security_scan", { kind });
      if (!res.success) {
        setActionError(res.message || "Could not start scan.");
        return;
      }
      if (kind === "heuristic") {
        pollGenerationRef.current.heuristic += 1;
        if (mountedRef.current) setHeurScan(startingScan(kind));
        void pollHeur();
      } else {
        pollGenerationRef.current.defender += 1;
        if (mountedRef.current) setDefScan(startingScan(kind));
        void pollDef();
      }
    } catch (e) {
      if (mountedRef.current) setActionError(String(e));
    } finally {
      startInFlightRef.current = false;
      if (mountedRef.current) setStartingKind(null);
    }
  };

  const openDefender = async () => {
    try {
      const result = await invoke<{ success?: boolean; message?: string }>("open_windows_security");
      if (!result?.success) setActionError(result?.message || "Could not open Windows Security.");
      else setActionError(null);
    } catch (openError) {
      setActionError(`Could not open Windows Security: ${String(openError)}`);
    }
  };

  if (loading) return <div className="panel-loading">Checking security status...</div>;
  if (loadError) return <div className="panel-error">Error: {loadError}</div>;
  if (!data) return null;

  const d = data.defender;

  const formatDate = (iso: string) => {
    if (!iso || Number.isNaN(Date.parse(iso))) return iso || "Unknown";
    return new Date(iso).toLocaleString();
  };

  const busy = anyRunning || startingKind !== null;
  const heurFindings: Finding[] = (heurScan?.done ? heurScan.findings : []) || [];
  const grouped = SEV_ORDER.map((sev) => ({
    severity: sev,
    findings: heurFindings.filter((f) => f.severity === sev),
  })).filter((g) => g.findings.length > 0);

  return (
    <div className="security-panel">
      {actionError && <div className="panel-error" role="alert">{actionError}</div>}
      {/* Defender status */}
      <div className="defender-status">
        <div className="defender-stat">
          <span className="defender-stat-label">Real-time Protection</span>
          <span
            className={`defender-stat-value ${
              !d.known ? "status-warn" : d.real_time_enabled ? "status-good" : "status-bad"
            }`}
          >
            {!d.known ? "Unknown" : d.real_time_enabled ? "ON" : "OFF"}
          </span>
        </div>
        <div className="defender-stat">
          <span className="defender-stat-label">Definitions</span>
          <span
            className={`defender-stat-value ${
              !d.known ? "status-warn" : d.definitions_age_days > 3 ? "status-warn" : "status-good"
            }`}
          >
            {!d.known
              ? "Unknown"
              : d.definitions_age_days === 0
                ? "Up to date"
                : `${d.definitions_age_days} day${d.definitions_age_days !== 1 ? "s" : ""} old`}
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
          {startingKind === "quick" ? "Starting..." : "Quick Scan"}
        </button>
        <button className="scan-btn" onClick={() => startScan("full")} disabled={busy}>
          {startingKind === "full" ? "Starting..." : "Full Scan"}
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
            {startingKind === "heuristic"
              ? "Starting..."
              : heurScan?.running
                ? "Scanning…"
                : "Run Heuristic Scan"}
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
