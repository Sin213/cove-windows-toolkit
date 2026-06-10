import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import "./SfcPanel.css";

interface AdminStatus {
  is_admin: boolean;
  message: string;
}

interface ScanResult {
  tool: string;
  success: boolean;
  exit_code: number;
  output: string;
  summary: string;
}

export default function SfcPanel() {
  const [admin, setAdmin] = useState<AdminStatus | null>(null);
  const [dismResult, setDismResult] = useState<ScanResult | null>(null);
  const [sfcResult, setSfcResult] = useState<ScanResult | null>(null);
  const [running, setRunning] = useState<"idle" | "dism" | "sfc" | "both">("idle");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    invoke<AdminStatus>("check_admin_status")
      .then(setAdmin)
      .catch((e) => setError(String(e)));
  }, []);

  const runDism = async () => {
    setRunning("dism");
    setDismResult(null);
    setError(null);
    try {
      const r = await invoke<ScanResult>("run_dism_scan");
      setDismResult(r);
    } catch (e) {
      setError(String(e));
    } finally {
      setRunning("idle");
    }
  };

  const runSfc = async () => {
    setRunning("sfc");
    setSfcResult(null);
    setError(null);
    try {
      const r = await invoke<ScanResult>("run_sfc_scan");
      setSfcResult(r);
    } catch (e) {
      setError(String(e));
    } finally {
      setRunning("idle");
    }
  };

  const runBoth = async () => {
    setRunning("both");
    setDismResult(null);
    setSfcResult(null);
    setError(null);
    try {
      const dism = await invoke<ScanResult>("run_dism_scan");
      setDismResult(dism);
      const sfc = await invoke<ScanResult>("run_sfc_scan");
      setSfcResult(sfc);
    } catch (e) {
      setError(String(e));
    } finally {
      setRunning("idle");
    }
  };

  const isRunning = running !== "idle";

  return (
    <div className="sfc-panel">
      {/* Admin check */}
      {admin && !admin.is_admin && (
        <div className="sfc-admin-warning">
          <span className="admin-icon">⚠</span>
          <span>{admin.message}</span>
        </div>
      )}

      {/* Info */}
      <div className="sfc-info">
        <p>
          These tools scan and repair Windows system files. <strong>DISM</strong> repairs
          the component store, then <strong>SFC</strong> verifies and fixes individual
          system files. Run DISM first for best results.
        </p>
      </div>

      {/* Action buttons */}
      <div className="sfc-actions">
        <button className="sfc-btn sfc-btn-primary" onClick={runBoth} disabled={isRunning}>
          {running === "both" ? (dismResult ? "Running SFC..." : "Running DISM...") : "Run Full Scan (DISM + SFC)"}
        </button>
        <div className="sfc-btn-row">
          <button className="sfc-btn sfc-btn-secondary" onClick={runDism} disabled={isRunning}>
            {running === "dism" ? "Running DISM..." : "DISM Only"}
          </button>
          <button className="sfc-btn sfc-btn-secondary" onClick={runSfc} disabled={isRunning}>
            {running === "sfc" ? "Running SFC..." : "SFC Only"}
          </button>
        </div>
      </div>

      {isRunning && (
        <div className="sfc-progress">
          <div className="sfc-spinner" />
          <span>This can take 10-30 minutes. Do not close the app.</span>
        </div>
      )}

      {error && <div className="sfc-error">{error}</div>}

      {/* Results */}
      {dismResult && <ResultCard result={dismResult} />}
      {sfcResult && <ResultCard result={sfcResult} />}
    </div>
  );
}

function ResultCard({ result }: { result: ScanResult }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className={`sfc-result ${result.success ? "result-ok" : "result-fail"}`}>
      <div className="result-header">
        <div className="result-title">
          <span className={`result-dot ${result.success ? "dot-ok" : "dot-fail"}`} />
          <strong>{result.tool}</strong>
          <span className="result-code">Exit code: {result.exit_code}</span>
        </div>
        <button className="expand-btn" onClick={() => setExpanded(!expanded)}>
          {expanded ? "Hide output" : "Show output"}
        </button>
      </div>
      <div className="result-summary">{result.summary}</div>
      {expanded && <pre className="result-output">{result.output}</pre>}
    </div>
  );
}
