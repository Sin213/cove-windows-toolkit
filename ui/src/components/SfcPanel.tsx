import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import "./SfcPanel.css";

interface AdminStatus {
  is_admin: boolean;
  message: string;
}

interface ScanProgress {
  running: boolean;
  started: boolean;
  percent: number;
  phase: string;
  output_tail: string[];
  done: boolean;
  success: boolean;
  summary: string;
  exit_code: number;
}

type Tool = "dism" | "sfc";

const LABEL: Record<Tool, string> = { dism: "DISM", sfc: "SFC" };
const CMDLINE: Record<Tool, string> = {
  dism: "DISM /Online /Cleanup-Image /RestoreHealth",
  sfc: "sfc /scannow",
};

export default function SfcPanel() {
  const [admin, setAdmin] = useState<AdminStatus | null>(null);
  const [scans, setScans] = useState<Record<Tool, ScanProgress | null>>({ dism: null, sfc: null });
  const [error, setError] = useState<string | null>(null);

  const poll = async (tool: Tool) => {
    try {
      const p = await invoke<ScanProgress>("get_scan_progress", { tool });
      setScans((s) => ({ ...s, [tool]: p }));
    } catch {
      /* ignore transient poll errors */
    }
  };

  // On mount, resume whatever the backend is doing (scans outlive this panel).
  useEffect(() => {
    invoke<AdminStatus>("check_admin_status").then(setAdmin).catch((e) => setError(String(e)));
    poll("dism");
    poll("sfc");
  }, []);

  const anyRunning = !!scans.dism?.running || !!scans.sfc?.running;
  useEffect(() => {
    if (!anyRunning) return;
    const id = setInterval(() => {
      poll("dism");
      poll("sfc");
    }, 1000);
    return () => clearInterval(id);
  }, [anyRunning]);

  const start = async (tool: Tool) => {
    setError(null);
    try {
      const res = await invoke<{ success: boolean; message?: string }>("start_scan", { tool });
      if (!res.success) {
        setError(res.message || "Could not start scan.");
        return;
      }
      poll(tool);
    } catch (e) {
      setError(String(e));
    }
  };

  const openCmd = (tool: Tool) => {
    invoke("open_scan_in_terminal", { tool }).catch(() => {});
  };

  return (
    <div className="sfc-panel">
      {admin && !admin.is_admin && (
        <div className="sfc-admin-warning">
          <span className="admin-icon">⚠</span>
          <span>{admin.message}</span>
        </div>
      )}

      <div className="sfc-info">
        <p>
          These tools scan and repair Windows system files. <strong>DISM</strong> repairs the
          component store, then <strong>SFC</strong> verifies and fixes individual system files.
          Run DISM first for best results. Scans keep running in the background even if you switch
          tabs.
        </p>
      </div>

      {error && <div className="sfc-error">{error}</div>}

      <ScanCard tool="dism" data={scans.dism} onStart={() => start("dism")} onCmd={() => openCmd("dism")} />
      <ScanCard tool="sfc" data={scans.sfc} onStart={() => start("sfc")} onCmd={() => openCmd("sfc")} />
    </div>
  );
}

function ScanCard({
  tool,
  data,
  onStart,
  onCmd,
}: {
  tool: Tool;
  data: ScanProgress | null;
  onStart: () => void;
  onCmd: () => void;
}) {
  const [showFull, setShowFull] = useState(false);
  const running = !!data?.running;
  const done = !!data?.done && !running;
  const pct = Math.max(0, Math.min(100, data?.percent ?? 0));

  return (
    <div className={`scan-card ${done ? (data?.success ? "scan-ok" : "scan-fail") : ""}`}>
      <div className="scan-head">
        <div className="scan-title">
          <span
            className={`scan-dot ${
              running ? "dot-run" : done ? (data?.success ? "dot-ok" : "dot-fail") : "dot-idle"
            }`}
          />
          <strong>{LABEL[tool]}</strong>
          <span className="scan-cmd">{CMDLINE[tool]}</span>
        </div>
        <div className="scan-actions">
          <button className="scan-btn ghost" onClick={onCmd}>
            Open in CMD
          </button>
          <button className="scan-btn primary" onClick={onStart} disabled={running}>
            {running ? "Running…" : done ? "Run again" : "Run"}
          </button>
        </div>
      </div>

      {running && (
        <div className="scan-live">
          <div className="scan-bar">
            <div className="scan-bar-fill" style={{ width: `${pct}%` }} />
          </div>
          <div className="scan-phase">
            {pct > 0 ? `${pct.toFixed(0)}% · ` : ""}
            {data?.phase || "Working…"}
          </div>
          {data && data.output_tail.length > 0 && (
            <pre className="scan-console">{data.output_tail.join("\n")}</pre>
          )}
          <div className="scan-hint">
            This can take 10–30 minutes. It keeps running if you switch tabs.
          </div>
        </div>
      )}

      {done && (
        <div className="scan-done">
          <div className="scan-summary">
            {data?.summary} <span className="scan-exit">(exit {data?.exit_code})</span>
          </div>
          {data && data.output_tail.length > 0 && (
            <>
              <button className="scan-expand" onClick={() => setShowFull(!showFull)}>
                {showFull ? "Hide output" : "Show output"}
              </button>
              {showFull && <pre className="scan-console">{data.output_tail.join("\n")}</pre>}
            </>
          )}
        </div>
      )}
    </div>
  );
}
