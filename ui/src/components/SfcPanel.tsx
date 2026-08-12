import { useCallback, useEffect, useRef, useState } from "react";
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

type Key = "full" | "dism" | "sfc";

const KEYS: Key[] = ["full", "dism", "sfc"];
const TITLE: Record<Key, string> = {
  full: "Full Scan (DISM + SFC)",
  dism: "DISM",
  sfc: "SFC",
};

function startingProgress(): ScanProgress {
  return {
    running: true,
    started: true,
    percent: 0,
    phase: "Starting...",
    output_tail: [],
    done: false,
    success: false,
    summary: "",
    exit_code: 0,
  };
}

export default function SfcPanel() {
  const [admin, setAdmin] = useState<AdminStatus | null>(null);
  const [scans, setScans] = useState<Record<Key, ScanProgress | null>>({
    full: null,
    dism: null,
    sfc: null,
  });
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState<Key | null>(null);
  const mountedRef = useRef(true);
  const effectGenerationRef = useRef(0);
  const startInFlightRef = useRef(false);
  const pollInFlightRef = useRef<Record<Key, boolean>>({ full: false, dism: false, sfc: false });
  const pollGenerationRef = useRef<Record<Key, number>>({ full: 0, dism: 0, sfc: 0 });

  const poll = useCallback(async (key: Key) => {
    if (pollInFlightRef.current[key]) return;
    pollInFlightRef.current[key] = true;
    const generation = ++pollGenerationRef.current[key];
    try {
      const p = await invoke<ScanProgress>("get_scan_progress", { tool: key });
      if (mountedRef.current && generation === pollGenerationRef.current[key]) {
        setScans((s) => ({ ...s, [key]: p }));
      }
    } catch {
      /* ignore transient poll errors */
    } finally {
      pollInFlightRef.current[key] = false;
    }
  }, []);

  // On mount, resume whatever the backend is doing (scans outlive this panel).
  useEffect(() => {
    mountedRef.current = true;
    const effectGeneration = ++effectGenerationRef.current;
    const pollGenerations = pollGenerationRef.current;
    invoke<AdminStatus>("check_admin_status")
      .then((status) => {
        if (mountedRef.current && effectGeneration === effectGenerationRef.current) {
          setAdmin(status);
        }
      })
      .catch((e) => {
        if (mountedRef.current && effectGeneration === effectGenerationRef.current) {
          setError(String(e));
        }
      });
    queueMicrotask(() => {
      if (mountedRef.current && effectGeneration === effectGenerationRef.current) {
        KEYS.forEach((key) => void poll(key));
      }
    });
    return () => {
      mountedRef.current = false;
      effectGenerationRef.current += 1;
      KEYS.forEach((key) => {
        pollGenerations[key] += 1;
      });
    };
  }, [poll]);

  const anyRunning = KEYS.some((k) => scans[k]?.running);
  const busy = anyRunning || starting !== null;
  useEffect(() => {
    if (!anyRunning) return;
    const id = window.setInterval(() => KEYS.forEach((key) => void poll(key)), 250);
    return () => clearInterval(id);
  }, [anyRunning, poll]);

  const start = async (key: Key) => {
    if (startInFlightRef.current || anyRunning) return;
    startInFlightRef.current = true;
    setStarting(key);
    setError(null);
    try {
      const res = await invoke<{ success: boolean; message?: string }>("start_scan", { tool: key });
      if (!res.success) {
        setError(res.message || "Could not start scan.");
        return;
      }
      pollGenerationRef.current[key] += 1;
      if (mountedRef.current) {
        setScans((current) => ({ ...current, [key]: startingProgress() }));
      }
      void poll(key);
    } catch (e) {
      if (mountedRef.current) setError(String(e));
    } finally {
      startInFlightRef.current = false;
      if (mountedRef.current) setStarting(null);
    }
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
          Scans keep running in the background even if you switch tabs.
        </p>
      </div>

      <div className="sfc-actions">
        <button
          className="sfc-btn sfc-btn-primary"
          onClick={() => start("full")}
          disabled={busy}
        >
          {starting === "full" ? "Starting..." : "Run Full Scan (DISM + SFC)"}
        </button>
        <div className="sfc-btn-row">
          <button
            className="sfc-btn sfc-btn-secondary"
            onClick={() => start("dism")}
            disabled={busy}
          >
            {starting === "dism" ? "Starting..." : "DISM Only"}
          </button>
          <button
            className="sfc-btn sfc-btn-secondary"
            onClick={() => start("sfc")}
            disabled={busy}
          >
            {starting === "sfc" ? "Starting..." : "SFC Only"}
          </button>
        </div>
      </div>

      {error && <div className="sfc-error">{error}</div>}

      {KEYS.filter((k) => scans[k]?.started).map((k) => (
        <ScanCard key={k} title={TITLE[k]} data={scans[k]!} />
      ))}
    </div>
  );
}

function ScanCard({ title, data }: { title: string; data: ScanProgress }) {
  const running = data.running;
  const done = data.done && !running;
  const pct = Math.max(0, Math.min(100, data.percent ?? 0));

  return (
    <div className={`scan-card ${done ? (data.success ? "scan-ok" : "scan-fail") : ""}`}>
      <div className="scan-head">
        <div className="scan-title">
          <span
            className={`scan-dot ${
              running ? "dot-run" : done ? (data.success ? "dot-ok" : "dot-fail") : "dot-idle"
            }`}
          />
          <strong>{title}</strong>
        </div>
      </div>

      {running && (
        <div className="scan-live">
          <div className="scan-bar">
            <div className="scan-bar-fill" style={{ width: `${pct}%` }} />
          </div>
          <div className="scan-phase">
            {pct > 0 ? `${pct.toFixed(0)}% · ` : ""}
            {data.phase || "Working…"}
          </div>
          <div className="scan-hint">
            This can take 10–30 minutes. It keeps running if you switch tabs.
          </div>
        </div>
      )}

      {done && (
        <div className="scan-done">
          <div className="scan-summary">
            {data.summary} <span className="scan-exit">(exit {data.exit_code})</span>
          </div>
        </div>
      )}
    </div>
  );
}
