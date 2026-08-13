import { useEffect, useState, useCallback, useRef } from "react";
import { invoke } from "../lib/tauri";
import ConfirmDialog from "./ConfirmDialog";
import "./TempsPanel.css";

/** Values of `TempReport.lhm_status`, mirroring the backend constants. */
const CPU_PROVIDER_DRIVER_MISSING = "driver-missing";

const DRIVER_CONSENT_MESSAGE =
  "CPU temperature sensors can only be read through a kernel-mode driver. " +
  "Cove will install PawnIO, a signed open-source driver, for this purpose. " +
  "It stays installed until you remove it from Apps & Features, and Cove will " +
  "need a restart afterwards. Nothing else on this screen installs anything.";

interface TempReading {
  sensor: string;
  category: string;
  temperature_c: number;
  max_c: number | null;
  critical_c: number | null;
}

interface TempReport {
  readings: TempReading[];
  warnings: string[];
  lhm_status: string;
}

function tempColor(c: number, max: number | null): string {
  const limit = max ?? 100;
  const pct = (c / limit) * 100;
  if (pct >= 90) return "var(--red)";
  if (pct >= 75) return "var(--orange, var(--yellow))";
  if (pct >= 60) return "var(--yellow)";
  return "var(--green)";
}

function tempLabel(c: number, max: number | null): string {
  const limit = max ?? 100;
  const pct = (c / limit) * 100;
  if (pct >= 90) return "Critical";
  if (pct >= 75) return "Hot";
  if (pct >= 60) return "Warm";
  return "Normal";
}

export default function TempsPanel() {
  const [report, setReport] = useState<TempReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [driverPrompt, setDriverPrompt] = useState(false);
  const [installing, setInstalling] = useState(false);
  const [driverMessage, setDriverMessage] = useState<string | null>(null);
  const mountedRef = useRef(true);
  const inFlightRef = useRef(false);
  const requestGenerationRef = useRef(0);

  const load = useCallback(async () => {
    if (inFlightRef.current) return;
    inFlightRef.current = true;
    const generation = ++requestGenerationRef.current;
    setError(null);
    try {
      const nextReport = await invoke<TempReport>("get_temperatures");
      if (!mountedRef.current || generation !== requestGenerationRef.current) return;
      setReport(nextReport);
      // No sensor provider is started in the background any more, so an empty
      // result is final - re-polling it every few seconds only spawned repeated
      // storage queries for a result that cannot change on its own.
    } catch (loadError) {
      if (mountedRef.current && generation === requestGenerationRef.current) {
        setError(String(loadError));
      }
    } finally {
      inFlightRef.current = false;
      if (mountedRef.current && generation === requestGenerationRef.current) setLoading(false);
    }
  }, []);

  // Only ever reached from the confirmation dialog below.
  const installDriver = useCallback(async () => {
    setInstalling(true);
    setDriverMessage(null);
    try {
      const result = await invoke<{ success: boolean; message?: string }>(
        "install_cpu_sensor_driver",
      );
      if (!mountedRef.current) return;
      setDriverMessage(result.message ?? (result.success ? "Driver installed." : "Install failed."));
      if (result.success) void load();
    } catch (installError) {
      if (mountedRef.current) setDriverMessage(String(installError));
    } finally {
      if (mountedRef.current) setInstalling(false);
    }
  }, [load]);

  useEffect(() => {
    mountedRef.current = true;
    queueMicrotask(load);
    return () => {
      mountedRef.current = false;
      requestGenerationRef.current += 1;
    };
  }, [load]);

  useEffect(() => {
    if (!autoRefresh) return;
    const id = window.setInterval(() => void load(), 3000);
    return () => clearInterval(id);
  }, [autoRefresh, load]);

  if (loading) return <div className="panel-loading">Reading sensors...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;
  if (!report) return null;

  const categories = ["CPU", "GPU", "Disk", "Other"];
  const grouped: Record<string, TempReading[]> = {};
  for (const r of report.readings) {
    const cat = categories.includes(r.category) ? r.category : "Other";
    (grouped[cat] ??= []).push(r);
  }

  return (
    <div className="temps-panel">
      <div className="temps-toolbar">
        <button className="temps-refresh-btn" onClick={() => void load()}>Refresh</button>
        <label className="auto-refresh-label">
          <input type="checkbox" checked={autoRefresh} onChange={(e) => setAutoRefresh(e.target.checked)} />
          Auto-refresh (3s)
        </label>
      </div>

      {report.warnings.length > 0 && (
        <div className="temps-warnings">
          {report.warnings.map((w, i) => (
            <div key={i} className="temps-warning">
              <span className="warn-icon">⚠</span>
              <span>{w}</span>
            </div>
          ))}
        </div>
      )}

      {report.lhm_status === CPU_PROVIDER_DRIVER_MISSING && (
        <div className="temps-driver-optin">
          <button
            className="temps-driver-btn"
            onClick={() => setDriverPrompt(true)}
            disabled={installing}
          >
            {installing ? "Installing..." : "Enable CPU sensors"}
          </button>
          <span className="temps-driver-hint">
            Installs the signed PawnIO driver. Cove asks first and never installs it during a scan.
          </span>
        </div>
      )}

      {driverMessage && <div className="temps-driver-result">{driverMessage}</div>}

      {report.readings.length === 0 && report.warnings.length === 0 && (
        <div className="temps-empty">No temperature sensors were detected on this machine.</div>
      )}

      {categories.map((cat) => {
        const readings = grouped[cat];
        if (!readings || readings.length === 0) return null;
        return (
          <div key={cat} className="temps-category">
            <h3 className="temps-cat-title">{cat}</h3>
            <div className="temps-grid">
              {/* Sensor names are not unique across sources (a machine can
                  report several identically named ACPI zones), so index in. */}
              {readings.map((r, index) => (
                <TempGauge key={`${r.sensor}-${index}`} reading={r} />
              ))}
            </div>
          </div>
        );
      })}

      <ConfirmDialog
        open={driverPrompt}
        title="Install the CPU sensor driver?"
        message={DRIVER_CONSENT_MESSAGE}
        safetyTier="Yellow"
        onConfirm={() => {
          setDriverPrompt(false);
          void installDriver();
        }}
        onCancel={() => setDriverPrompt(false)}
      />
    </div>
  );
}

function TempGauge({ reading }: { reading: TempReading }) {
  const { sensor, temperature_c, max_c, critical_c } = reading;
  const limit = critical_c ?? max_c ?? 105;
  const pct = Math.min((temperature_c / limit) * 100, 100);
  // Use the same limit for color/label as the gauge fill so the severity color
  // never disagrees with the displayed arc.
  const color = tempColor(temperature_c, critical_c ?? max_c);
  const label = tempLabel(temperature_c, critical_c ?? max_c);

  const radius = 42;
  const circumference = Math.PI * radius;
  const offset = circumference * (1 - pct / 100);

  return (
    <div className="temp-gauge">
      <div className="gauge-ring-wrap">
        <svg viewBox="0 0 100 60" className="gauge-svg">
          <path
            d="M 8 52 A 42 42 0 0 1 92 52"
            fill="none"
            stroke="var(--border)"
            strokeWidth="7"
            strokeLinecap="round"
          />
          <path
            d="M 8 52 A 42 42 0 0 1 92 52"
            fill="none"
            stroke={color}
            strokeWidth="7"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            style={{ transition: "stroke-dashoffset 0.6s ease, stroke 0.3s" }}
          />
        </svg>
        <div className="gauge-temp" style={{ color }}>{temperature_c}°C</div>
      </div>
      <div className="gauge-label">{sensor}</div>
      <div className="gauge-status" style={{ color }}>{label}</div>
      {max_c != null && (
        <div className="gauge-max">Max: {max_c}°C</div>
      )}
    </div>
  );
}
