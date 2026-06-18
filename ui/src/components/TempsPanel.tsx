import { useEffect, useState, useCallback } from "react";
import { invoke } from "../lib/tauri";
import "./TempsPanel.css";

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

  const load = useCallback(() => {
    setError(null);
    invoke<TempReport>("get_temperatures")
      .then((r) => {
        setReport(r);
        // LHM just launched - retry after it registers WMI
        if (r.lhm_status !== "active" && r.readings.length === 0) {
          setTimeout(() => {
            invoke<TempReport>("get_temperatures")
              .then(setReport)
              .catch(() => {});
          }, 4000);
        }
      })
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!autoRefresh) return;
    const id = setInterval(load, 3000);
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
        <button className="temps-refresh-btn" onClick={load}>Refresh</button>
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

      {report.readings.length === 0 && report.warnings.length === 0 && (
        <div className="temps-empty">
          No temperature sensors detected. Run as Administrator for ACPI access, or install
          Libre Hardware Monitor for detailed readings.
        </div>
      )}

      {categories.map((cat) => {
        const readings = grouped[cat];
        if (!readings || readings.length === 0) return null;
        return (
          <div key={cat} className="temps-category">
            <h3 className="temps-cat-title">{cat}</h3>
            <div className="temps-grid">
              {readings.map((r) => (
                <TempGauge key={r.sensor} reading={r} />
              ))}
            </div>
          </div>
        );
      })}
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
