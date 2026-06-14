import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import Icon from "./Icon";
import "./HealthPanel.css";

interface Finding {
  id: string;
  severity: string;
  title: string;
  detail: string;
  metric: Record<string, number | string> | null;
  remediation: string | null;
}

interface HealthReport {
  score: number;
  findings: Finding[];
}

function sevClass(severity: string): string {
  const s = severity.toLowerCase();
  if (s === "ok") return "ok";
  if (s === "warning") return "warning";
  if (s === "critical") return "critical";
  return "info";
}

function sevBadge(severity: string): string {
  return severity.toLowerCase() === "ok" ? "Healthy" : severity;
}

export default function HealthPanel() {
  const [report, setReport] = useState<HealthReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    setError(null);
    invoke<HealthReport>("get_health_report")
      .then(setReport)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
  }, []);

  if (loading) return <div className="panel-loading">Running health scan...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;
  if (!report) return null;

  const score = report.score;
  const scoreColor =
    score >= 90 ? "var(--green)" : score >= 70 ? "var(--yellow)" : score >= 50 ? "var(--orange)" : "var(--red)";
  const grade =
    score >= 90 ? "Excellent" : score >= 70 ? "Good standing" : score >= 50 ? "Needs attention" : "Critical";

  const attention = report.findings.filter(
    (f) => f.severity === "Warning" || f.severity === "Critical"
  ).length;
  const sub =
    attention === 0
      ? "All checks passed. Nothing requires action."
      : `${attention} finding${attention > 1 ? "s" : ""} worth a glance.`;

  const size = 104;
  const stroke = 10;
  const r = (size - stroke) / 2 - 2;
  const circumference = 2 * Math.PI * r;
  const offset = circumference * (1 - score / 100);
  const cx = size / 2;

  return (
    <div className="health-panel">
      <div className="health-hero">
        <div className="ring-wrap" style={{ width: size, height: size }}>
          <svg viewBox={`0 0 ${size} ${size}`} style={{ transform: "rotate(-90deg)" }}>
            <circle cx={cx} cy={cx} r={r} fill="none" stroke="var(--line-2)" strokeWidth={stroke} />
            <circle
              cx={cx}
              cy={cx}
              r={r}
              fill="none"
              stroke={scoreColor}
              strokeWidth={stroke}
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={offset}
              style={{
                transition: "stroke-dashoffset 0.9s cubic-bezier(.4,0,.2,1)",
                filter: `drop-shadow(0 0 6px color-mix(in oklch, ${scoreColor} 50%, transparent))`,
              }}
            />
          </svg>
          <span className="ring-num" style={{ color: scoreColor }}>{score}</span>
          <span className="ring-lbl">Health</span>
        </div>
        <div className="hh-body">
          <div className="hh-grade" style={{ color: scoreColor }}>{grade}</div>
          <div className="hh-sub">{sub}</div>
        </div>
        <button className="rescan-btn" onClick={load}>
          <Icon name="refresh" size={15} /> Rescan
        </button>
      </div>

      <div className="findings-list">
        {report.findings.map((f) => (
          <div key={f.id} className={`finding-item ${sevClass(f.severity)}`}>
            <span className="sev-bar" />
            <div className="finding-content">
              <span className="finding-title">{f.title}</span>
              <span className={`severity-badge ${sevClass(f.severity)}`}>{sevBadge(f.severity)}</span>
              <div className="finding-detail">{f.detail}</div>
              {f.remediation && <div className="finding-remediation">{f.remediation}</div>}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
