import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
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

  const scoreColor =
    report.score >= 90
      ? "var(--green)"
      : report.score >= 70
        ? "var(--yellow)"
        : report.score >= 50
          ? "var(--orange)"
          : "var(--red)";

  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - report.score / 100);

  return (
    <div className="health-panel">
      <div className="health-hero">
        <div className="health-ring-wrap">
          <svg viewBox="0 0 128 128" className="health-ring">
            <circle
              cx="64"
              cy="64"
              r={radius}
              fill="none"
              stroke="var(--border)"
              strokeWidth="10"
            />
            <circle
              cx="64"
              cy="64"
              r={radius}
              fill="none"
              stroke={scoreColor}
              strokeWidth="10"
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={offset}
              transform="rotate(-90 64 64)"
              style={{ transition: "stroke-dashoffset 0.8s ease" }}
            />
          </svg>
          <div className="health-score" style={{ color: scoreColor }}>
            {report.score}
          </div>
          <div className="health-score-label">Health</div>
        </div>
        <button className="rescan-btn" onClick={load}>
          Rescan
        </button>
      </div>

      <div className="findings-list">
        {report.findings.map((f) => (
          <div key={f.id} className="finding-item">
            <span className={`severity-dot severity-${f.severity.toLowerCase()}`} />
            <div className="finding-content">
              <div className="finding-header">
                <span className="finding-title">{f.title}</span>
                <span className={`severity-badge sev-${f.severity.toLowerCase()}`}>
                  {f.severity}
                </span>
              </div>
              <div className="finding-detail">{f.detail}</div>
              {f.remediation && (
                <div className="finding-remediation">{f.remediation}</div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
