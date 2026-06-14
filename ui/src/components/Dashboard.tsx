import { useEffect, useState } from "react";
import type { View } from "../App";
import { invoke } from "../lib/tauri";
import Icon from "./Icon";
import "./Dashboard.css";

interface Props {
  onNavigate: (v: View) => void;
}

interface HealthReport {
  score: number;
  findings: { severity: string }[];
}

interface DiagModule {
  id: string;
  name: string;
  severity: string;
}

interface DiagResult {
  overall_severity: string;
  modules: DiagModule[];
  activated: boolean;
}

interface Preset {
  id: string;
  name: string;
  description: string;
  actions: { module: string; action_id: string; display_name: string }[];
}

interface PresetResult {
  success: boolean;
  total: number;
  succeeded: number;
  failed: number;
}

interface CategoryCard {
  id: View;
  title: string;
  description: string;
  icon: string;
  badge?: string;
  badgeColor?: string;
  section: "optimize" | "diagnose";
}

const OPTIMIZER_CARDS: CategoryCard[] = [
  {
    id: "performance",
    title: "Performance Tweaks",
    description: "NTFS, prefetch, CPU scheduling, boot, and gaming optimizations",
    icon: "⚡",
    section: "optimize",
  },
  {
    id: "visual",
    title: "Visual Effects",
    description: "Disable transparency, animations, and cosmetic effects",
    icon: "◑",
    section: "optimize",
  },
  {
    id: "privacy",
    title: "Privacy & Telemetry",
    description: "Control data collection, ads, and tracking",
    icon: "◉",
    section: "optimize",
  },
  {
    id: "services",
    title: "Service Optimizer",
    description: "Disable unnecessary background services",
    icon: "⚙",
    section: "optimize",
  },
  {
    id: "startup",
    title: "Startup Manager",
    description: "Control what runs at boot",
    icon: "▶",
    section: "optimize",
  },
  {
    id: "cleanup",
    title: "Disk Cleanup",
    description: "Remove temp files, caches, and Windows bloat",
    icon: "⊘",
    section: "optimize",
  },
  {
    id: "bloatware",
    title: "Bloatware Remover",
    description: "Uninstall preinstalled Microsoft, OEM, and sponsored apps",
    icon: "🗑",
    section: "optimize",
  },
  {
    id: "power",
    title: "Power Plan",
    description: "Switch to High Performance, adjust sleep settings",
    icon: "⚡",
    section: "optimize",
  },
];

const DIAGNOSTIC_CARDS: CategoryCard[] = [
  {
    id: "health",
    title: "System Health",
    description: "Disk, RAM, CPU, SMART - quick triage",
    icon: "♥",
    section: "diagnose",
  },
  {
    id: "eventlog",
    title: "Event Log Analyzer",
    description: "Critical errors, warnings, crash patterns",
    icon: "☰",
    section: "diagnose",
  },
  {
    id: "bsod",
    title: "BSOD Analyzer",
    description: "Read minidumps, decode bug check codes",
    icon: "⬛",
    section: "diagnose",
  },
  {
    id: "netdiag",
    title: "Network Diagnostics",
    description: "DNS, ping, traceroute, Wi-Fi, adapter health",
    icon: "⇆",
    section: "diagnose",
  },
  {
    id: "updates",
    title: "Windows Update",
    description: "Pending updates, CBS errors, component health",
    icon: "↻",
    section: "diagnose",
  },
  {
    id: "security",
    title: "Security Scan",
    description: "Defender status, heuristic scan for suspicious activity",
    icon: "🔒",
    section: "diagnose",
  },
  {
    id: "runtimes",
    title: "Runtimes",
    description: ".NET, Visual C++, DirectX, Java - installed versions",
    icon: "⊞",
    section: "diagnose",
  },
];

function ScoreRing({ score, size = 108, stroke = 9 }: { score: number | null; size?: number; stroke?: number }) {
  const r = (size - stroke) / 2 - 2;
  const circumference = 2 * Math.PI * r;
  const pct = score !== null ? score / 100 : 0;
  const offset = circumference * (1 - pct);
  const cx = size / 2;
  const color =
    score === null
      ? "var(--ink-3)"
      : score >= 90
        ? "var(--green)"
        : score >= 70
          ? "var(--yellow)"
          : score >= 50
            ? "var(--orange)"
            : "var(--red)";

  return (
    <div className="score-ring-wrapper" style={{ width: size, height: size }}>
      <svg viewBox={`0 0 ${size} ${size}`} className="score-ring" style={{ transform: "rotate(-90deg)" }}>
        <circle cx={cx} cy={cx} r={r} fill="none" stroke="var(--line-2)" strokeWidth={stroke} />
        <circle
          cx={cx}
          cy={cx}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{
            transition: "stroke-dashoffset 0.9s cubic-bezier(.4,0,.2,1)",
            filter: score !== null ? `drop-shadow(0 0 6px color-mix(in oklch, ${color} 50%, transparent))` : undefined,
          }}
        />
      </svg>
      <div className="score-text" style={{ color }}>
        {score !== null ? score : "--"}
      </div>
      <div className="score-label">Health</div>
    </div>
  );
}

function Card({
  card,
  onClick,
}: {
  card: CategoryCard;
  onClick: () => void;
}) {
  return (
    <button className="card" onClick={onClick}>
      <div className="card-header">
        <span className="card-icon"><Icon name={card.id} size={19} /></span>
        {card.badge && (
          <span className={`card-badge ${card.badgeColor || ""}`}>
            {card.badge}
          </span>
        )}
      </div>
      <div className="card-title">{card.title}</div>
      <div className="card-desc">{card.description}</div>
    </button>
  );
}

const SEVERITY_ICON: Record<string, string> = {
  Ok: "✔",
  Info: "ℹ",
  Warning: "⚠",
  Critical: "✖",
};

const SEVERITY_CLASS: Record<string, string> = {
  Ok: "sev-ok",
  Info: "sev-ok",
  Warning: "sev-warning",
  Critical: "sev-critical",
};

export default function Dashboard({ onNavigate }: Props) {
  const [score, setScore] = useState<number | null>(null);
  const [statusText, setStatusText] = useState("Loading...");
  const [diagRunning, setDiagRunning] = useState(false);
  const [diagResult, setDiagResult] = useState<DiagResult | null>(null);
  const [presets, setPresets] = useState<Preset[]>([]);
  const [presetRunning, setPresetRunning] = useState<string | null>(null);
  const [presetResult, setPresetResult] = useState<PresetResult | null>(null);
  const [exporting, setExporting] = useState(false);
  const [exportPath, setExportPath] = useState<string | null>(null);

  useEffect(() => {
    invoke<HealthReport>("get_health_report")
      .then((report) => {
        setScore(report.score);
        const warnings = report.findings.filter(
          (f) => f.severity === "Warning" || f.severity === "Critical"
        ).length;
        if (warnings === 0) {
          setStatusText("All checks passed. System looks healthy.");
        } else {
          setStatusText(
            `${warnings} finding${warnings > 1 ? "s" : ""} need attention. Click System Health for details.`
          );
        }
      })
      .catch(() => {
        setStatusText("Ready to scan. Could not reach backend.");
      });

    invoke<Preset[]>("get_presets")
      .then(setPresets)
      .catch(() => {});
  }, []);

  const handleRunDiag = async () => {
    setDiagRunning(true);
    setDiagResult(null);
    try {
      const result = await invoke<DiagResult>("run_all_diagnostics");
      setDiagResult(result);
    } catch (e) {
      console.error("Diagnostics failed:", e);
    } finally {
      setDiagRunning(false);
    }
  };

  const handleRunPreset = async (preset: Preset) => {
    setPresetRunning(preset.id);
    setPresetResult(null);
    try {
      const result = await invoke<PresetResult>("run_preset", { id: preset.id });
      setPresetResult(result);
    } catch (e) {
      console.error("Preset failed:", e);
    } finally {
      setPresetRunning(null);
    }
  };

  // Update the health card badge with live score
  const diagCards = DIAGNOSTIC_CARDS.map((c) => {
    if (c.id === "health" && score !== null) {
      return {
        ...c,
        badge: `Score: ${score}`,
        badgeColor:
          score >= 90 ? "green" : score >= 70 ? "yellow" : "red",
      };
    }
    return c;
  });

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <div className="header-text">
          <h1>Cove Windows Toolkit</h1>
          <p className="subtitle">
            Tech support toolkit - optimize and diagnose safely
          </p>
        </div>
        <ScoreRing score={score} />
      </div>

      <div className="dashboard-status">
        <span className="status-dot" />
        <span>{statusText}</span>
      </div>

      {/* Run All Diagnostics + Export */}
      <div className="diag-batch-section">
        <div className="diag-batch-actions">
          <button
            className="diag-batch-btn"
            onClick={handleRunDiag}
            disabled={diagRunning}
          >
            {diagRunning ? "Running Diagnostics..." : "Run All Diagnostics"}
          </button>
          <button
            className="export-btn"
            disabled={exporting}
            onClick={async () => {
              setExporting(true);
              setExportPath(null);
              try {
                const res = await invoke<{ success: boolean; path: string }>("export_report");
                if (res.success) setExportPath(res.path);
              } catch (e) {
                console.error("Export failed:", e);
              } finally {
                setExporting(false);
              }
            }}
          >
            <Icon name="export" size={16} />
            {exporting ? "Exporting..." : "Export Report"}
          </button>
        </div>
        {exportPath && (
          <div className="export-result">
            Report saved and opened: <span className="export-path">{exportPath}</span>
          </div>
        )}
        {diagResult && (
          <div className="diag-results">
            <div className={`diag-overall ${SEVERITY_CLASS[diagResult.overall_severity]}`}>
              Overall: {diagResult.overall_severity}
            </div>
            <div className="diag-module-list">
              {diagResult.modules.map((m) => (
                <button
                  key={m.id}
                  className="diag-module-row"
                  onClick={() => onNavigate(m.id as View)}
                >
                  <span className={`diag-sev-icon ${SEVERITY_CLASS[m.severity]}`}>
                    {SEVERITY_ICON[m.severity]}
                  </span>
                  <span className="diag-module-name">{m.name}</span>
                  <span className={`diag-sev-label ${SEVERITY_CLASS[m.severity]}`}>
                    {m.severity}
                  </span>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Quick Actions (Presets) */}
      {presets.length > 0 && (
        <section className="dashboard-section">
          <h2>Quick Actions</h2>
          <div className="preset-grid">
            {presets.map((p) => (
              <div key={p.id} className="preset-card">
                <div className="preset-info">
                  <div className="preset-name">{p.name}</div>
                  <div className="preset-desc">{p.description}</div>
                  <div className="preset-count">{p.actions.length} actions (all Green tier)</div>
                </div>
                <button
                  className="preset-run-btn"
                  onClick={() => handleRunPreset(p)}
                  disabled={presetRunning === p.id}
                >
                  {presetRunning === p.id ? "Running..." : "Run"}
                </button>
              </div>
            ))}
          </div>
          {presetResult && (
            <div className="preset-result">
              <span className="preset-result-icon">
                {presetResult.failed === 0 ? "✔" : "⚠"}
              </span>
              <span>
                {presetResult.succeeded} of {presetResult.total} actions applied
                {presetResult.failed > 0 && ` (${presetResult.failed} failed)`}
              </span>
            </div>
          )}
        </section>
      )}

      <section className="dashboard-section">
        <h2>Optimize</h2>
        <div className="card-grid">
          {OPTIMIZER_CARDS.map((c) => (
            <Card key={c.id} card={c} onClick={() => onNavigate(c.id)} />
          ))}
        </div>
      </section>

      <section className="dashboard-section">
        <h2>Diagnose</h2>
        <div className="card-grid">
          {diagCards.map((c) => (
            <Card key={c.id} card={c} onClick={() => onNavigate(c.id)} />
          ))}
        </div>
      </section>
    </div>
  );
}
