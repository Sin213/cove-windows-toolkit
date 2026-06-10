import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import "./DiffPanel.css";

interface DiffChanges {
  new_startup_items: string[];
  removed_startup_items: string[];
  new_programs: string[];
  removed_programs: string[];
  new_bloatware: string[];
  health_score_change: number;
  disk_free_change: number;
  temp_size_change: number;
  critical_event_change: number;
  warning_event_change: number;
}

interface DiffData {
  has_previous: boolean;
  previous_timestamp?: string;
  changes?: DiffChanges;
}

function formatBytes(b: number): string {
  const abs = Math.abs(b);
  if (abs >= 1e9) return `${(b / 1e9).toFixed(1)} GB`;
  if (abs >= 1e6) return `${(b / 1e6).toFixed(0)} MB`;
  return `${(b / 1e3).toFixed(0)} KB`;
}

function formatTimestamp(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

export default function DiffPanel() {
  const [data, setData] = useState<DiffData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [snapping, setSnapping] = useState(false);
  const [snapDone, setSnapDone] = useState(false);

  useEffect(() => {
    invoke<DiffData>("get_machine_diff")
      .then(setData)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const handleSnapshot = async () => {
    setSnapping(true);
    try {
      await invoke("take_snapshot");
      setSnapDone(true);
    } catch (e) {
      console.error("Snapshot failed:", e);
    } finally {
      setSnapping(false);
    }
  };

  if (loading) return <div className="panel-loading">Checking for previous snapshots...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;
  if (!data) return null;

  if (!data.has_previous) {
    return (
      <div className="diff-panel">
        <div className="diff-first-visit">
          <div className="diff-first-visit-icon">📋</div>
          <h2>First visit to this machine</h2>
          <p>No previous snapshot found. A baseline snapshot will be saved when you run diagnostics or take a snapshot manually.</p>
          <button className="diff-snapshot-btn" onClick={handleSnapshot} disabled={snapping || snapDone}>
            {snapDone ? "Snapshot Saved" : snapping ? "Saving..." : "Take Baseline Snapshot"}
          </button>
        </div>
      </div>
    );
  }

  const c = data.changes!;

  const metrics: { label: string; value: string; direction: "positive" | "negative" | "neutral" }[] = [
    {
      label: "Health Score",
      value: c.health_score_change === 0 ? "No change" : `${c.health_score_change > 0 ? "+" : ""}${c.health_score_change}`,
      direction: c.health_score_change > 0 ? "positive" : c.health_score_change < 0 ? "negative" : "neutral",
    },
    {
      label: "Free Disk Space",
      value: c.disk_free_change === 0 ? "No change" : `${c.disk_free_change > 0 ? "+" : ""}${formatBytes(c.disk_free_change)}`,
      direction: c.disk_free_change > 0 ? "positive" : c.disk_free_change < 0 ? "negative" : "neutral",
    },
    {
      label: "Temp File Size",
      value: c.temp_size_change === 0 ? "No change" : `${c.temp_size_change > 0 ? "+" : ""}${formatBytes(c.temp_size_change)}`,
      direction: c.temp_size_change > 0 ? "negative" : c.temp_size_change < 0 ? "positive" : "neutral",
    },
    {
      label: "Critical Events",
      value: c.critical_event_change === 0 ? "No change" : `${c.critical_event_change > 0 ? "+" : ""}${c.critical_event_change}`,
      direction: c.critical_event_change > 0 ? "negative" : c.critical_event_change < 0 ? "positive" : "neutral",
    },
    {
      label: "Warning Events",
      value: c.warning_event_change === 0 ? "No change" : `${c.warning_event_change > 0 ? "+" : ""}${c.warning_event_change}`,
      direction: c.warning_event_change > 0 ? "negative" : c.warning_event_change < 0 ? "positive" : "neutral",
    },
  ];

  const lists: { title: string; items: string[]; icon: string; cls: string }[] = [
    ...(c.new_startup_items.length > 0 ? [{ title: `${c.new_startup_items.length} New Startup Items`, items: c.new_startup_items, icon: "+", cls: "added" }] : []),
    ...(c.removed_startup_items.length > 0 ? [{ title: `${c.removed_startup_items.length} Removed Startup Items`, items: c.removed_startup_items, icon: "-", cls: "removed" }] : []),
    ...(c.new_programs.length > 0 ? [{ title: `${c.new_programs.length} New Programs`, items: c.new_programs, icon: "+", cls: "added" }] : []),
    ...(c.removed_programs.length > 0 ? [{ title: `${c.removed_programs.length} Removed Programs`, items: c.removed_programs, icon: "-", cls: "removed" }] : []),
    ...(c.new_bloatware.length > 0 ? [{ title: `${c.new_bloatware.length} New Bloatware`, items: c.new_bloatware, icon: "+", cls: "added" }] : []),
  ];

  return (
    <div className="diff-panel">
      <div className="diff-timestamp">
        Last scanned: {formatTimestamp(data.previous_timestamp!)}
      </div>

      <div className="diff-grid">
        {metrics.map((m) => (
          <div key={m.label} className="diff-row">
            <span className="diff-row-label">{m.label}</span>
            <span className={`diff-row-value ${m.direction}`}>{m.value}</span>
          </div>
        ))}
      </div>

      {lists.map((list) => (
        <div key={list.title} className="diff-list-section">
          <div className="diff-list-title">{list.title}</div>
          <div className="diff-list-items">
            {list.items.map((item) => (
              <div key={item} className="diff-list-item">
                <span className={`diff-list-icon ${list.cls}`}>{list.icon}</span>
                <span>{item}</span>
              </div>
            ))}
          </div>
        </div>
      ))}

      <div className="diff-actions">
        <button className="diff-snapshot-btn" onClick={handleSnapshot} disabled={snapping || snapDone}>
          {snapDone ? "Snapshot Updated" : snapping ? "Saving..." : "Save New Snapshot"}
        </button>
      </div>
    </div>
  );
}
