import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import "./DiffPanel.css";

interface DiffChanges {
  new_startup_items: string[];
  removed_startup_items: string[];
  new_programs: string[];
  removed_programs: string[];
  new_bloatware: string[];
  health_score_change: number | null;
  disk_free_change: number | null;
  temp_size_change: number | null;
  critical_event_change: number | null;
  warning_event_change: number | null;
}

interface DiffData {
  has_previous: boolean;
  success?: boolean;
  message?: string;
  previous_timestamp?: string;
  error?: string;
  changes?: DiffChanges;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function requireDiffData(value: unknown): DiffData {
  if (!isRecord(value)) {
    throw new Error("The backend returned an invalid machine-diff response.");
  }
  if (value.success === false) {
    throw new Error(
      typeof value.message === "string" ? value.message : "The machine comparison failed."
    );
  }
  if (typeof value.has_previous !== "boolean") {
    throw new Error(
      typeof value.message === "string"
        ? value.message
        : "The backend returned an invalid machine-diff response."
    );
  }
  if (value.has_previous) {
    const changes = value.changes;
    const listFields = [
      "new_startup_items",
      "removed_startup_items",
      "new_programs",
      "removed_programs",
      "new_bloatware",
    ];
    if (
      !isRecord(changes) ||
      !listFields.every((field) => Array.isArray(changes[field]))
    ) {
      throw new Error("The backend returned an incomplete machine-diff response.");
    }
  }
  return value as unknown as DiffData;
}

function formatBytes(b: number): string {
  const abs = Math.abs(b);
  if (abs >= 1e9) return `${(b / 1e9).toFixed(1)} GB`;
  if (abs >= 1e6) return `${(b / 1e6).toFixed(0)} MB`;
  return `${(b / 1e3).toFixed(0)} KB`;
}

function formatTimestamp(iso: string): string {
  const value = new Date(iso);
  return Number.isNaN(value.getTime()) ? "Unknown" : value.toLocaleString();
}

function metric(value: number | null, formatter: (value: number) => string = String): string {
  if (value === null) return "Unknown";
  if (value === 0) return "No change";
  return `${value > 0 ? "+" : ""}${formatter(value)}`;
}

export default function DiffPanel() {
  const [data, setData] = useState<DiffData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [snapping, setSnapping] = useState(false);
  const [snapDone, setSnapDone] = useState(false);

  useEffect(() => {
    invoke<unknown>("get_machine_diff")
      .then((value) => setData(requireDiffData(value)))
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const handleSnapshot = async () => {
    setSnapping(true);
    setError(null);
    try {
      const result = await invoke<{ success: boolean; message?: string }>("take_snapshot");
      if (!result.success) throw new Error(result.message || "Snapshot save failed.");
      setSnapDone(true);
      setData(requireDiffData(await invoke<unknown>("get_machine_diff")));
    } catch (e) {
      console.error("Snapshot failed:", e);
      setError(String(e));
    } finally {
      setSnapping(false);
    }
  };

  if (loading) return <div className="panel-loading">Checking for previous snapshots...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;
  if (!data) return null;

  if (!data.has_previous) {
    if (data.error) {
      return (
        <div className="diff-panel">
          <div className="diff-first-visit">
            <div className="panel-error" role="alert">
              The previous snapshot could not be read: {data.error}
            </div>
            <p>
              Taking a new baseline will replace the unreadable snapshot. Only continue if you no
              longer need the previous comparison.
            </p>
            <button className="diff-snapshot-btn" onClick={handleSnapshot} disabled={snapping || snapDone}>
              {snapDone ? "Snapshot Replaced" : snapping ? "Replacing..." : "Replace with New Baseline"}
            </button>
          </div>
        </div>
      );
    }
    return (
      <div className="diff-panel">
        <div className="diff-first-visit">
          <div className="diff-first-visit-icon">📋</div>
          <h2>First visit to this machine</h2>
          <p>No previous snapshot found. Take a baseline snapshot manually to compare future machine state.</p>
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
      value: metric(c.health_score_change),
      direction: c.health_score_change !== null && c.health_score_change > 0 ? "positive" : c.health_score_change !== null && c.health_score_change < 0 ? "negative" : "neutral",
    },
    {
      label: "Free Disk Space",
      value: metric(c.disk_free_change, formatBytes),
      direction: c.disk_free_change !== null && c.disk_free_change > 0 ? "positive" : c.disk_free_change !== null && c.disk_free_change < 0 ? "negative" : "neutral",
    },
    {
      label: "Temp File Size",
      value: metric(c.temp_size_change, formatBytes),
      direction: c.temp_size_change !== null && c.temp_size_change > 0 ? "negative" : c.temp_size_change !== null && c.temp_size_change < 0 ? "positive" : "neutral",
    },
    {
      label: "Critical Events",
      value: metric(c.critical_event_change),
      direction: c.critical_event_change !== null && c.critical_event_change > 0 ? "negative" : c.critical_event_change !== null && c.critical_event_change < 0 ? "positive" : "neutral",
    },
    {
      label: "Warning Events",
      value: metric(c.warning_event_change),
      direction: c.warning_event_change !== null && c.warning_event_change > 0 ? "negative" : c.warning_event_change !== null && c.warning_event_change < 0 ? "positive" : "neutral",
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
