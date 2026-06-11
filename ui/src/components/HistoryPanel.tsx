import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import { timeAgo } from "../lib/format";
import "./HistoryPanel.css";

interface ChangeEntry {
  id: number;
  timestamp: string;
  module: string;
  name: string;
  tier: string;
  status: string;
}

export default function HistoryPanel() {
  const [entries, setEntries] = useState<ChangeEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [undoing, setUndoing] = useState<Record<number, boolean>>({});

  useEffect(() => {
    invoke<ChangeEntry[]>("get_change_history")
      .then(setEntries)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const handleUndo = async (entry: ChangeEntry) => {
    setUndoing((s) => ({ ...s, [entry.id]: true }));
    try {
      const res = await invoke<{ success: boolean }>("undo_change", { id: entry.id });
      if (res.success) {
        setEntries((prev) =>
          prev.map((e) => (e.id === entry.id ? { ...e, status: "undone" } : e))
        );
      }
    } catch (e) {
      console.error("Undo failed:", e);
    } finally {
      setUndoing((s) => ({ ...s, [entry.id]: false }));
    }
  };

  if (loading) return <div className="panel-loading">Loading history...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;

  if (entries.length === 0) {
    return (
      <div className="history-panel">
        <div className="history-empty">
          <h3>No changes yet</h3>
          <p>Changes you make will appear here with the ability to undo them.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="history-panel">
      <div className="history-list">
        {entries.map((entry) => {
          const isUndone = entry.status === "undone";
          const isFailed = entry.status === "failed";
          return (
            <div
              key={entry.id}
              className={`history-item ${isUndone ? "item-undone" : ""} ${isFailed ? "item-failed" : ""}`}
            >
              <div className="history-timeline">
                <span
                  className={`timeline-dot ${isUndone ? "dot-undone" : isFailed ? "dot-failed" : "dot-committed"}`}
                />
                <span className="timeline-line" />
              </div>
              <div className="history-content">
                <div className="history-header">
                  <span className="history-desc">{entry.name}</span>
                  <span className={`history-status status-${entry.status}`}>
                    {entry.status}
                  </span>
                </div>
                <div className="history-meta">
                  <span className="history-module">{entry.module}</span>
                  <span className={`tier-badge tier-${entry.tier.toLowerCase()}`}>{entry.tier}</span>
                  <span className="history-time">{timeAgo(entry.timestamp)}</span>
                </div>
              </div>
              <div className="history-actions">
                {!isUndone && entry.status === "committed" && (
                  <button
                    className="undo-btn"
                    onClick={() => handleUndo(entry)}
                    disabled={undoing[entry.id]}
                  >
                    {undoing[entry.id] ? "..." : "Undo"}
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
