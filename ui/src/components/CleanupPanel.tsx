import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import { formatBytes } from "../lib/format";
import ConfirmDialog from "./ConfirmDialog";
import "./CleanupPanel.css";

interface CleanupTarget {
  id: string;
  name: string;
  path: string;
  size_bytes: number;
  file_count: number;
  safety: string;
}

export default function CleanupPanel() {
  const [targets, setTargets] = useState<CleanupTarget[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [cleaning, setCleaning] = useState(false);
  const [cleaned, setCleaned] = useState<Record<string, boolean>>({});
  const [showConfirm, setShowConfirm] = useState(false);

  useEffect(() => {
    invoke<CleanupTarget[]>("get_cleanup_targets")
      .then((data) => {
        setTargets(data);
        // Select all green (safe) targets by default
        const sel: Record<string, boolean> = {};
        data.forEach((t) => {
          if (t.safety === "green") sel[t.id] = true;
        });
        setSelected(sel);
      })
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const toggle = (id: string) => {
    if (cleaned[id]) return;
    setSelected((s) => ({ ...s, [id]: !s[id] }));
  };

  const toggleAll = () => {
    const uncleaned = targets.filter((t) => !cleaned[t.id]);
    const allSelected = uncleaned.every((t) => selected[t.id]);
    const next: Record<string, boolean> = { ...selected };
    uncleaned.forEach((t) => {
      next[t.id] = !allSelected;
    });
    setSelected(next);
  };

  const selectedTargets = targets.filter(
    (t) => selected[t.id] && !cleaned[t.id]
  );
  const totalSize = selectedTargets.reduce((s, t) => s + t.size_bytes, 0);
  const totalFiles = selectedTargets.reduce((s, t) => s + t.file_count, 0);

  const handleClean = async () => {
    setCleaning(true);
    try {
      const ids = selectedTargets.map((t) => t.id);
      const res = await invoke<{ success: boolean; results: { id: string; success: boolean }[] }>(
        "run_cleanup",
        { ids }
      );
      // Mark only the targets that actually succeeded, per-result.
      const ok = new Set((res.results || []).filter((r) => r.success).map((r) => r.id));
      for (const t of selectedTargets) {
        if (ok.has(t.id)) setCleaned((s) => ({ ...s, [t.id]: true }));
      }
    } catch (e) {
      console.error("Cleanup failed:", e);
    } finally {
      setCleaning(false);
    }
  };

  if (loading)
    return <div className="panel-loading">Scanning cleanup targets...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;

  return (
    <div className="cleanup-panel">
      <div className="cleanup-summary">
        <div className="summary-stat">
          <span className="stat-value">{formatBytes(totalSize)}</span>
          <span className="stat-label">selected</span>
        </div>
        <div className="summary-stat">
          <span className="stat-value">
            {totalFiles.toLocaleString()}
          </span>
          <span className="stat-label">files</span>
        </div>
        <div className="summary-actions">
          <button className="select-all-btn" onClick={toggleAll}>
            Select All
          </button>
          <button
            className="clean-btn"
            onClick={() => {
              const hasYellow = selectedTargets.some((t) => t.safety !== "green");
              if (hasYellow) {
                setShowConfirm(true);
              } else {
                handleClean();
              }
            }}
            disabled={cleaning || selectedTargets.length === 0}
          >
            {cleaning ? "Cleaning..." : "Clean Selected"}
          </button>
        </div>
      </div>

      <div className="cleanup-list">
        {targets.map((target) => (
          <label
            key={target.id}
            className={`cleanup-item ${cleaned[target.id] ? "item-cleaned" : ""}`}
          >
            <input
              type="checkbox"
              checked={!!selected[target.id]}
              onChange={() => toggle(target.id)}
              disabled={cleaned[target.id]}
              className="cleanup-check"
            />
            <div className="cleanup-info">
              <div className="cleanup-name">{target.name}</div>
              <div className="cleanup-path">{target.path}</div>
            </div>
            <div className="cleanup-meta">
              <span className={`safety-badge safety-${target.safety}`}>{target.safety}</span>
              <div className="cleanup-size">{formatBytes(target.size_bytes)}</div>
              <div className="cleanup-files">
                {target.file_count.toLocaleString()} files
              </div>
            </div>
            {cleaned[target.id] && (
              <span className="cleaned-badge">Cleaned</span>
            )}
          </label>
        ))}
      </div>
      <ConfirmDialog
        open={showConfirm}
        title="Clean Selected Files"
        message={`This will delete ${formatBytes(totalSize)} across ${selectedTargets.length} targets, including system caches. This cannot be undone. Continue?`}
        safetyTier="Yellow"
        onConfirm={() => {
          setShowConfirm(false);
          handleClean();
        }}
        onCancel={() => setShowConfirm(false)}
      />
    </div>
  );
}
