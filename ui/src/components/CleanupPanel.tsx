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
  scan_error: string | null;
}

interface CleanupRunResult {
  id: string;
  success: boolean;
  partial: boolean;
  message: string;
  freed_bytes: number;
  deleted_files: number;
  skipped_items: number;
}

export default function CleanupPanel() {
  const [targets, setTargets] = useState<CleanupTarget[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [cleaning, setCleaning] = useState(false);
  const [cleaned, setCleaned] = useState<Record<string, boolean>>({});
  const [showConfirm, setShowConfirm] = useState(false);
  const [results, setResults] = useState<Record<string, CleanupRunResult>>({});

  useEffect(() => {
    invoke<CleanupTarget[]>("get_cleanup_targets")
      .then((data) => {
        setTargets(data);
        // Select all green (safe) targets by default
        const sel: Record<string, boolean> = {};
        data.forEach((t) => {
          if (t.safety === "green" && !t.scan_error) sel[t.id] = true;
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
    const selectable = targets.filter((t) => !cleaned[t.id] && !t.scan_error);
    const allSelected = selectable.every((t) => selected[t.id]);
    const next: Record<string, boolean> = { ...selected };
    selectable.forEach((t) => {
      next[t.id] = !allSelected;
    });
    setSelected(next);
  };

  const selectedTargets = targets.filter(
    (t) => selected[t.id] && !cleaned[t.id] && !t.scan_error
  );
  const uncleanedTargets = targets.filter(
    (t) => !cleaned[t.id] && !t.scan_error
  );
  const allSelected =
    uncleanedTargets.length > 0 && uncleanedTargets.every((t) => selected[t.id]);
  const totalSize = selectedTargets.reduce((s, t) => s + t.size_bytes, 0);
  const totalFiles = selectedTargets.reduce((s, t) => s + t.file_count, 0);

  const handleClean = async () => {
    setCleaning(true);
    try {
      const ids = selectedTargets.map((t) => t.id);
      const res = await invoke<{ success: boolean; results: CleanupRunResult[] }>(
        "run_cleanup",
        { ids }
      );
      const runResults = res.results || [];
      setResults(Object.fromEntries(runResults.map((result) => [result.id, result])));
      setCleaned((current) => {
        const next = { ...current };
        runResults.forEach((result) => {
          // A partial run leaves skipped files available for a later retry.
          if (result.success && !result.partial) next[result.id] = true;
        });
        return next;
      });
      setSelected((current) => {
        const next = { ...current };
        ids.forEach((id) => {
          next[id] = false;
        });
        return next;
      });

      // Reflect what remains instead of retaining the pre-clean sizes/counts.
      try {
        setTargets(await invoke<CleanupTarget[]>("get_cleanup_targets"));
      } catch (scanError) {
        console.error("Cleanup rescan failed:", scanError);
      }
    } catch (e) {
      console.error("Cleanup failed:", e);
      setError(`Cleanup failed: ${String(e)}`);
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
            {allSelected ? "Deselect All" : "Select All"}
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
      {Object.keys(results).length > 0 && (
        <div className="cleanup-results">
          {Object.entries(results).map(([id, result]) => (
            <div
              key={id}
              className={`cleanup-result ${
                !result.success
                  ? "cleanup-result-error"
                  : result.partial
                    ? "cleanup-result-partial"
                    : "cleanup-result-success"
              }`}
              role={result.success ? "status" : "alert"}
            >
              {targets.find((target) => target.id === id)?.name || id}: {result.message}
            </div>
          ))}
        </div>
      )}

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
              disabled={cleaned[target.id] || !!target.scan_error}
              className="cleanup-check"
            />
            <div className="cleanup-info">
              <div className="cleanup-name">{target.name}</div>
              <div className="cleanup-path">{target.path}</div>
              {target.scan_error && <div className="panel-error">Scan failed: {target.scan_error}</div>}
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
