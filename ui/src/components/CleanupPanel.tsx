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
  scan_warning: string | null;
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

interface CleanupResponse {
  success: boolean;
  message?: string;
  results?: CleanupRunResult[];
}

function requireCleanupTargets(value: unknown): CleanupTarget[] {
  if (!Array.isArray(value)) {
    throw new Error("The backend returned an invalid cleanup-target list.");
  }
  return value as CleanupTarget[];
}

export default function CleanupPanel() {
  const [targets, setTargets] = useState<CleanupTarget[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [cleaning, setCleaning] = useState(false);
  const [cleaned, setCleaned] = useState<Record<string, boolean>>({});
  const [showConfirm, setShowConfirm] = useState(false);
  const [results, setResults] = useState<Record<string, CleanupRunResult>>({});

  useEffect(() => {
    invoke<unknown>("get_cleanup_targets")
      .then((value) => {
        const data = requireCleanupTargets(value);
        setTargets(data);
        // Select all green (safe) targets by default
        const sel: Record<string, boolean> = {};
        data.forEach((t) => {
          if (t.safety === "green" && !t.scan_error) sel[t.id] = true;
        });
        setSelected(sel);
      })
      .catch((e) => setLoadError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const toggle = (id: string) => {
    if (targets.find((target) => target.id === id)?.scan_error) return;
    setSelected((s) => ({ ...s, [id]: !s[id] }));
  };

  const toggleAll = () => {
    const selectable = targets.filter((target) => !target.scan_error);
    const allSelected = selectable.every((t) => selected[t.id]);
    const next: Record<string, boolean> = { ...selected };
    selectable.forEach((t) => {
      next[t.id] = !allSelected;
    });
    setSelected(next);
  };

  const selectedTargets = targets.filter(
    (t) => selected[t.id] && !t.scan_error
  );
  const uncleanedTargets = targets.filter((target) => !target.scan_error);
  const allSelected =
    uncleanedTargets.length > 0 && uncleanedTargets.every((t) => selected[t.id]);
  const totalSize = selectedTargets.reduce((s, t) => s + t.size_bytes, 0);
  const totalFiles = selectedTargets.reduce((s, t) => s + t.file_count, 0);

  const handleClean = async () => {
    setCleaning(true);
    setActionError(null);
    try {
      const ids = selectedTargets.map((t) => t.id);
      const res = await invoke<CleanupResponse>(
        "run_cleanup",
        { ids }
      );
      const returnedResults = Array.isArray(res.results) ? res.results : [];
      const returnedById = new Map(returnedResults.map((result) => [result.id, result]));
      const runResults = ids.map((id) => returnedById.get(id) ?? {
        id,
        success: false,
        partial: false,
        message: res.message || "The cleanup command did not return a result for this target.",
        freed_bytes: 0,
        deleted_files: 0,
        skipped_items: 0,
      });
      setResults(Object.fromEntries(runResults.map((result) => [result.id, result])));
      if (!res.success) {
        setActionError(res.message || "Cleanup did not complete for every selected target.");
      }
      setCleaned((current) => {
        const next = { ...current };
        runResults.forEach((result) => {
          // A partial run leaves skipped files available for a later retry.
          next[result.id] = result.success && !result.partial;
        });
        return next;
      });
      setSelected((current) => {
        const next = { ...current };
        runResults.forEach((result) => {
          // Keep partial, failed, and missing results selected for a one-click retry.
          next[result.id] = !result.success || result.partial;
        });
        return next;
      });

      // Reflect what remains instead of retaining the pre-clean sizes/counts.
      try {
        const refreshed = requireCleanupTargets(await invoke<unknown>("get_cleanup_targets"));
        setTargets(refreshed);
        setSelected((current) => {
          const next = { ...current };
          refreshed.forEach((target) => {
            if (target.scan_error) next[target.id] = false;
          });
          return next;
        });
        setCleaned((current) => {
          const next = { ...current };
          refreshed.forEach((target) => {
            if (
              target.size_bytes > 0 ||
              target.file_count > 0 ||
              target.scan_error ||
              target.scan_warning
            ) {
              next[target.id] = false;
            }
          });
          return next;
        });
      } catch (scanError) {
        console.error("Cleanup rescan failed:", scanError);
        setActionError((current) =>
          [current, `Cleanup finished, but the remaining files could not be rescanned: ${String(scanError)}`]
            .filter(Boolean)
            .join(" ")
        );
      }
    } catch (e) {
      console.error("Cleanup failed:", e);
      setActionError(`Cleanup failed: ${String(e)}`);
    } finally {
      setCleaning(false);
    }
  };

  if (loading)
    return <div className="panel-loading">Scanning cleanup targets...</div>;
  if (loadError) return <div className="panel-error">Error: {loadError}</div>;

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
          <button className="select-all-btn" onClick={toggleAll} disabled={cleaning}>
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
      {actionError && <div className="panel-error" role="alert">{actionError}</div>}
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
              disabled={cleaning || !!target.scan_error}
              className="cleanup-check"
            />
            <div className="cleanup-info">
              <div className="cleanup-name">{target.name}</div>
              <div className="cleanup-path">{target.path}</div>
              {target.scan_error && <div className="panel-error">Scan failed: {target.scan_error}</div>}
              {target.scan_warning && (
                <div className="panel-error">
                  Scan incomplete: {target.scan_warning}. Cleanup can still be attempted.
                </div>
              )}
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
