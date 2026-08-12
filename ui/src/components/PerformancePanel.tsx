import { useEffect, useRef, useState } from "react";
import { invoke } from "../lib/tauri";
import ConfirmDialog from "./ConfirmDialog";
import "./PerformancePanel.css";

interface PerformanceTweak {
  id: string;
  name: string;
  description: string;
  category: string;
  safety_tier: string;
  registry_path: string;
  current_value: string | null;
  optimized_value: string;
  warning: string | null;
  applied: boolean;
  can_undo: boolean;
}

export default function PerformancePanel() {
  const [tweaks, setTweaks] = useState<PerformanceTweak[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [applying, setApplying] = useState<Record<string, boolean>>({});
  const [applied, setApplied] = useState<Record<string, boolean>>({});
  const [undoable, setUndoable] = useState<Record<string, boolean>>({});
  const [batchApplying, setBatchApplying] = useState(false);
  const [pendingConfirm, setPendingConfirm] = useState<PerformanceTweak | null>(null);
  const inFlightRef = useRef(new Set<string>());
  const batchRef = useRef(false);

  useEffect(() => {
    invoke<PerformanceTweak[]>("get_performance_tweaks")
      .then((data) => {
        setTweaks(data);
        setApplied(Object.fromEntries(data.map((tweak) => [tweak.id, tweak.applied])));
        setUndoable(Object.fromEntries(data.map((tweak) => [tweak.id, tweak.can_undo])));
      })
      .catch((e) => setLoadError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const handleApply = async (tweak: PerformanceTweak, fromBatch = false) => {
    if (inFlightRef.current.has(tweak.id) || (batchRef.current && !fromBatch)) return;
    inFlightRef.current.add(tweak.id);
    setActionError(null);
    setApplying((s) => ({ ...s, [tweak.id]: true }));
    try {
      const result = await invoke<{ success: boolean; message?: string }>("apply_performance_tweak", { id: tweak.id });
      if (result.success) {
        setApplied((s) => ({ ...s, [tweak.id]: true }));
        setUndoable((s) => ({ ...s, [tweak.id]: true }));
      } else setActionError(result.message || "Failed to apply tweak.");
    } catch (e) {
      setActionError(String(e));
    } finally {
      inFlightRef.current.delete(tweak.id);
      setApplying((s) => ({ ...s, [tweak.id]: false }));
    }
  };

  const handleUndo = async (tweak: PerformanceTweak) => {
    if (inFlightRef.current.has(tweak.id) || batchRef.current) return;
    inFlightRef.current.add(tweak.id);
    setActionError(null);
    setApplying((s) => ({ ...s, [tweak.id]: true }));
    try {
      const result = await invoke<{ success: boolean; message?: string }>("undo_performance_tweak", { id: tweak.id });
      if (result.success) {
        setApplied((s) => ({ ...s, [tweak.id]: false }));
        setUndoable((s) => ({ ...s, [tweak.id]: false }));
      } else setActionError(result.message || "Failed to undo tweak.");
    } catch (e) {
      setActionError(String(e));
    } finally {
      inFlightRef.current.delete(tweak.id);
      setApplying((s) => ({ ...s, [tweak.id]: false }));
    }
  };

  const handleApplyAllSafe = async () => {
    if (batchRef.current || inFlightRef.current.size > 0) return;
    batchRef.current = true;
    setBatchApplying(true);
    const safe = tweaks.filter(
      (t) => t.safety_tier === "Green" && !applied[t.id]
    );
    try {
      for (const t of safe) {
        await handleApply(t, true);
      }
    } finally {
      batchRef.current = false;
      setBatchApplying(false);
    }
  };

  if (loading)
    return <div className="panel-loading">Loading performance tweaks...</div>;
  if (loadError) return <div className="panel-error">Error: {loadError}</div>;

  const categories = [...new Set(tweaks.map((t) => t.category))];

  return (
    <div className="performance-panel">
      {actionError && <div className="panel-error" role="alert">{actionError}</div>}
      {categories.map((cat) => {
        const group = tweaks.filter((t) => t.category === cat);
        return (
          <div key={cat} className="perf-category">
            <h3 className="perf-category-title">{cat}</h3>
            <div className="tweaks-list">
              {group.map((tweak) => (
                <div
                  key={tweak.id}
                  className={`tweak-item ${applied[tweak.id] ? "tweak-applied" : ""}`}
                >
                  <div className="tweak-left">
                    <div className="tweak-title-row">
                      <span
                        className={`tier-badge tier-${tweak.safety_tier.toLowerCase()}`}
                      >
                        {tweak.safety_tier}
                      </span>
                      <span className="tweak-name">{tweak.name}</span>
                    </div>
                    <div className="tweak-desc">{tweak.description}</div>
                    {tweak.warning && (
                      <div className="tweak-warning">{tweak.warning}</div>
                    )}
                  </div>
                  <div className="tweak-right">
                    <div className="tweak-values">
                      <span className="val-current">
                        {tweak.current_value ?? "N/A"}
                      </span>
                      <span className="val-arrow">&rarr;</span>
                      <span className="val-optimized">
                        {tweak.optimized_value}
                      </span>
                    </div>
                    {applied[tweak.id] && undoable[tweak.id] ? (
                      <button
                        className="undo-btn"
                        onClick={() => handleUndo(tweak)}
                        disabled={batchApplying || applying[tweak.id]}
                      >
                        {applying[tweak.id] ? "..." : "Undo"}
                      </button>
                    ) : applied[tweak.id] ? (
                      <span className="applied-label">Already applied</span>
                    ) : (
                      <button
                        className="apply-btn"
                        onClick={() => {
                          if (tweak.safety_tier !== "Green") {
                            setPendingConfirm(tweak);
                          } else {
                            handleApply(tweak);
                          }
                        }}
                        disabled={batchApplying || applying[tweak.id]}
                      >
                        {applying[tweak.id] ? "..." : "Apply"}
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        );
      })}
      <div className="batch-actions">
        <button
          className="batch-btn"
          onClick={handleApplyAllSafe}
          disabled={batchApplying || Object.values(applying).some(Boolean)}
        >
          {batchApplying ? "Applying..." : "Apply All Green Tweaks"}
        </button>
      </div>
      <ConfirmDialog
        open={!!pendingConfirm}
        title={pendingConfirm?.name ?? ""}
        message={
          pendingConfirm?.warning ??
          (pendingConfirm?.safety_tier === "Red"
            ? "This is a destructive operation. Are you sure?"
            : "This changes system settings. Continue?")
        }
        safetyTier={(pendingConfirm?.safety_tier as "Yellow" | "Red") ?? "Yellow"}
        onConfirm={() => {
          if (pendingConfirm) handleApply(pendingConfirm);
          setPendingConfirm(null);
        }}
        onCancel={() => setPendingConfirm(null)}
      />
    </div>
  );
}
