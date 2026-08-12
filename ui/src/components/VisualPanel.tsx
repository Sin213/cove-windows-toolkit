import { useEffect, useRef, useState } from "react";
import { invoke } from "../lib/tauri";
import ConfirmDialog from "./ConfirmDialog";
import "./VisualPanel.css";

interface VisualTweak {
  id: string;
  name: string;
  description: string;
  category: string;
  safety_tier: string;
  current_value: string | null;
  optimized_value: string;
  applied: boolean;
  can_undo: boolean;
}

export default function VisualPanel() {
  const [tweaks, setTweaks] = useState<VisualTweak[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [applying, setApplying] = useState<Record<string, boolean>>({});
  const [applied, setApplied] = useState<Record<string, boolean>>({});
  const [undoable, setUndoable] = useState<Record<string, boolean>>({});
  const [batchApplying, setBatchApplying] = useState(false);
  const [pendingConfirm, setPendingConfirm] = useState<VisualTweak | null>(null);
  const inFlightRef = useRef(new Set<string>());
  const batchRef = useRef(false);

  useEffect(() => {
    invoke<VisualTweak[]>("get_visual_tweaks")
      .then((data) => {
        setTweaks(data);
        setApplied(Object.fromEntries(data.map((tweak) => [tweak.id, tweak.applied])));
        setUndoable(Object.fromEntries(data.map((tweak) => [tweak.id, tweak.can_undo])));
      })
      .catch((e) => setLoadError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const handleApply = async (tweak: VisualTweak, fromBatch = false) => {
    if (inFlightRef.current.has(tweak.id) || (batchRef.current && !fromBatch)) return;
    inFlightRef.current.add(tweak.id);
    setActionError(null);
    setApplying((s) => ({ ...s, [tweak.id]: true }));
    try {
      const res = await invoke<{ success: boolean; message?: string }>("apply_tweak", { module: "visual", id: tweak.id });
      if (res.success) {
        setApplied((s) => ({ ...s, [tweak.id]: true }));
        setUndoable((s) => ({ ...s, [tweak.id]: true }));
      } else {
        setActionError(res.message || "Failed to apply tweak.");
      }
    } catch (e) {
      setActionError(String(e));
    } finally {
      inFlightRef.current.delete(tweak.id);
      setApplying((s) => ({ ...s, [tweak.id]: false }));
    }
  };

  const handleUndo = async (tweak: VisualTweak) => {
    if (inFlightRef.current.has(tweak.id) || batchRef.current) return;
    inFlightRef.current.add(tweak.id);
    setActionError(null);
    setApplying((s) => ({ ...s, [tweak.id]: true }));
    try {
      const res = await invoke<{ success: boolean; message?: string }>("undo_tweak", { module: "visual", id: tweak.id });
      if (res.success) {
        setApplied((s) => ({ ...s, [tweak.id]: false }));
        setUndoable((s) => ({ ...s, [tweak.id]: false }));
      } else {
        setActionError(res.message || "Failed to undo tweak.");
      }
    } catch (e) {
      setActionError(String(e));
    } finally {
      inFlightRef.current.delete(tweak.id);
      setApplying((s) => ({ ...s, [tweak.id]: false }));
    }
  };

  const handleApplyAll = async () => {
    if (batchRef.current || inFlightRef.current.size > 0) return;
    batchRef.current = true;
    setBatchApplying(true);
    const unapplied = tweaks.filter(
      (t) => t.safety_tier === "Green" && !applied[t.id]
    );
    try {
      for (const t of unapplied) {
        await handleApply(t, true);
      }
    } finally {
      batchRef.current = false;
      setBatchApplying(false);
    }
  };

  if (loading) return <div className="panel-loading">Loading visual tweaks...</div>;
  if (loadError) return <div className="panel-error">Error: {loadError}</div>;

  const isApplied = (id: string) => applied[id];
  const isWorking = (id: string) => applying[id];

  return (
    <div className="visual-panel">
      {actionError && <div className="panel-error" role="alert">{actionError}</div>}
      <div className="tweaks-list">
        {tweaks.map((tweak) => (
          <div
            key={tweak.id}
            className={`tweak-item ${isApplied(tweak.id) ? "tweak-applied" : ""}`}
          >
            <div className="tweak-left">
              <div className="tweak-title-row">
                <span className={`tier-badge tier-${tweak.safety_tier.toLowerCase()}`}>
                  {tweak.safety_tier}
                </span>
                <span className="tweak-name">{tweak.name}</span>
              </div>
              <div className="tweak-desc">{tweak.description}</div>
            </div>
            <div className="tweak-right">
              <div className="tweak-values">
                <span className="val-current">
                  {tweak.current_value ?? "N/A"}
                </span>
                <span className="val-arrow">&rarr;</span>
                <span className="val-optimized">{tweak.optimized_value}</span>
              </div>
              {isApplied(tweak.id) && undoable[tweak.id] ? (
                <button
                  className="undo-btn"
                  onClick={() => handleUndo(tweak)}
                  disabled={batchApplying || isWorking(tweak.id)}
                >
                  {isWorking(tweak.id) ? "..." : "Undo"}
                </button>
              ) : isApplied(tweak.id) ? (
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
                    disabled={batchApplying || isWorking(tweak.id)}
                >
                  {isWorking(tweak.id) ? "..." : "Apply"}
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
      <div className="batch-actions">
        <button
          className="batch-btn"
          onClick={handleApplyAll}
          disabled={batchApplying || Object.values(applying).some(Boolean)}
        >
          {batchApplying ? "Applying..." : "Apply All Safe Tweaks"}
        </button>
      </div>
      <ConfirmDialog
        open={!!pendingConfirm}
        title={pendingConfirm?.name ?? ""}
        message={
          pendingConfirm?.safety_tier === "Red"
            ? "This is a destructive operation. Are you sure?"
            : "This changes system settings. Continue?"
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
