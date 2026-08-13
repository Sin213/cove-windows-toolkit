import { useEffect, useRef, useState } from "react";
import { invoke } from "../lib/tauri";
import ConfirmDialog from "./ConfirmDialog";
import TweakSwitch from "./TweakSwitch";
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
  const [batchReverting, setBatchReverting] = useState(false);
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

  const handleUndo = async (tweak: VisualTweak, fromBatch = false) => {
    if (inFlightRef.current.has(tweak.id) || (batchRef.current && !fromBatch)) return;
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

  // Puts every tweak Cove changed back to the value it had before, in one go.
  const handleRevertAll = async () => {
    if (batchRef.current || inFlightRef.current.size > 0) return;
    batchRef.current = true;
    setBatchReverting(true);
    const revertable = tweaks.filter((t) => applied[t.id] && undoable[t.id]);
    try {
      for (const t of revertable) {
        await handleUndo(t, true);
      }
    } finally {
      batchRef.current = false;
      setBatchReverting(false);
    }
  };

  if (loading) return <div className="panel-loading">Loading visual tweaks...</div>;
  if (loadError) return <div className="panel-error">Error: {loadError}</div>;

  const isApplied = (id: string) => applied[id];
  const isWorking = (id: string) => applying[id];
  const revertableCount = tweaks.filter((t) => applied[t.id] && undoable[t.id]).length;

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
              <TweakSwitch
                label={tweak.name}
                applied={!!isApplied(tweak.id)}
                canRevert={!!undoable[tweak.id]}
                busy={!!isWorking(tweak.id)}
                disabled={batchApplying || batchReverting}
                onApply={() => {
                  if (tweak.safety_tier !== "Green") {
                    setPendingConfirm(tweak);
                  } else {
                    handleApply(tweak);
                  }
                }}
                onRevert={() => handleUndo(tweak)}
              />
            </div>
          </div>
        ))}
      </div>
      <div className="batch-actions">
        <button
          className="tweak-revert-all-btn"
          onClick={handleRevertAll}
          disabled={
            batchApplying ||
            batchReverting ||
            Object.values(applying).some(Boolean) ||
            revertableCount === 0
          }
          title="Restore the original value of every tweak Cove changed"
        >
          {batchReverting ? "Reverting..." : `Revert All (${revertableCount})`}
        </button>
        <button
          className="batch-btn"
          onClick={handleApplyAll}
          disabled={batchApplying || batchReverting || Object.values(applying).some(Boolean)}
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
