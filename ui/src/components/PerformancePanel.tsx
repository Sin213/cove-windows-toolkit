import { useEffect, useState } from "react";
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
}

export default function PerformancePanel() {
  const [tweaks, setTweaks] = useState<PerformanceTweak[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [applying, setApplying] = useState<Record<string, boolean>>({});
  const [applied, setApplied] = useState<Record<string, boolean>>({});
  const [pendingConfirm, setPendingConfirm] = useState<PerformanceTweak | null>(null);

  useEffect(() => {
    invoke<PerformanceTweak[]>("get_performance_tweaks")
      .then(setTweaks)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const handleApply = async (tweak: PerformanceTweak) => {
    setApplying((s) => ({ ...s, [tweak.id]: true }));
    try {
      await invoke("apply_performance_tweak", { id: tweak.id });
      setApplied((s) => ({ ...s, [tweak.id]: true }));
    } catch (e) {
      console.error("Apply failed:", e);
    } finally {
      setApplying((s) => ({ ...s, [tweak.id]: false }));
    }
  };

  const handleUndo = async (tweak: PerformanceTweak) => {
    setApplying((s) => ({ ...s, [tweak.id]: true }));
    try {
      await invoke("undo_performance_tweak", { id: tweak.id });
      setApplied((s) => ({ ...s, [tweak.id]: false }));
    } catch (e) {
      console.error("Undo failed:", e);
    } finally {
      setApplying((s) => ({ ...s, [tweak.id]: false }));
    }
  };

  const handleApplyAllSafe = async () => {
    const safe = tweaks.filter(
      (t) => t.safety_tier === "Green" && !applied[t.id]
    );
    for (const t of safe) {
      await handleApply(t);
    }
  };

  if (loading)
    return <div className="panel-loading">Loading performance tweaks...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;

  const categories = [...new Set(tweaks.map((t) => t.category))];

  return (
    <div className="performance-panel">
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
                    {applied[tweak.id] ? (
                      <button
                        className="undo-btn"
                        onClick={() => handleUndo(tweak)}
                        disabled={applying[tweak.id]}
                      >
                        {applying[tweak.id] ? "..." : "Undo"}
                      </button>
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
                        disabled={applying[tweak.id]}
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
        <button className="batch-btn" onClick={handleApplyAllSafe}>
          Apply All Green Tweaks
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
