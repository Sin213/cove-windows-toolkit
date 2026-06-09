import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import "./VisualPanel.css";

interface VisualTweak {
  id: string;
  name: string;
  description: string;
  category: string;
  safety_tier: string;
  current_value: string | null;
  optimized_value: string;
}

export default function VisualPanel() {
  const [tweaks, setTweaks] = useState<VisualTweak[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [applying, setApplying] = useState<Record<string, boolean>>({});
  const [applied, setApplied] = useState<Record<string, boolean>>({});

  useEffect(() => {
    invoke<VisualTweak[]>("get_visual_tweaks")
      .then(setTweaks)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const handleApply = async (tweak: VisualTweak) => {
    setApplying((s) => ({ ...s, [tweak.id]: true }));
    try {
      await invoke("apply_tweak", { module: "visual", id: tweak.id });
      setApplied((s) => ({ ...s, [tweak.id]: true }));
    } catch (e) {
      console.error("Apply failed:", e);
    } finally {
      setApplying((s) => ({ ...s, [tweak.id]: false }));
    }
  };

  const handleUndo = async (tweak: VisualTweak) => {
    setApplying((s) => ({ ...s, [tweak.id]: true }));
    try {
      await invoke("undo_tweak", { module: "visual", id: tweak.id });
      setApplied((s) => ({ ...s, [tweak.id]: false }));
    } catch (e) {
      console.error("Undo failed:", e);
    } finally {
      setApplying((s) => ({ ...s, [tweak.id]: false }));
    }
  };

  const handleApplyAll = async () => {
    const unapplied = tweaks.filter(
      (t) => t.safety_tier === "Green" && !applied[t.id]
    );
    for (const t of unapplied) {
      await handleApply(t);
    }
  };

  if (loading) return <div className="panel-loading">Loading visual tweaks...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;

  const isApplied = (id: string) => applied[id];
  const isWorking = (id: string) => applying[id];

  return (
    <div className="visual-panel">
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
              {isApplied(tweak.id) ? (
                <button
                  className="undo-btn"
                  onClick={() => handleUndo(tweak)}
                  disabled={isWorking(tweak.id)}
                >
                  {isWorking(tweak.id) ? "..." : "Undo"}
                </button>
              ) : (
                <button
                  className="apply-btn"
                  onClick={() => handleApply(tweak)}
                  disabled={isWorking(tweak.id)}
                >
                  {isWorking(tweak.id) ? "..." : "Apply"}
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
      <div className="batch-actions">
        <button className="batch-btn" onClick={handleApplyAll}>
          Apply All Safe Tweaks
        </button>
      </div>
    </div>
  );
}
