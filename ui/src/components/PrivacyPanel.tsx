import { useEffect, useRef, useState } from "react";
import { invoke } from "../lib/tauri";
import ConfirmDialog from "./ConfirmDialog";
import TweakSwitch from "./TweakSwitch";
import "./PrivacyPanel.css";

interface PrivacyTweak {
  id: string;
  name: string;
  description: string;
  tier: string;
  path: string;
  current: string;
  optimized: string;
  warning?: string | null;
  applied: boolean;
  /** False for service-based tweaks and anything Cove has no snapshot for. */
  can_undo: boolean;
}

interface PrivacyData {
  basic: PrivacyTweak[];
  standard: PrivacyTweak[];
  advanced: PrivacyTweak[];
}

const TIER_ORDER: (keyof PrivacyData)[] = ["basic", "standard", "advanced"];
const TIER_LABELS: Record<string, string> = {
  basic: "Basic (Safe)",
  standard: "Standard (Minor Trade-offs)",
  advanced: "Advanced (Review Carefully)",
};

export default function PrivacyPanel() {
  const [data, setData] = useState<PrivacyData | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({
    basic: true,
    standard: true,
    advanced: false,
  });
  const [applied, setApplied] = useState<Record<string, boolean>>({});
  const [undoable, setUndoable] = useState<Record<string, boolean>>({});
  const [applying, setApplying] = useState<Record<string, boolean>>({});
  const [reverting, setReverting] = useState(false);
  const [pendingConfirm, setPendingConfirm] = useState<PrivacyTweak | null>(null);
  const inFlightRef = useRef(new Set<string>());

  useEffect(() => {
    invoke<PrivacyData>("get_privacy_tweaks")
      .then((response) => {
        setData(response);
        const items = [...response.basic, ...response.standard, ...response.advanced];
        setApplied(
          Object.fromEntries(
            items.map((item) => [item.id, item.applied ?? item.current === item.optimized]),
          ),
        );
        setUndoable(Object.fromEntries(items.map((item) => [item.id, !!item.can_undo])));
      })
      .catch((e) => setLoadError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const toggle = (tier: string) =>
    setExpanded((s) => ({ ...s, [tier]: !s[tier] }));

  const handleApply = async (tweak: PrivacyTweak) => {
    if (inFlightRef.current.size > 0) return;
    inFlightRef.current.add(tweak.id);
    setApplying((current) => ({ ...current, [tweak.id]: true }));
    setActionError(null);
    try {
      const res = await invoke<{ success: boolean; message?: string }>("apply_tweak", {
        module: "privacy",
        id: tweak.id,
      });
      if (res.success) {
        setApplied((s) => ({ ...s, [tweak.id]: true }));
        // Service-based tweaks have no snapshot, so they stay non-revertable.
        setUndoable((s) => ({ ...s, [tweak.id]: !tweak.path.startsWith("Service:") }));
        setData((current) => current ? {
          basic: current.basic.map((item) => item.id === tweak.id ? { ...item, current: item.optimized } : item),
          standard: current.standard.map((item) => item.id === tweak.id ? { ...item, current: item.optimized } : item),
          advanced: current.advanced.map((item) => item.id === tweak.id ? { ...item, current: item.optimized } : item),
        } : current);
      } else {
        setActionError(res.message || "Failed to apply tweak.");
      }
    } catch (e) {
      setActionError(String(e));
    } finally {
      inFlightRef.current.delete(tweak.id);
      setApplying((current) => ({ ...current, [tweak.id]: false }));
    }
  };

  const handleRevert = async (tweak: PrivacyTweak) => {
    if (inFlightRef.current.size > 0) return;
    inFlightRef.current.add(tweak.id);
    setApplying((current) => ({ ...current, [tweak.id]: true }));
    setActionError(null);
    try {
      const res = await invoke<{ success: boolean; message?: string }>("undo_tweak", {
        module: "privacy",
        id: tweak.id,
      });
      if (res.success) {
        setApplied((s) => ({ ...s, [tweak.id]: false }));
        setUndoable((s) => ({ ...s, [tweak.id]: false }));
      } else {
        setActionError(res.message || "Failed to revert tweak.");
      }
    } catch (e) {
      setActionError(String(e));
    } finally {
      inFlightRef.current.delete(tweak.id);
      setApplying((current) => ({ ...current, [tweak.id]: false }));
    }
  };

  // Puts every privacy tweak Cove changed back to the value it had before.
  const handleRevertAll = async (items: PrivacyTweak[]) => {
    if (inFlightRef.current.size > 0 || reverting) return;
    setReverting(true);
    try {
      for (const tweak of items) {
        if (applied[tweak.id] && undoable[tweak.id]) {
          await handleRevert(tweak);
        }
      }
    } finally {
      setReverting(false);
    }
  };

  if (loading) return <div className="panel-loading">Loading privacy tweaks...</div>;
  if (loadError) return <div className="panel-error">Error: {loadError}</div>;
  if (!data) return null;

  const grouped = TIER_ORDER.map((tier) => ({
    tier,
    label: TIER_LABELS[tier],
    items: data[tier],
  }));
  const allItems = [...data.basic, ...data.standard, ...data.advanced];
  const revertableCount = allItems.filter((t) => applied[t.id] && undoable[t.id]).length;

  return (
    <div className="privacy-panel">
      {actionError && <div className="panel-error" role="alert">{actionError}</div>}
      <div className="privacy-batch-actions">
        <button
          className="tweak-revert-all-btn"
          onClick={() => handleRevertAll(allItems)}
          disabled={reverting || Object.values(applying).some(Boolean) || revertableCount === 0}
          title="Restore the original value of every privacy tweak Cove changed"
        >
          {reverting ? "Reverting..." : `Revert All (${revertableCount})`}
        </button>
      </div>
      {grouped.map((group) => (
        <div key={group.tier} className="privacy-tier">
          <button
            className="tier-header"
            onClick={() => toggle(group.tier)}
            aria-expanded={expanded[group.tier]}
          >
            <span className="tier-chevron">
              {expanded[group.tier] ? "▾" : "▸"}
            </span>
            <span className="tier-title">{group.label}</span>
            <span className="tier-count">{group.items.length} items</span>
          </button>
          {expanded[group.tier] && (
            <div className="tier-items">
              {group.items.map((tweak) => (
                <div
                  key={tweak.id}
                  className={`privacy-item ${applied[tweak.id] ? "item-applied" : ""}`}
                >
                  <div className="privacy-item-left">
                    <div className="privacy-item-header">
                      <span
                        className={`tier-badge tier-${tweak.tier.toLowerCase()}`}
                      >
                        {tweak.tier}
                      </span>
                      <span className="privacy-item-name">{tweak.name}</span>
                    </div>
                    <div className="privacy-item-desc">
                      {tweak.description}
                    </div>
                    {tweak.warning && (
                      <div className="privacy-item-warning">
                        {tweak.warning}
                      </div>
                    )}
                  </div>
                  <div className="privacy-item-right">
                    <TweakSwitch
                      label={tweak.name}
                      applied={!!applied[tweak.id]}
                      canRevert={!!undoable[tweak.id]}
                      busy={!!applying[tweak.id]}
                      disabled={reverting || Object.values(applying).some(Boolean)}
                      onApply={() => {
                        if (tweak.tier !== "green") {
                          setPendingConfirm(tweak);
                        } else {
                          handleApply(tweak);
                        }
                      }}
                      onRevert={() => handleRevert(tweak)}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      ))}
      <ConfirmDialog
        open={!!pendingConfirm}
        title={pendingConfirm?.name ?? ""}
        message={
          pendingConfirm?.warning ??
          (pendingConfirm?.tier === "red"
            ? "This is a destructive operation. Are you sure?"
            : "This changes system settings. Continue?")
        }
        safetyTier={pendingConfirm?.tier === "red" ? "Red" : "Yellow"}
        onConfirm={() => {
          if (pendingConfirm) handleApply(pendingConfirm);
          setPendingConfirm(null);
        }}
        onCancel={() => setPendingConfirm(null)}
      />
    </div>
  );
}
