import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import "./PrivacyPanel.css";

interface PrivacyTweak {
  id: string;
  name: string;
  description: string;
  tier: string;
  safety: string;
  enabled: boolean;
  warning: string | null;
}

const TIER_ORDER = ["basic", "standard", "advanced"];
const TIER_LABELS: Record<string, string> = {
  basic: "Basic (Safe)",
  standard: "Standard (Minor Trade-offs)",
  advanced: "Advanced (Review Carefully)",
};

export default function PrivacyPanel() {
  const [tweaks, setTweaks] = useState<PrivacyTweak[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({
    basic: true,
    standard: true,
    advanced: false,
  });
  const [applied, setApplied] = useState<Record<string, boolean>>({});
  const [confirming, setConfirming] = useState<string | null>(null);

  useEffect(() => {
    invoke<PrivacyTweak[]>("get_privacy_tweaks")
      .then(setTweaks)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const toggle = (tier: string) =>
    setExpanded((s) => ({ ...s, [tier]: !s[tier] }));

  const handleApply = async (tweak: PrivacyTweak) => {
    if (tweak.safety === "Red" && confirming !== tweak.id) {
      setConfirming(tweak.id);
      return;
    }
    setConfirming(null);
    try {
      await invoke("apply_tweak", { id: tweak.id });
      setApplied((s) => ({ ...s, [tweak.id]: true }));
    } catch (e) {
      console.error("Apply failed:", e);
    }
  };

  if (loading) return <div className="panel-loading">Loading privacy tweaks...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;

  const grouped = TIER_ORDER.map((tier) => ({
    tier,
    label: TIER_LABELS[tier],
    items: tweaks.filter((t) => t.tier === tier),
  }));

  return (
    <div className="privacy-panel">
      {grouped.map((group) => (
        <div key={group.tier} className="privacy-tier">
          <button
            className="tier-header"
            onClick={() => toggle(group.tier)}
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
                        className={`tier-badge tier-${tweak.safety.toLowerCase()}`}
                      >
                        {tweak.safety}
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
                    {applied[tweak.id] ? (
                      <span className="applied-label">Applied</span>
                    ) : confirming === tweak.id ? (
                      <div className="confirm-group">
                        <span className="confirm-label">Are you sure?</span>
                        <button
                          className="confirm-btn"
                          onClick={() => handleApply(tweak)}
                        >
                          Confirm
                        </button>
                        <button
                          className="cancel-btn"
                          onClick={() => setConfirming(null)}
                        >
                          Cancel
                        </button>
                      </div>
                    ) : (
                      <button
                        className="apply-btn"
                        onClick={() => handleApply(tweak)}
                      >
                        Apply
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
