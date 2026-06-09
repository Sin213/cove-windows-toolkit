import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
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
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({
    basic: true,
    standard: true,
    advanced: false,
  });
  const [applied, setApplied] = useState<Record<string, boolean>>({});
  const [confirming, setConfirming] = useState<string | null>(null);

  useEffect(() => {
    invoke<PrivacyData>("get_privacy_tweaks")
      .then(setData)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const toggle = (tier: string) =>
    setExpanded((s) => ({ ...s, [tier]: !s[tier] }));

  const handleApply = async (tweak: PrivacyTweak) => {
    if (tweak.tier === "red" && confirming !== tweak.id) {
      setConfirming(tweak.id);
      return;
    }
    setConfirming(null);
    try {
      await invoke("apply_tweak", { module: "privacy", id: tweak.id });
      setApplied((s) => ({ ...s, [tweak.id]: true }));
    } catch (e) {
      console.error("Apply failed:", e);
    }
  };

  if (loading) return <div className="panel-loading">Loading privacy tweaks...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;
  if (!data) return null;

  const grouped = TIER_ORDER.map((tier) => ({
    tier,
    label: TIER_LABELS[tier],
    items: data[tier],
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
