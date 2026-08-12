import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import ConfirmDialog from "./ConfirmDialog";
import "./StartupPanel.css";

interface StartupItem {
  id: string;
  name: string;
  path: string;
  command: string;
  impact: string;
  enabled: boolean;
  can_toggle: boolean;
  toggle_reason: string;
}

interface StartupResponse {
  success: boolean;
  message: string;
  items: StartupItem[];
}

export default function StartupPanel() {
  const [items, setItems] = useState<StartupItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [toggling, setToggling] = useState<Record<string, boolean>>({});
  const [pendingConfirm, setPendingConfirm] = useState<StartupItem | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);

  useEffect(() => {
    invoke<StartupResponse>("get_startup_items")
      .then((response) => {
        if (!response.success || !Array.isArray(response.items)) {
          throw new Error(response.message || "Startup inventory could not be queried.");
        }
        setItems(response.items);
      })
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const handleToggle = async (item: StartupItem) => {
    if (!item.can_toggle) {
      setFeedback(item.toggle_reason || "This startup entry cannot be changed by Cove.");
      return;
    }
    setToggling((s) => ({ ...s, [item.id]: true }));
    try {
      setFeedback(null);
      const res = await invoke<{ success: boolean; message?: string }>("toggle_startup", {
        id: item.id,
        enabled: !item.enabled,
      });
      if (res.success) {
        setItems((prev) =>
          prev.map((it) =>
            it.id === item.id ? { ...it, enabled: !it.enabled } : it
          )
        );
      } else setFeedback(res.message || "Startup change failed.");
    } catch (e) {
      console.error("Toggle failed:", e);
      setFeedback(`Startup change failed: ${String(e)}`);
    } finally {
      setToggling((s) => ({ ...s, [item.id]: false }));
    }
  };

  if (loading)
    return <div className="panel-loading">Loading startup items...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;

  const enabledCount = items.filter((i) => i.enabled).length;

  return (
    <div className="startup-panel">
      {feedback && <div className="panel-error" role="alert">{feedback}</div>}
      <div className="startup-summary">
        <span>{enabledCount} enabled</span>
        <span className="sep">/</span>
        <span>{items.length} total startup items</span>
      </div>

      <div className="startup-list">
        {items.map((item) => (
          <div
            key={item.id}
            className={`startup-item ${!item.enabled ? "item-disabled" : ""}`}
          >
            <div className="startup-left">
              <div className="startup-name-row">
                <span className="startup-name">{item.name}</span>
                <span className={`impact-badge impact-${item.impact.toLowerCase()}`}>
                  {item.impact}
                </span>
              </div>
              <div className="startup-cmd">{item.command}</div>
            </div>
            <div className="startup-right">
              <button
                className={`toggle-btn ${item.enabled ? "toggle-on" : "toggle-off"}`}
                onClick={() => setPendingConfirm(item)}
                disabled={toggling[item.id] || !item.can_toggle}
                aria-label={`${item.enabled ? "Disable" : "Enable"} ${item.name} at startup`}
                aria-pressed={item.enabled}
                title={!item.can_toggle ? item.toggle_reason : undefined}
              >
                <span className="toggle-knob" />
              </button>
              {!item.can_toggle && (
                <span className="startup-toggle-reason">
                  {item.toggle_reason || "This entry cannot be changed by Cove."}
                </span>
              )}
            </div>
          </div>
        ))}
      </div>
      <ConfirmDialog
        open={!!pendingConfirm}
        title={`${pendingConfirm?.enabled ? "Disable" : "Enable"} ${pendingConfirm?.name ?? ""}`}
        message={
          pendingConfirm?.enabled
            ? `This will prevent ${pendingConfirm.name} from starting at boot. Continue?`
            : `This will allow ${pendingConfirm?.name ?? ""} to run at startup. Continue?`
        }
        safetyTier="Yellow"
        onConfirm={() => {
          if (pendingConfirm) handleToggle(pendingConfirm);
          setPendingConfirm(null);
        }}
        onCancel={() => setPendingConfirm(null)}
      />
    </div>
  );
}
