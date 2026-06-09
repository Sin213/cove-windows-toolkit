import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import "./StartupPanel.css";

interface StartupItem {
  name: string;
  publisher: string;
  command: string;
  location: string;
  enabled: boolean;
  impact: string;
}

export default function StartupPanel() {
  const [items, setItems] = useState<StartupItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [toggling, setToggling] = useState<Record<string, boolean>>({});

  useEffect(() => {
    invoke<StartupItem[]>("get_startup_items")
      .then(setItems)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const handleToggle = async (item: StartupItem) => {
    setToggling((s) => ({ ...s, [item.name]: true }));
    try {
      await invoke("toggle_startup", {
        name: item.name,
        enabled: !item.enabled,
      });
      setItems((prev) =>
        prev.map((it) =>
          it.name === item.name ? { ...it, enabled: !it.enabled } : it
        )
      );
    } catch (e) {
      console.error("Toggle failed:", e);
    } finally {
      setToggling((s) => ({ ...s, [item.name]: false }));
    }
  };

  if (loading)
    return <div className="panel-loading">Loading startup items...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;

  const enabledCount = items.filter((i) => i.enabled).length;

  return (
    <div className="startup-panel">
      <div className="startup-summary">
        <span>{enabledCount} enabled</span>
        <span className="sep">/</span>
        <span>{items.length} total startup items</span>
      </div>

      <div className="startup-list">
        {items.map((item) => (
          <div
            key={item.name}
            className={`startup-item ${!item.enabled ? "item-disabled" : ""}`}
          >
            <div className="startup-left">
              <div className="startup-name-row">
                <span className="startup-name">{item.name}</span>
                <span className={`impact-badge impact-${item.impact.toLowerCase()}`}>
                  {item.impact}
                </span>
              </div>
              <div className="startup-publisher">{item.publisher}</div>
              <div className="startup-cmd">{item.command}</div>
            </div>
            <div className="startup-right">
              <button
                className={`toggle-btn ${item.enabled ? "toggle-on" : "toggle-off"}`}
                onClick={() => handleToggle(item)}
                disabled={toggling[item.name]}
              >
                <span className="toggle-knob" />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
