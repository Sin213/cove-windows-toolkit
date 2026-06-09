import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import "./PowerPanel.css";

interface PowerPlan {
  guid: string;
  name: string;
  active: boolean;
}

interface PowerData {
  current_plan: string;
  current_guid: string;
  available_plans: PowerPlan[];
  hdd_sleep_minutes: number;
  display_off_minutes: number;
  sleep_minutes: number;
}

export default function PowerPanel() {
  const [data, setData] = useState<PowerData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedPlan, setSelectedPlan] = useState<string>("");

  useEffect(() => {
    invoke<PowerData>("get_power_info")
      .then((d) => {
        setData(d);
        setSelectedPlan(d.current_guid);
      })
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const handlePlanChange = async (guid: string) => {
    const prev = selectedPlan;
    setSelectedPlan(guid);
    try {
      const res = await invoke<{ success: boolean }>("set_power_plan", { guid });
      if (!res.success) setSelectedPlan(prev);
    } catch {
      setSelectedPlan(prev);
    }
  };

  if (loading) return <div className="panel-loading">Loading power info...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;
  if (!data) return null;

  const fmt = (m: number) => (m === 0 ? "Never" : `${m} min`);

  return (
    <div className="power-panel">
      {/* Plan selector */}
      <div className="power-section">
        <h3>Power Plan</h3>
        <div className="plan-grid">
          {data.available_plans.map((plan) => (
            <button
              key={plan.guid}
              className={`plan-card ${selectedPlan === plan.guid ? "active" : ""}`}
              onClick={() => handlePlanChange(plan.guid)}
            >
              <span className="plan-name">{plan.name}</span>
              {selectedPlan === plan.guid && (
                <span className="plan-active-badge">Active</span>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* Settings display */}
      <div className="power-section">
        <h3>Timeout Settings</h3>
        <div className="settings-grid">
          <div className="setting-row">
            <span className="setting-label">Turn off display</span>
            <span className="setting-val">{fmt(data.display_off_minutes)}</span>
          </div>
          <div className="setting-row">
            <span className="setting-label">Sleep after</span>
            <span className="setting-val">{fmt(data.sleep_minutes)}</span>
          </div>
          <div className="setting-row">
            <span className="setting-label">Turn off hard disk</span>
            <span className="setting-val">{fmt(data.hdd_sleep_minutes)}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
