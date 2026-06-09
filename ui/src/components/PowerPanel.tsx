import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import "./PowerPanel.css";

interface PowerPlan {
  guid: string;
  name: string;
}

interface PowerSettings {
  display_off_ac_minutes: number;
  display_off_dc_minutes: number;
  sleep_ac_minutes: number;
  sleep_dc_minutes: number;
  hdd_off_ac_minutes: number;
  hdd_off_dc_minutes: number;
  hibernate_enabled: boolean;
}

interface BatteryInfo {
  present: boolean;
  charge_percent: number;
  charging: boolean;
  estimated_minutes: number;
}

interface PowerData {
  active_plan: PowerPlan;
  plans: PowerPlan[];
  settings: PowerSettings;
  battery: BatteryInfo | null;
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
        setSelectedPlan(d.active_plan.guid);
      })
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const handlePlanChange = async (guid: string) => {
    setSelectedPlan(guid);
    try {
      await invoke("set_power_plan", { guid });
    } catch (e) {
      console.error("Plan change failed:", e);
    }
  };

  if (loading) return <div className="panel-loading">Loading power info...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;
  if (!data) return null;

  const { settings, battery } = data;

  return (
    <div className="power-panel">
      {/* Battery info */}
      {battery && battery.present && (
        <div className="battery-card">
          <div className="battery-icon">
            <div className="battery-shell">
              <div
                className="battery-fill"
                style={{
                  width: `${battery.charge_percent}%`,
                  background:
                    battery.charge_percent > 50
                      ? "var(--green)"
                      : battery.charge_percent > 20
                        ? "var(--yellow)"
                        : "var(--red)",
                }}
              />
            </div>
          </div>
          <div className="battery-details">
            <span className="battery-pct">{battery.charge_percent}%</span>
            <span className="battery-status">
              {battery.charging ? "Charging" : `${battery.estimated_minutes} min remaining`}
            </span>
          </div>
        </div>
      )}

      {/* Plan selector */}
      <div className="power-section">
        <h3>Power Plan</h3>
        <div className="plan-grid">
          {data.plans.map((plan) => (
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
          <SettingRow
            label="Turn off display"
            acValue={settings.display_off_ac_minutes}
            dcValue={settings.display_off_dc_minutes}
          />
          <SettingRow
            label="Sleep after"
            acValue={settings.sleep_ac_minutes}
            dcValue={settings.sleep_dc_minutes}
          />
          <SettingRow
            label="Turn off hard disk"
            acValue={settings.hdd_off_ac_minutes}
            dcValue={settings.hdd_off_dc_minutes}
          />
        </div>
      </div>

      <div className="power-section">
        <h3>Hibernate</h3>
        <div className="hibernate-row">
          <span className="hibernate-label">Hibernate mode</span>
          <span
            className={`hibernate-status ${settings.hibernate_enabled ? "status-on" : "status-off"}`}
          >
            {settings.hibernate_enabled ? "Enabled" : "Disabled"}
          </span>
        </div>
      </div>
    </div>
  );
}

function SettingRow({
  label,
  acValue,
  dcValue,
}: {
  label: string;
  acValue: number;
  dcValue: number;
}) {
  const fmt = (m: number) => (m === 0 ? "Never" : `${m} min`);
  return (
    <div className="setting-row">
      <span className="setting-label">{label}</span>
      <div className="setting-values">
        <span className="setting-val">
          <span className="setting-val-label">AC</span> {fmt(acValue)}
        </span>
        <span className="setting-val">
          <span className="setting-val-label">DC</span> {fmt(dcValue)}
        </span>
      </div>
    </div>
  );
}
