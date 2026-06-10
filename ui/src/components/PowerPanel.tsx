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

const TIMEOUT_OPTIONS = [0, 1, 2, 3, 5, 10, 15, 20, 25, 30, 45, 60, 120, 180, 240, 300];

function fmtTimeout(m: number): string {
  if (m === 0) return "Never";
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  const rem = m % 60;
  return rem ? `${h} hr ${rem} min` : `${h} hr`;
}

export default function PowerPanel() {
  const [data, setData] = useState<PowerData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedPlan, setSelectedPlan] = useState("");
  const [display, setDisplay] = useState(0);
  const [sleep, setSleep] = useState(0);
  const [disk, setDisk] = useState(0);
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; message: string } | null>(null);

  useEffect(() => {
    invoke<PowerData>("get_power_info")
      .then((d) => {
        setData(d);
        setSelectedPlan(d.current_guid);
        setDisplay(d.display_off_minutes);
        setSleep(d.sleep_minutes);
        setDisk(d.hdd_sleep_minutes);
      })
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const handlePlanChange = async (guid: string) => {
    const prev = selectedPlan;
    setSelectedPlan(guid);
    setFeedback(null);
    try {
      const res = await invoke<{ success: boolean; message?: string }>("set_power_plan", { guid });
      if (res.success) {
        setFeedback({ type: "success", message: `Power plan changed.` });
      } else {
        setSelectedPlan(prev);
        setFeedback({ type: "error", message: res.message || "Failed to change plan." });
      }
    } catch {
      setSelectedPlan(prev);
    }
  };

  const handleTimeout = async (setting: string, minutes: number) => {
    setFeedback(null);
    if (setting === "display") setDisplay(minutes);
    if (setting === "sleep") setSleep(minutes);
    if (setting === "disk") setDisk(minutes);
    try {
      const res = await invoke<{ success: boolean; message?: string }>("set_power_timeout", { setting, minutes });
      if (res.success) {
        setFeedback({ type: "success", message: res.message || "Timeout updated." });
      } else {
        setFeedback({ type: "error", message: res.message || "Failed to update timeout." });
      }
    } catch (e) {
      setFeedback({ type: "error", message: String(e) });
    }
  };

  if (loading) return <div className="panel-loading">Loading power info...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;
  if (!data) return null;

  return (
    <div className="power-panel">
      {feedback && (
        <div className={`power-feedback feedback-${feedback.type}`}>
          {feedback.message}
        </div>
      )}

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

      <div className="power-section">
        <h3>Timeout Settings</h3>
        <div className="settings-grid">
          <TimeoutRow
            label="Turn off display"
            value={display}
            onChange={(v) => handleTimeout("display", v)}
          />
          <TimeoutRow
            label="Sleep after"
            value={sleep}
            onChange={(v) => handleTimeout("sleep", v)}
          />
          <TimeoutRow
            label="Turn off hard disk"
            value={disk}
            onChange={(v) => handleTimeout("disk", v)}
          />
        </div>
      </div>
    </div>
  );
}

function TimeoutRow({ label, value, onChange }: { label: string; value: number; onChange: (v: number) => void }) {
  return (
    <div className="setting-row">
      <span className="setting-label">{label}</span>
      <select
        className="timeout-select"
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
      >
        {TIMEOUT_OPTIONS.map((m) => (
          <option key={m} value={m}>{fmtTimeout(m)}</option>
        ))}
        {!TIMEOUT_OPTIONS.includes(value) && (
          <option value={value}>{fmtTimeout(value)}</option>
        )}
      </select>
    </div>
  );
}
