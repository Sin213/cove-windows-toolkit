import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import { timeAgo } from "../lib/format";
import "./UpdatesPanel.css";

interface PendingUpdate {
  title: string;
  severity: string;
  size_mb: number;
  category: string;
}

interface UpdateStatus {
  last_check: string;
  last_install: string;
  service_status: string;
  pending_updates: PendingUpdate[];
  component_store_health: string;
  days_since_last_update: number;
}

interface ActionResult {
  success: boolean;
  message: string;
  output?: string;
}

export default function UpdatesPanel() {
  const [data, setData] = useState<UpdateStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [resetting, setResetting] = useState(false);
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; message: string } | null>(null);
  const [resetOutput, setResetOutput] = useState<string | null>(null);

  useEffect(() => {
    invoke<UpdateStatus>("get_update_status")
      .then(setData)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const handleCheckUpdates = () => {
    setFeedback(null);
    invoke<ActionResult>("trigger_update_check")
      .then((r) => setFeedback({ type: r.success ? "success" : "error", message: r.message }))
      .catch((e) => setFeedback({ type: "error", message: String(e) }));
  };

  const handleReset = async () => {
    setResetting(true);
    setFeedback(null);
    setResetOutput(null);
    try {
      const r = await invoke<ActionResult>("reset_windows_update");
      setFeedback({ type: r.success ? "success" : "error", message: r.message });
      if (r.output) setResetOutput(r.output);
    } catch (e) {
      setFeedback({ type: "error", message: String(e) });
    } finally {
      setResetting(false);
    }
  };

  if (loading) return <div className="panel-loading">Checking updates...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;
  if (!data) return null;

  return (
    <div className="updates-panel">
      {/* Status row */}
      <div className="update-status-row">
        <div className="status-field">
          <span className="status-label">Last Install</span>
          <span className="status-value">{timeAgo(data.last_install)}</span>
        </div>
        <div className="status-field">
          <span className="status-label">Service</span>
          <span className="status-value">{data.service_status}</span>
        </div>
        <div className="status-field">
          <span className="status-label">Days Since Update</span>
          <span className="status-value">{data.days_since_last_update}</span>
        </div>
      </div>

      {/* Pending updates */}
      <div className="updates-section">
        <h3>
          Pending Updates ({data.pending_updates.length})
        </h3>
        {data.pending_updates.length === 0 ? (
          <div className="up-to-date">System is up to date</div>
        ) : (
          <div className="updates-list">
            {data.pending_updates.map((u, i) => (
              <div key={i} className="update-item">
                <div className="update-info">
                  <div className="update-title-row">
                    <span className="update-title">{u.title}</span>
                    <span
                      className={`update-severity sev-${u.severity.toLowerCase()}`}
                    >
                      {u.severity}
                    </span>
                  </div>
                  <div className="update-meta">
                    <span className="update-class">{u.category}</span>
                    <span className="update-size">{u.size_mb} MB</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="updates-section">
        <h3>Actions</h3>
        <div className="wu-actions">
          <button className="wu-btn wu-btn-primary" onClick={handleCheckUpdates}>
            Check for Updates
          </button>
          <button className="wu-btn wu-btn-secondary" onClick={() => invoke("open_url", { url: "ms-settings:windowsupdate-optionalupdates" })}>
            Check for Driver Updates
          </button>
          <button className="wu-btn wu-btn-warning" onClick={handleReset} disabled={resetting}>
            {resetting ? "Resetting..." : "Reset Windows Update"}
          </button>
        </div>
        <p className="wu-hint">
          Reset stops WU services, clears the update cache (SoftwareDistribution &amp; catroot2),
          re-registers DLLs, and restarts services. A reboot is recommended after.
        </p>
        {feedback && (
          <div className={`wu-feedback wu-feedback-${feedback.type}`}>
            {feedback.message}
          </div>
        )}
        {resetOutput && (
          <pre className="wu-output">{resetOutput}</pre>
        )}
      </div>

      {/* Component store health */}
      <div className="updates-section">
        <h3>Component Store</h3>
        <div className="cbs-card">
          <div className="cbs-grid">
            <div className="cbs-field">
              <span className="cbs-label">Health</span>
              <span
                className={`cbs-value ${data.component_store_health === "Healthy" ? "cbs-healthy" : "cbs-unhealthy"}`}
              >
                {data.component_store_health}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
