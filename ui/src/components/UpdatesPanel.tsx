import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import { timeAgo, formatBytes } from "../lib/format";
import "./UpdatesPanel.css";

interface PendingUpdate {
  title: string;
  kb: string | null;
  severity: string;
  size_bytes: number;
  classification: string;
}

interface ComponentStore {
  health: string;
  size_bytes: number;
  last_cleanup: string;
  pending_cleanup_bytes: number;
}

interface UpdateStatus {
  last_check: string;
  last_install: string;
  reboot_required: boolean;
  pending_updates: PendingUpdate[];
  component_store: ComponentStore;
}

export default function UpdatesPanel() {
  const [data, setData] = useState<UpdateStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    invoke<UpdateStatus>("get_update_status")
      .then(setData)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="panel-loading">Checking updates...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;
  if (!data) return null;

  return (
    <div className="updates-panel">
      {/* Status row */}
      <div className="update-status-row">
        <div className="status-field">
          <span className="status-label">Last Check</span>
          <span className="status-value">{timeAgo(data.last_check)}</span>
        </div>
        <div className="status-field">
          <span className="status-label">Last Install</span>
          <span className="status-value">{timeAgo(data.last_install)}</span>
        </div>
        {data.reboot_required && (
          <div className="reboot-notice">Reboot Required</div>
        )}
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
                    {u.kb && <span className="update-kb">{u.kb}</span>}
                    <span className="update-class">{u.classification}</span>
                    <span className="update-size">
                      {formatBytes(u.size_bytes)}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
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
                className={`cbs-value ${data.component_store.health === "Healthy" ? "cbs-healthy" : "cbs-unhealthy"}`}
              >
                {data.component_store.health}
              </span>
            </div>
            <div className="cbs-field">
              <span className="cbs-label">Size</span>
              <span className="cbs-value">
                {formatBytes(data.component_store.size_bytes)}
              </span>
            </div>
            <div className="cbs-field">
              <span className="cbs-label">Last Cleanup</span>
              <span className="cbs-value">
                {timeAgo(data.component_store.last_cleanup)}
              </span>
            </div>
            <div className="cbs-field">
              <span className="cbs-label">Reclaimable</span>
              <span className="cbs-value">
                {formatBytes(data.component_store.pending_cleanup_bytes)}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
