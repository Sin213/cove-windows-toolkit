import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import ConfirmDialog from "./ConfirmDialog";
import "./RestorePanel.css";

interface RestorePoint {
  sequence_number: number;
  description: string;
  restore_point_type: string;
  creation_time: string;
}

interface RestoreStatus {
  enabled: boolean;
  message: string;
}

interface ActionResult {
  success: boolean;
  message: string;
}

export default function RestorePanel() {
  const [points, setPoints] = useState<RestorePoint[]>([]);
  const [status, setStatus] = useState<RestoreStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [enabling, setEnabling] = useState(false);
  const [description, setDescription] = useState("Cove Optimizer - Pre-optimization backup");
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; message: string } | null>(null);
  const [confirmRestore, setConfirmRestore] = useState(false);

  const load = () => {
    setLoading(true);
    setError(null);
    Promise.all([
      invoke<RestoreStatus>("get_restore_status"),
      invoke<RestorePoint[]>("get_restore_points"),
    ])
      .then(([s, p]) => {
        setStatus(s);
        setPoints(p);
      })
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
  }, []);

  const handleCreate = () => {
    if (!description.trim()) return;
    setCreating(true);
    setFeedback(null);
    invoke<ActionResult>("create_restore_point", { description: description.trim() })
      .then((r) => {
        setFeedback({ type: r.success ? "success" : "error", message: r.message });
        if (r.success) load();
      })
      .catch((e) => setFeedback({ type: "error", message: String(e) }))
      .finally(() => setCreating(false));
  };

  const handleEnable = () => {
    setEnabling(true);
    setFeedback(null);
    invoke<ActionResult>("enable_system_protection")
      .then((r) => {
        setFeedback({ type: r.success ? "success" : "error", message: r.message });
        if (r.success) load();
      })
      .catch((e) => setFeedback({ type: "error", message: String(e) }))
      .finally(() => setEnabling(false));
  };

  const handleLaunchRestore = () => {
    invoke<ActionResult>("launch_system_restore")
      .then((r) => {
        setFeedback({ type: r.success ? "success" : "error", message: r.message });
      })
      .catch((e) => setFeedback({ type: "error", message: String(e) }));
  };

  if (loading) return <div className="panel-loading">Checking System Restore status...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;

  const formatDate = (iso: string) => {
    try {
      return new Date(iso).toLocaleString();
    } catch {
      return iso;
    }
  };

  return (
    <div className="restore-panel">
      {/* Status banner */}
      <div className={`restore-status ${status?.enabled ? "status-enabled" : "status-disabled"}`}>
        <span className="status-icon">{status?.enabled ? "✔" : "⚠"}</span>
        <span className="status-text">{status?.message}</span>
        {!status?.enabled && (
          <button className="enable-btn" onClick={handleEnable} disabled={enabling}>
            {enabling ? "Enabling..." : "Enable System Protection"}
          </button>
        )}
      </div>

      {/* Create section */}
      <div className="restore-create-section">
        <h3>Create Restore Point</h3>
        <p className="section-hint">
          Create a snapshot before running optimizations. You can roll back to this point if anything goes wrong.
        </p>
        <div className="create-row">
          <input
            type="text"
            className="restore-input"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Restore point description..."
            disabled={creating || !status?.enabled}
          />
          <button
            className="create-btn"
            onClick={handleCreate}
            disabled={creating || !description.trim() || !status?.enabled}
          >
            {creating ? "Creating..." : "Create"}
          </button>
        </div>
        {feedback && (
          <div className={`feedback feedback-${feedback.type}`}>
            {feedback.message}
          </div>
        )}
      </div>

      {/* Restore action */}
      <div className="restore-launch-section">
        <h3>Restore Windows</h3>
        <p className="section-hint">
          Opens the Windows System Restore wizard. You can choose a restore point and confirm before any changes are made.
        </p>
        <button className="launch-btn" onClick={() => setConfirmRestore(true)} disabled={!status?.enabled}>
          Open System Restore...
        </button>
      </div>

      {/* Existing restore points */}
      <div className="restore-points-section">
        <div className="points-header">
          <h3>Existing Restore Points</h3>
          <button className="refresh-btn" onClick={load}>Refresh</button>
        </div>
        {points.length === 0 ? (
          <div className="no-points">No restore points found.</div>
        ) : (
          <div className="points-list">
            {points.map((p) => (
              <div key={p.sequence_number} className="point-item">
                <div className="point-icon">&#x1F6E1;</div>
                <div className="point-content">
                  <div className="point-header">
                    <span className="point-desc">{p.description}</span>
                    <span className="point-type">{p.restore_point_type}</span>
                  </div>
                  <div className="point-meta">
                    <span className="point-date">{formatDate(p.creation_time)}</span>
                    <span className="point-seq">#{p.sequence_number}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
      <ConfirmDialog
        open={confirmRestore}
        title="Open System Restore"
        message="This will open the Windows System Restore wizard. You will be able to choose a restore point before any changes are made."
        safetyTier="Yellow"
        onConfirm={() => {
          setConfirmRestore(false);
          handleLaunchRestore();
        }}
        onCancel={() => setConfirmRestore(false)}
      />
    </div>
  );
}
