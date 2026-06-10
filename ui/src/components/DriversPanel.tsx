import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import "./DriversPanel.css";

interface DriverEntry {
  name: string;
  device: string;
  version: string;
  date: string;
  signed: boolean;
  status: string;
}

interface DriverAudit {
  total: number;
  unsigned: number;
  outdated: number;
  problematic: DriverEntry[];
  healthy: DriverEntry[];
}

export default function DriversPanel() {
  const [data, setData] = useState<DriverAudit | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showHealthy, setShowHealthy] = useState(false);

  useEffect(() => {
    invoke<DriverAudit>("get_driver_audit")
      .then(setData)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="panel-loading">Auditing drivers...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;
  if (!data) return null;

  const handleCheckUpdates = () => {
    invoke("open_url", { url: "ms-settings:windowsupdate-optionalupdates" });
  };

  return (
    <div className="drivers-panel">
      <div className="driver-stats">
        <div className="stat-card">
          <span className="stat-num">{data.total}</span>
          <span className="stat-label">Total</span>
        </div>
        <div className="stat-card stat-warn">
          <span className="stat-num">{data.unsigned}</span>
          <span className="stat-label">Unsigned</span>
        </div>
        <div className="stat-card stat-warn">
          <span className="stat-num">{data.outdated}</span>
          <span className="stat-label">Outdated</span>
        </div>
      </div>

      {(data.outdated > 0 || data.unsigned > 0) && (
        <div className="driver-update-bar">
          <span>
            {data.outdated > 0 && `${data.outdated} outdated`}
            {data.outdated > 0 && data.unsigned > 0 && " and "}
            {data.unsigned > 0 && `${data.unsigned} unsigned`}
            {" driver"}{(data.outdated + data.unsigned) !== 1 && "s"} found
          </span>
          <button className="driver-update-btn" onClick={handleCheckUpdates}>
            Check for Driver Updates
          </button>
        </div>
      )}

      {data.problematic.length > 0 && (
        <div className="driver-section">
          <h3>Problematic Drivers</h3>
          <div className="driver-table">
            {data.problematic.map((d, i) => (
              <div key={`${d.name}-${i}`} className="driver-row problem-row">
                <div className="driver-info">
                  <div className="driver-name-row">
                    <span className="driver-name">{d.name}</span>
                    <span className={`driver-status-badge status-${d.status}`}>
                      {d.status}
                    </span>
                    {!d.signed && (
                      <span className="unsigned-badge">unsigned</span>
                    )}
                  </div>
                  <div className="driver-device">{d.device}</div>
                </div>
                <div className="driver-meta">
                  <div className="driver-version">{d.version}</div>
                  <div className="driver-date">{d.date}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="driver-section">
        <button
          className="healthy-toggle"
          onClick={() => setShowHealthy(!showHealthy)}
        >
          {showHealthy ? "▾" : "▸"} Healthy Drivers ({data.healthy.length})
        </button>
        {showHealthy && (
          <div className="driver-table">
            {data.healthy.map((d, i) => (
              <div key={`${d.name}-${i}`} className="driver-row">
                <div className="driver-info">
                  <div className="driver-name-row">
                    <span className="driver-name">{d.name}</span>
                    <span className="driver-status-badge status-ok">ok</span>
                  </div>
                  <div className="driver-device">{d.device}</div>
                </div>
                <div className="driver-meta">
                  <div className="driver-version">{d.version}</div>
                  <div className="driver-date">{d.date}</div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
