import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import { timeAgo } from "../lib/format";
import "./BsodPanel.css";

interface BsodDump {
  filename: string;
  timestamp: string;
  bug_check_code: string;
  bug_check_name: string;
  faulting_module: string;
  faulting_driver: string;
  detail: string;
  recommendation: string;
}

export default function BsodPanel() {
  const [dumps, setDumps] = useState<BsodDump[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  useEffect(() => {
    invoke<BsodDump[]>("get_bsod_dumps")
      .then(setDumps)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const toggle = (filename: string) =>
    setExpanded((s) => ({ ...s, [filename]: !s[filename] }));

  if (loading) return <div className="panel-loading">Scanning minidumps...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;

  if (dumps.length === 0) {
    return (
      <div className="bsod-panel">
        <div className="bsod-empty">
          <div className="empty-icon">&#10003;</div>
          <h3>No crash dumps found</h3>
          <p>No BSOD minidump files were found in C:\Windows\Minidump</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bsod-panel">
      <div className="bsod-count">
        {dumps.length} crash dump{dumps.length !== 1 ? "s" : ""} found
      </div>

      <div className="dumps-list">
        {dumps.map((dump) => (
          <div key={dump.filename} className="dump-item">
            <button className="dump-header" onClick={() => toggle(dump.filename)}>
              <span className="dump-chevron">
                {expanded[dump.filename] ? "▾" : "▸"}
              </span>
              <div className="dump-header-info">
                <span className="dump-code">{dump.bug_check_code}</span>
                <span className="dump-name">{dump.bug_check_name}</span>
              </div>
              <span className="dump-time">{timeAgo(dump.timestamp)}</span>
            </button>
            {expanded[dump.filename] && (
              <div className="dump-details">
                <div className="dump-row">
                  <span className="dump-label">File</span>
                  <span className="dump-value mono">{dump.filename}</span>
                </div>
                <div className="dump-row">
                  <span className="dump-label">Faulting Module</span>
                  <span className="dump-value mono">{dump.faulting_module}</span>
                </div>
                <div className="dump-row">
                  <span className="dump-label">Faulting Driver</span>
                  <span className="dump-value mono">{dump.faulting_driver}</span>
                </div>
                <div className="dump-row">
                  <span className="dump-label">Description</span>
                  <span className="dump-value">{dump.detail}</span>
                </div>
                <div className="dump-recommendation">
                  <span className="rec-label">Recommendation</span>
                  <p>{dump.recommendation}</p>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
