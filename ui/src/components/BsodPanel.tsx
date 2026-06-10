import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import { timeAgo } from "../lib/format";
import "./BsodPanel.css";

interface BsodDump {
  file: string;
  date: string;
  bug_check: string;
  bug_check_name: string;
  faulting_module: string;
  description: string;
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

  const toggle = (file: string) =>
    setExpanded((s) => ({ ...s, [file]: !s[file] }));

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
          <div key={dump.file} className="dump-item">
            <button className="dump-header" onClick={() => toggle(dump.file)}>
              <span className="dump-chevron">
                {expanded[dump.file] ? "▾" : "▸"}
              </span>
              <div className="dump-header-info">
                <span className="dump-code">{dump.bug_check}</span>
                <span className="dump-name">{dump.bug_check_name}</span>
              </div>
              <span className="dump-time">{timeAgo(dump.date)}</span>
            </button>
            {expanded[dump.file] && (
              <div className="dump-details">
                <div className="dump-row">
                  <span className="dump-label">File</span>
                  <span className="dump-value mono">{dump.file}</span>
                </div>
                <div className="dump-row">
                  <span className="dump-label">Faulting Module</span>
                  <span className="dump-value mono">{dump.faulting_module}</span>
                </div>
                <div className="dump-row">
                  <span className="dump-label">Description</span>
                  <span className="dump-value">{dump.description}</span>
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
