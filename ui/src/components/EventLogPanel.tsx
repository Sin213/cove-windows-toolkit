import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import { timeAgo } from "../lib/format";
import "./EventLogPanel.css";

interface EventEntry {
  id: number;
  source: string;
  level: string;
  message: string;
  time: string;
  count: number;
}

interface LogChannel {
  total: number;
  critical: number;
  error: number;
  warning: number;
  events: EventEntry[];
}

interface EventLogData {
  system: LogChannel;
  application: LogChannel;
}

type Tab = "system" | "application";

export default function EventLogPanel() {
  const [data, setData] = useState<EventLogData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("system");

  useEffect(() => {
    invoke<EventLogData>("get_event_log_summary")
      .then(setData)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="panel-loading">Reading event logs...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;
  if (!data) return null;

  const channel = tab === "system" ? data.system : data.application;

  return (
    <div className="eventlog-panel">
      <div className="log-tabs">
        <button
          className={`log-tab ${tab === "system" ? "active" : ""}`}
          onClick={() => setTab("system")}
        >
          System
        </button>
        <button
          className={`log-tab ${tab === "application" ? "active" : ""}`}
          onClick={() => setTab("application")}
        >
          Application
        </button>
      </div>

      <div className="log-summary-bar">
        <span className="log-stat total">{channel.total.toLocaleString()} total</span>
        {channel.critical > 0 && (
          <span className="log-stat critical">{channel.critical} critical</span>
        )}
        <span className="log-stat error">{channel.error} errors</span>
        <span className="log-stat warning">{channel.warning} warnings</span>
      </div>

      <div className="events-list">
        {channel.events.map((ev, i) => (
          <div key={i} className="event-item">
            <span className={`event-level-bar level-${ev.level.toLowerCase()}`} />
            <div className="event-content">
              <div className="event-header">
                <span className="event-source">{ev.source}</span>
                <span className={`event-level level-text-${ev.level.toLowerCase()}`}>
                  {ev.level}
                </span>
                <span className="event-id">ID {ev.id}</span>
                {ev.count > 1 && (
                  <span className="event-count">x{ev.count}</span>
                )}
                <span className="event-time">{timeAgo(ev.time)}</span>
              </div>
              <div className="event-message">{ev.message}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
