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
}

interface LogChannel {
  critical: number;
  error: number;
  warning: number;
  recent_events: EventEntry[];
}

interface EventLogData {
  system: LogChannel;
  application: LogChannel;
}

type Tab = "system" | "application";
type SeverityFilter = "all" | "Critical" | "Error" | "Warning";

export default function EventLogPanel() {
  const [data, setData] = useState<EventLogData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("system");
  const [filter, setFilter] = useState<SeverityFilter>("all");

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
  const filtered = filter === "all"
    ? channel.recent_events
    : channel.recent_events.filter((ev) => ev.level === filter);

  return (
    <div className="eventlog-panel">
      <div className="log-tabs">
        <button
          className={`log-tab ${tab === "system" ? "active" : ""}`}
          onClick={() => { setTab("system"); setFilter("all"); }}
        >
          System
        </button>
        <button
          className={`log-tab ${tab === "application" ? "active" : ""}`}
          onClick={() => { setTab("application"); setFilter("all"); }}
        >
          Application
        </button>
      </div>

      <div className="log-summary-bar">
        {channel.critical > 0 && (
          <button
            className={`log-stat critical ${filter === "Critical" ? "active-filter" : ""}`}
            onClick={() => setFilter(filter === "Critical" ? "all" : "Critical")}
          >
            {channel.critical} critical
          </button>
        )}
        <button
          className={`log-stat error ${filter === "Error" ? "active-filter" : ""}`}
          onClick={() => setFilter(filter === "Error" ? "all" : "Error")}
        >
          {channel.error} errors
        </button>
        <button
          className={`log-stat warning ${filter === "Warning" ? "active-filter" : ""}`}
          onClick={() => setFilter(filter === "Warning" ? "all" : "Warning")}
        >
          {channel.warning} warnings
        </button>
        {filter !== "all" && (
          <button className="log-stat clear-filter" onClick={() => setFilter("all")}>
            Show all
          </button>
        )}
      </div>

      <div className="events-list">
        {filtered.length === 0 && (
          <div className="no-events">No {filter === "all" ? "" : filter.toLowerCase() + " "}events found.</div>
        )}
        {filtered.map((ev, i) => (
          <div key={`${ev.time}-${ev.id}-${ev.source}-${i}`} className="event-item">
            <span className={`event-level-bar level-${ev.level.toLowerCase()}`} />
            <div className="event-content">
              <div className="event-header">
                <span className="event-source">{ev.source}</span>
                <span className={`event-level level-text-${ev.level.toLowerCase()}`}>
                  {ev.level}
                </span>
                <span className="event-id">ID {ev.id}</span>
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
