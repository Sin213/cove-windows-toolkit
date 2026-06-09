import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import "./ServicesPanel.css";

interface ServiceProfile {
  id: string;
  name: string;
  description: string;
}

interface ServiceItem {
  name: string;
  display_name: string;
  description: string;
  current_state: string;
  current_start_type: string;
  target_start_type: string;
  profile: string;
  safety: string;
}

interface ServicesData {
  profiles: ServiceProfile[];
  services: ServiceItem[];
}

export default function ServicesPanel() {
  const [data, setData] = useState<ServicesData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeProfile, setActiveProfile] = useState("conservative");
  const [applied, setApplied] = useState<Record<string, boolean>>({});

  useEffect(() => {
    invoke<ServicesData>("get_services_tweaks")
      .then(setData)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const handleApply = async (svc: ServiceItem) => {
    try {
      await invoke("apply_service_change", { name: svc.name });
      setApplied((s) => ({ ...s, [svc.name]: true }));
    } catch (e) {
      console.error("Service change failed:", e);
    }
  };

  if (loading) return <div className="panel-loading">Loading services...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;
  if (!data) return null;

  const filtered = data.services.filter((s) => {
    if (activeProfile === "advanced") return true;
    return s.profile === "conservative";
  });

  return (
    <div className="services-panel">
      <div className="profile-tabs">
        {data.profiles.map((p) => (
          <button
            key={p.id}
            className={`profile-tab ${activeProfile === p.id ? "active" : ""}`}
            onClick={() => setActiveProfile(p.id)}
          >
            <span className="profile-tab-name">{p.name}</span>
            <span className="profile-tab-desc">{p.description}</span>
          </button>
        ))}
      </div>

      <div className="services-list">
        <div className="services-header-row">
          <span className="sh-name">Service</span>
          <span className="sh-state">State</span>
          <span className="sh-current">Current</span>
          <span className="sh-target">Target</span>
          <span className="sh-action">Action</span>
        </div>
        {filtered.map((svc) => (
          <div
            key={svc.name}
            className={`service-row ${applied[svc.name] ? "row-applied" : ""}`}
          >
            <div className="svc-info">
              <div className="svc-name-row">
                <span className={`tier-badge tier-${svc.safety.toLowerCase()}`}>
                  {svc.safety}
                </span>
                <span className="svc-display-name">{svc.display_name}</span>
              </div>
              <div className="svc-desc">{svc.description}</div>
            </div>
            <div className="svc-state">
              <span
                className={`state-dot ${svc.current_state === "Running" ? "dot-running" : "dot-stopped"}`}
              />
              {svc.current_state}
            </div>
            <div className="svc-start-type">{svc.current_start_type}</div>
            <div className="svc-target">{svc.target_start_type}</div>
            <div className="svc-action">
              {applied[svc.name] ? (
                <span className="applied-label">Done</span>
              ) : (
                <button
                  className="apply-btn"
                  onClick={() => handleApply(svc)}
                >
                  Apply
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
