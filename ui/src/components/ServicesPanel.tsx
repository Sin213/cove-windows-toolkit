import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import ConfirmDialog from "./ConfirmDialog";
import "./ServicesPanel.css";

interface ServiceItem {
  id: string;
  name: string;
  service: string;
  description: string;
  tier: string;
  current: string;
  optimized: string;
  impact: string;
  warning?: string;
}

interface ServicesData {
  conservative: ServiceItem[];
  advanced: ServiceItem[];
}

const PROFILE_TABS = [
  { id: "conservative", name: "Conservative", description: "Disable only clearly unnecessary services" },
  { id: "advanced", name: "Advanced", description: "Disable more services for maximum performance (review carefully)" },
];

export default function ServicesPanel() {
  const [data, setData] = useState<ServicesData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeProfile, setActiveProfile] = useState("conservative");
  const [applied, setApplied] = useState<Record<string, boolean>>({});
  const [pendingConfirm, setPendingConfirm] = useState<ServiceItem | null>(null);

  useEffect(() => {
    invoke<ServicesData>("get_services_tweaks")
      .then(setData)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const handleApply = async (svc: ServiceItem) => {
    try {
      const res = await invoke<{ success: boolean; message?: string }>("apply_service_change", { id: svc.id });
      if (res.success) {
        setApplied((s) => ({ ...s, [svc.id]: true }));
      } else {
        setError(res.message || "Service change failed.");
      }
    } catch (e) {
      setError(String(e));
    }
  };

  if (loading) return <div className="panel-loading">Loading services...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;
  if (!data) return null;

  const filtered: ServiceItem[] =
    activeProfile === "advanced"
      ? [...data.conservative, ...data.advanced]
      : data.conservative;

  return (
    <div className="services-panel">
      <div className="profile-tabs">
        {PROFILE_TABS.map((p) => (
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
          <span className="sh-current">Current</span>
          <span className="sh-target">Target</span>
          <span className="sh-action">Action</span>
        </div>
        {filtered.map((svc) => (
          <div
            key={svc.id}
            className={`service-row ${applied[svc.id] ? "row-applied" : ""}`}
          >
            <div className="svc-info">
              <div className="svc-name-row">
                <span className={`tier-badge tier-${svc.tier.toLowerCase()}`}>
                  {svc.tier}
                </span>
                <span className="svc-display-name">{svc.name}</span>
              </div>
              <div className="svc-desc">{svc.description}</div>
              {svc.warning && (
                <div className="svc-warning">{svc.warning}</div>
              )}
            </div>
            <div className="svc-start-type">{svc.current}</div>
            <div className="svc-target">{svc.optimized}</div>
            <div className="svc-action">
              {applied[svc.id] ? (
                <span className="applied-label">Done</span>
              ) : (
                <button
                  className="apply-btn"
                  onClick={() => {
                    if (svc.tier !== "green") {
                      setPendingConfirm(svc);
                    } else {
                      handleApply(svc);
                    }
                  }}
                >
                  Apply
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
      <ConfirmDialog
        open={!!pendingConfirm}
        title={`Change ${pendingConfirm?.name ?? ""}`}
        message={
          pendingConfirm?.warning ??
          (pendingConfirm?.tier === "red"
            ? "This is a destructive operation. Are you sure?"
            : `This will change ${pendingConfirm?.service ?? "the service"} from ${pendingConfirm?.current ?? ""} to ${pendingConfirm?.optimized ?? ""}. Continue?`)
        }
        safetyTier={pendingConfirm?.tier === "red" ? "Red" : "Yellow"}
        onConfirm={() => {
          if (pendingConfirm) handleApply(pendingConfirm);
          setPendingConfirm(null);
        }}
        onCancel={() => setPendingConfirm(null)}
      />
    </div>
  );
}
