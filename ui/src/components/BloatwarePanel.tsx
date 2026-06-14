import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import ConfirmDialog from "./ConfirmDialog";
import Icon from "./Icon";
import "./BloatwarePanel.css";

interface BloatwareApp {
  package_name: string;
  display_name: string;
  publisher: string;
  category: string;
  installed: boolean;
}

interface RemoveResult {
  package_name: string;
  success: boolean;
  message: string;
}

const CATEGORY_ORDER = [
  "games_and_ads",
  "communication",
  "media",
  "utilities",
  "oem",
] as const;

const CATEGORY_LABELS: Record<string, string> = {
  games_and_ads: "Games & Ads",
  communication: "Communication",
  media: "Media",
  utilities: "Utilities",
  oem: "Manufacturer (OEM)",
};

export default function BloatwarePanel() {
  const [apps, setApps] = useState<BloatwareApp[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [removing, setRemoving] = useState(false);
  const [results, setResults] = useState<Record<string, RemoveResult>>({});
  const [showConfirm, setShowConfirm] = useState(false);

  useEffect(() => {
    invoke<BloatwareApp[]>("get_bloatware")
      .then(setApps)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const installed = apps.filter((a) => a.installed);

  const toggle = (pkg: string) => {
    if (results[pkg]?.success) return;
    setSelected((s) => ({ ...s, [pkg]: !s[pkg] }));
  };

  const toggleAll = () => {
    const removable = installed.filter((a) => !results[a.package_name]?.success);
    const allSelected = removable.every((a) => selected[a.package_name]);
    const next: Record<string, boolean> = { ...selected };
    removable.forEach((a) => {
      next[a.package_name] = !allSelected;
    });
    setSelected(next);
  };

  const selectedApps = installed.filter(
    (a) => selected[a.package_name] && !results[a.package_name]?.success
  );

  const handleRemove = async () => {
    setRemoving(true);
    try {
      const packages = selectedApps.map((a) => a.package_name);
      const res = await invoke<RemoveResult[]>("remove_bloatware", { packages });
      const map: Record<string, RemoveResult> = {};
      res.forEach((r) => {
        map[r.package_name] = r;
      });
      setResults((prev) => ({ ...prev, ...map }));
    } catch (e) {
      console.error("Bloatware removal failed:", e);
    } finally {
      setRemoving(false);
    }
  };

  if (loading) return <div className="panel-loading">Scanning installed apps...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;

  const grouped = CATEGORY_ORDER.map((cat) => ({
    cat,
    items: installed.filter((a) => a.category === cat),
  })).filter((g) => g.items.length > 0);

  return (
    <div className="bloatware-panel">
      <div className="bloat-summary">
        <div className="bs-stat">
          <span className="bs-num">{installed.length}</span>
          <span className="bs-lbl">installed bloatware apps</span>
        </div>
        <div className="bloat-actions">
          <button className="btn-sel" onClick={toggleAll} disabled={installed.length === 0}>
            Select All
          </button>
          <button
            className="btn-remove"
            onClick={() => setShowConfirm(true)}
            disabled={removing || selectedApps.length === 0}
          >
            {removing ? "Removing..." : `Remove Selected (${selectedApps.length})`}
          </button>
        </div>
      </div>

      {installed.length === 0 && (
        <div className="no-bloatware">No known bloatware apps are installed. Nice and clean.</div>
      )}

      {grouped.map((group) => (
        <div key={group.cat} className="bloat-group">
          <div className="bloat-group-title">{CATEGORY_LABELS[group.cat] || group.cat}</div>
          <div className="bloat-list">
            {group.items.map((app) => {
              const result = results[app.package_name];
              const on = !!selected[app.package_name] && !result?.success;
              return (
                <label
                  key={app.package_name}
                  className={`bloat-item ${on ? "on" : ""} ${result?.success ? "removed" : ""}`}
                >
                  <input
                    type="checkbox"
                    checked={on}
                    onChange={() => toggle(app.package_name)}
                    disabled={result?.success}
                    className="bloat-native"
                  />
                  <span className="bloat-check"><Icon name="check" size={11} stroke={2.4} /></span>
                  <div className="bloat-info">
                    <div className="bloat-name">{app.display_name}</div>
                    <div className="bloat-pkg">{app.package_name}</div>
                  </div>
                  {result && (
                    <span className={`bloat-result ${result.success ? "ok" : "fail"}`}>
                      {result.success ? "Removed" : result.message}
                    </span>
                  )}
                </label>
              );
            })}
          </div>
        </div>
      ))}

      <ConfirmDialog
        open={showConfirm}
        title="Remove Selected Apps"
        message={`This will uninstall ${selectedApps.length} app${selectedApps.length === 1 ? "" : "s"} for all users (and deprovision them so they don't reinstall for new users). Continue?`}
        safetyTier="Yellow"
        onConfirm={() => {
          setShowConfirm(false);
          handleRemove();
        }}
        onCancel={() => setShowConfirm(false)}
      />
    </div>
  );
}
