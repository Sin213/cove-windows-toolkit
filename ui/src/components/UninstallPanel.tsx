import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import ConfirmDialog from "./ConfirmDialog";
import "./UninstallPanel.css";

interface InstalledProgram {
  name: string;
  publisher: string;
  version: string;
  install_date: string;
  size_bytes: number;
  uninstall_string: string;
  quiet_uninstall_string: string;
  install_location: string;
  registry_key: string;
  is_system: boolean;
}

interface Leftover {
  path: string;
  category: string;
  size_bytes: number;
}

interface ScanResult {
  leftovers: Leftover[];
  total_size_bytes: number;
}

interface RemoveResult {
  results: { path: string; success: boolean; message: string }[];
}

function fmtBytes(b: number): string {
  if (b >= 1e9) return `${(b / 1e9).toFixed(1)} GB`;
  if (b >= 1e6) return `${(b / 1e6).toFixed(1)} MB`;
  if (b >= 1e3) return `${(b / 1e3).toFixed(0)} KB`;
  return `${b} B`;
}

// Stable identity for a program row. registry_key can be empty for some entries
// (e.g. system VC++ redists), so fall back to a composite of name/version/publisher
// to avoid duplicate React keys and mis-highlighting rows that share a name.
function progId(p: InstalledProgram): string {
  return p.registry_key || `${p.name}|${p.version}|${p.publisher}`;
}

type Step = "list" | "uninstalling" | "scanning" | "leftovers" | "cleaning" | "done";

export default function UninstallPanel() {
  const [programs, setPrograms] = useState<InstalledProgram[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [showSystem, setShowSystem] = useState(false);
  const [selected, setSelected] = useState<InstalledProgram | null>(null);
  const [step, setStep] = useState<Step>("list");
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [checkedLeftovers, setCheckedLeftovers] = useState<Set<string>>(new Set());
  const [feedback, setFeedback] = useState<string | null>(null);
  const [removeResults, setRemoveResults] = useState<RemoveResult | null>(null);
  const [confirmAction, setConfirmAction] = useState<"uninstall" | "clean" | null>(null);

  useEffect(() => {
    invoke<InstalledProgram[]>("get_installed_programs")
      .then(setPrograms)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const filtered = programs.filter((p) => {
    if (!showSystem && p.is_system) return false;
    if (!search) return true;
    const q = search.toLowerCase();
    return p.name.toLowerCase().includes(q) || p.publisher.toLowerCase().includes(q);
  });

  const handleSelect = (p: InstalledProgram) => {
    setSelected(p);
    setStep("list");
    setScan(null);
    setFeedback(null);
    setRemoveResults(null);
  };

  const handleUninstall = async () => {
    if (!selected) return;
    setStep("uninstalling");
    setFeedback(null);
    try {
      await invoke("uninstall_program", {
        uninstallString: selected.uninstall_string,
        quietUninstallString: selected.quiet_uninstall_string,
      });
      setFeedback("Standard uninstall completed. Scanning for leftovers...");
    } catch (e) {
      setFeedback(`Uninstall error: ${e}. Scanning for leftovers anyway...`);
    }
    handleScan();
  };

  const handleScanOnly = () => {
    handleScan();
  };

  const handleScan = async () => {
    if (!selected) return;
    setStep("scanning");
    try {
      const result = await invoke<ScanResult>("scan_leftovers", {
        name: selected.name,
        publisher: selected.publisher,
        installLocation: selected.install_location,
        registryKey: selected.registry_key,
      });
      setScan(result);
      // Pre-check only files/registry; require a conscious choice to remove
      // services and scheduled tasks.
      setCheckedLeftovers(
        new Set(
          result.leftovers
            .filter((l) => l.category === "Folder" || l.category === "Registry")
            .map((l) => l.path)
        )
      );
      setStep("leftovers");
    } catch (e) {
      setFeedback(`Scan error: ${e}`);
      setStep("list");
    }
  };

  const handleClean = async () => {
    if (!scan) return;
    const paths = Array.from(checkedLeftovers);
    if (paths.length === 0) return;
    setStep("cleaning");
    try {
      const result = await invoke<RemoveResult>("remove_leftovers", { paths });
      setRemoveResults(result);
      setStep("done");
    } catch (e) {
      setFeedback(`Clean error: ${e}`);
      setStep("leftovers");
    }
  };

  const toggleLeftover = (path: string) => {
    setCheckedLeftovers((prev) => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });
  };

  const toggleAll = () => {
    if (!scan) return;
    if (checkedLeftovers.size === scan.leftovers.length) {
      setCheckedLeftovers(new Set());
    } else {
      setCheckedLeftovers(new Set(scan.leftovers.map((l) => l.path)));
    }
  };

  const resetToList = () => {
    setSelected(null);
    setStep("list");
    setScan(null);
    setFeedback(null);
    setRemoveResults(null);
  };

  if (loading) return <div className="panel-loading">Loading installed programs...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;

  return (
    <div className="uninstall-panel">
      {/* Program list */}
      <div className="uninstall-left">
        <div className="search-bar">
          <input
            type="text"
            placeholder="Search programs..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="search-input"
          />
          <label className="system-toggle">
            <input type="checkbox" checked={showSystem} onChange={(e) => setShowSystem(e.target.checked)} />
            System
          </label>
        </div>
        <div className="program-count">{filtered.length} programs</div>
        <div className="program-list">
          {filtered.map((p) => (
            <button
              key={progId(p)}
              className={`program-item ${selected && progId(selected) === progId(p) ? "active" : ""}`}
              onClick={() => handleSelect(p)}
            >
              <div className="prog-name">{p.name}</div>
              <div className="prog-meta">
                <span>{p.publisher}</span>
                {p.size_bytes > 0 && <span>{fmtBytes(p.size_bytes)}</span>}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Detail / action area */}
      <div className="uninstall-right">
        {!selected && (
          <div className="no-selection">
            <div className="no-sel-icon">⊘</div>
            <p>Select a program to uninstall</p>
          </div>
        )}

        {selected && step === "list" && (
          <div className="program-detail">
            <h2>{selected.name}</h2>
            <div className="detail-grid">
              {selected.publisher && <DetailRow label="Publisher" value={selected.publisher} />}
              {selected.version && <DetailRow label="Version" value={selected.version} />}
              {selected.install_date && <DetailRow label="Installed" value={selected.install_date} />}
              {selected.size_bytes > 0 && <DetailRow label="Size" value={fmtBytes(selected.size_bytes)} />}
              {selected.install_location && <DetailRow label="Location" value={selected.install_location} />}
            </div>
            <div className="action-buttons">
              <button className="action-btn action-primary" onClick={() => setConfirmAction("uninstall")}
                disabled={!selected.uninstall_string && !selected.quiet_uninstall_string}>
                Uninstall + Deep Clean
              </button>
              <button className="action-btn action-secondary" onClick={handleScanOnly}>
                Scan for Leftovers Only
              </button>
            </div>
            {!selected.uninstall_string && !selected.quiet_uninstall_string && (
              <div className="no-uninstall-hint">No uninstall command found. Use "Scan for Leftovers" to find remaining files.</div>
            )}
          </div>
        )}

        {(step === "uninstalling" || step === "scanning") && (
          <div className="progress-state">
            <div className="progress-spinner" />
            <p>{step === "uninstalling" ? "Running uninstaller..." : "Scanning for leftover files, registry keys, services..."}</p>
            {feedback && <div className="progress-feedback">{feedback}</div>}
          </div>
        )}

        {step === "leftovers" && scan && (
          <div className="leftovers-view">
            <div className="leftovers-header">
              <h3>Leftovers Found</h3>
              <span className="leftover-summary">
                {scan.leftovers.length} items - {fmtBytes(scan.total_size_bytes)}
              </span>
            </div>
            {feedback && <div className="progress-feedback">{feedback}</div>}
            {scan.leftovers.length === 0 ? (
              <div className="no-leftovers">
                <p>No leftover files or registry entries found. Clean uninstall!</p>
                <button className="action-btn action-secondary" onClick={resetToList}>Back to list</button>
              </div>
            ) : (
              <>
                <div className="leftovers-toolbar">
                  <button className="select-all-btn" onClick={toggleAll}>
                    {checkedLeftovers.size === scan.leftovers.length ? "Deselect All" : "Select All"}
                  </button>
                  <span className="checked-count">{checkedLeftovers.size} selected</span>
                </div>
                <div className="leftovers-list">
                  {scan.leftovers.map((l) => (
                    <label key={l.path} className="leftover-item">
                      <input
                        type="checkbox"
                        checked={checkedLeftovers.has(l.path)}
                        onChange={() => toggleLeftover(l.path)}
                      />
                      <span className={`leftover-cat cat-${l.category.toLowerCase().replace(/\s/g, '-')}`}>
                        {l.category}
                      </span>
                      <span className="leftover-path">{l.path}</span>
                      {l.size_bytes > 0 && <span className="leftover-size">{fmtBytes(l.size_bytes)}</span>}
                    </label>
                  ))}
                </div>
                <div className="leftovers-actions">
                  <button className="action-btn action-danger" onClick={() => setConfirmAction("clean")} disabled={checkedLeftovers.size === 0}>
                    Remove Selected ({checkedLeftovers.size})
                  </button>
                  <button className="action-btn action-secondary" onClick={resetToList}>Cancel</button>
                </div>
              </>
            )}
          </div>
        )}

        {step === "cleaning" && (
          <div className="progress-state">
            <div className="progress-spinner" />
            <p>Removing leftover files and registry entries...</p>
          </div>
        )}

        {step === "done" && removeResults && (
          <div className="done-view">
            <h3>Cleanup Complete</h3>
            <div className="results-list">
              {removeResults.results.map((r, i) => (
                <div key={i} className={`result-row ${r.success ? "result-ok" : "result-fail"}`}>
                  <span className="result-icon">{r.success ? "✔" : "✖"}</span>
                  <span className="result-path">{r.path}</span>
                  {r.message && r.message !== "Removed" && (
                    <span className="result-msg">{r.message}</span>
                  )}
                </div>
              ))}
            </div>
            {removeResults.results.some((r) => r.message.toLowerCase().includes("restart")) && (
              <div className="restart-note">
                ⟳ Some items were in use and will be removed after you restart Windows.
              </div>
            )}
            <div className="done-summary">
              {removeResults.results.filter((r) => r.success).length} of {removeResults.results.length} items removed.
            </div>
            <button className="action-btn action-secondary" onClick={resetToList}>Back to list</button>
          </div>
        )}
      </div>
      <ConfirmDialog
        open={!!confirmAction}
        title={
          confirmAction === "uninstall"
            ? `Uninstall ${selected?.name ?? ""}`
            : `Remove ${checkedLeftovers.size} Leftover Items`
        }
        message={
          confirmAction === "uninstall"
            ? `This will uninstall ${selected?.name ?? ""} and scan for leftover files. This cannot be undone.`
            : `This will permanently delete ${checkedLeftovers.size} leftover files and registry entries. This cannot be undone.`
        }
        safetyTier="Red"
        onConfirm={() => {
          if (confirmAction === "uninstall") handleUninstall();
          else if (confirmAction === "clean") handleClean();
          setConfirmAction(null);
        }}
        onCancel={() => setConfirmAction(null)}
      />
    </div>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="detail-row">
      <span className="detail-label">{label}</span>
      <span className="detail-value">{value}</span>
    </div>
  );
}
