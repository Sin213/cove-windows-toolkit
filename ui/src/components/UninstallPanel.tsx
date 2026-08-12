import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import ConfirmDialog from "./ConfirmDialog";
import "./UninstallPanel.css";

interface InstalledProgram {
  id: string;
  name: string;
  publisher: string;
  version: string;
  install_date: string;
  size_bytes: number;
  install_location: string;
  registry_key: string;
  is_system: boolean;
  can_uninstall: boolean;
  uninstall_reason: string;
}

interface Leftover {
  path: string;
  category: string;
  size_bytes: number;
}

interface ScanResult {
  success: boolean;
  message?: string;
  scan_id: string;
  leftovers: Leftover[];
  total_size_bytes: number;
}

interface ProgramInventory {
  success: boolean;
  message: string;
  programs: InstalledProgram[];
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
type Step = "list" | "uninstalling" | "scanning" | "leftovers";

export default function UninstallPanel() {
  const [programs, setPrograms] = useState<InstalledProgram[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [showSystem, setShowSystem] = useState(false);
  const [selected, setSelected] = useState<InstalledProgram | null>(null);
  const [step, setStep] = useState<Step>("list");
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [uninstallCompleted, setUninstallCompleted] = useState(false);
  const [confirmAction, setConfirmAction] = useState(false);

  useEffect(() => {
    invoke<ProgramInventory>("get_installed_programs")
      .then((result) => {
        if (!result.success || !Array.isArray(result.programs)) {
          throw new Error(result.message || "The installed-program inventory failed.");
        }
        setPrograms(result.programs);
      })
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
    setUninstallCompleted(false);
  };

  const handleUninstall = async () => {
    if (!selected) return;
    setStep("uninstalling");
    setFeedback(null);
    try {
      const result = await invoke<{ success: boolean; message: string }>("uninstall_program", {
        programId: selected.id,
      });
      if (!result.success) {
        setFeedback(result.message || "The uninstaller failed. No cleanup was attempted.");
        setStep("list");
        return;
      }
      setUninstallCompleted(true);
      setPrograms((current) => current.filter((program) => program.id !== selected.id));
      setFeedback("Standard uninstall completed. Scanning for leftovers...");
    } catch (e) {
      setFeedback(`Uninstall error: ${e}. No cleanup was attempted.`);
      setStep("list");
      return;
    }
    await handleScan();
  };

  const handleScan = async () => {
    if (!selected) return;
    setStep("scanning");
    setFeedback(null);
    try {
      const result = await invoke<ScanResult>("scan_leftovers", {
        programId: selected.id,
      });
      if (!result.success) throw new Error(result.message || "The leftover scan failed.");
      setScan(result);
      setStep("leftovers");
    } catch (e) {
      setFeedback(`Scan error: ${e}`);
      setStep("list");
    }
  };

  const resetToList = () => {
    setSelected(null);
    setStep("list");
    setScan(null);
    setFeedback(null);
    setUninstallCompleted(false);
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
            aria-label="Search installed programs"
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
              key={p.id}
              className={`program-item ${selected?.id === p.id ? "active" : ""}`}
              onClick={() => handleSelect(p)}
              disabled={step !== "list"}
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
              <button
                className="action-btn action-primary"
                onClick={() => {
                  if (uninstallCompleted) void handleScan();
                  else setConfirmAction(true);
                }}
                disabled={!uninstallCompleted && !selected.can_uninstall}
                title={
                  !uninstallCompleted && !selected.can_uninstall
                    ? selected.uninstall_reason
                    : undefined
                }
              >
                {uninstallCompleted ? "Retry Location Scan" : "Uninstall + Review Location"}
              </button>
            </div>
            {feedback && (
              <div className="progress-feedback" role="alert">
                {feedback}
              </div>
            )}
            {!uninstallCompleted && !selected.can_uninstall && (
              <div className="progress-feedback" role="status">
                This entry cannot be uninstalled by Cove: {selected.uninstall_reason || "Only trusted machine-wide MSI entries are supported."}
              </div>
            )}
          </div>
        )}

        {(step === "uninstalling" || step === "scanning") && (
          <div className="progress-state">
            <div className="progress-spinner" />
            <p>{step === "uninstalling" ? "Running uninstaller..." : "Scanning for leftover application folders..."}</p>
            {feedback && <div className="progress-feedback">{feedback}</div>}
          </div>
        )}

        {step === "leftovers" && scan && (
          <div className="leftovers-view">
            <div className="leftovers-header">
              <h3>Registered Location Review</h3>
              <span className="leftover-summary">
                {scan.leftovers.length} items - {fmtBytes(scan.total_size_bytes)}
              </span>
            </div>
            {feedback && <div className="progress-feedback">{feedback}</div>}
            {scan.leftovers.length === 0 ? (
              <div className="no-leftovers">
                <p>No dedicated registered install folder remains.</p>
                <button className="action-btn action-secondary" onClick={resetToList}>Back to list</button>
              </div>
            ) : (
              <>
                <div className="progress-feedback" role="status">
                  Automatic deletion is disabled because Windows cannot reliably prove that a registered folder is exclusively owned by one program. Review this location and remove it manually only if you recognize it.
                </div>
                <div className="leftovers-list">
                  {scan.leftovers.map((l) => (
                    <div key={l.path} className="leftover-item">
                      <span className={`leftover-cat cat-${l.category.toLowerCase().replace(/\s/g, '-')}`}>
                        {l.category}
                      </span>
                      <span className="leftover-path">{l.path}</span>
                      {l.size_bytes > 0 && <span className="leftover-size">{fmtBytes(l.size_bytes)}</span>}
                    </div>
                  ))}
                </div>
                <div className="leftovers-actions">
                  <button className="action-btn action-secondary" onClick={handleScan}>Rescan</button>
                  <button className="action-btn action-secondary" onClick={resetToList}>Back to list</button>
                </div>
              </>
            )}
          </div>
        )}

      </div>
      <ConfirmDialog
        open={confirmAction}
        title={`Uninstall ${selected?.name ?? ""}`}
        message={`This will uninstall ${selected?.name ?? ""} and review its registered install location. The uninstall cannot be undone.`}
        safetyTier="Red"
        onConfirm={() => {
          handleUninstall();
          setConfirmAction(false);
        }}
        onCancel={() => setConfirmAction(false)}
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
