import { useEffect, useState } from "react";
import { invoke } from "../lib/tauri";
import ConfirmDialog from "./ConfirmDialog";
import "./DiskHealthPanel.css";

interface DriveHealth {
  model: string;
  serial: string;
  interface_type: string;
  media_type: string;
  size_bytes: number | null;
  status: string;
  temperature_c: number | null;
  wear_percent: number | null;
  read_errors: number | null;
  write_errors: number | null;
  power_on_hours: number | null;
  trim_enabled: boolean;
  trim_known: boolean;
  health_rating: string;
}

interface DriveHealthReport {
  complete: boolean;
  errors: string[];
  drives: DriveHealth[];
}

interface LargeFile {
  path: string;
  name: string;
  extension: string;
  size_bytes: number;
}

interface DiskSpaceReport {
  drive: string;
  complete: boolean;
  errors: string[];
  total_bytes: number | null;
  free_bytes: number | null;
  largest_files: LargeFile[];
}

interface ChkdskResult {
  success: boolean;
  mode: string;
  scheduled_reboot: boolean;
  message: string;
  output: string;
}

interface LastChkdskInfo {
  complete: boolean;
  error: string | null;
  found: boolean;
  timestamp: string | null;
  result_text: string | null;
  dirty_bit: boolean;
  dirty_bit_known: boolean;
}

const RATING_ICON: Record<string, string> = {
  Good: "✔",
  Warning: "⚠",
  Critical: "✖",
};

const RATING_CLASS: Record<string, string> = {
  Good: "rating-good",
  Warning: "rating-warn",
  Critical: "rating-crit",
};

function formatBytes(bytes: number | null): string {
  if (bytes === null) return "Unknown";
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}

export default function DiskHealthPanel() {
  const [driveReport, setDriveReport] = useState<DriveHealthReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [spaceData, setSpaceData] = useState<DiskSpaceReport | null>(null);
  const [spaceLoading, setSpaceLoading] = useState(false);

  const [lastChkdsk, setLastChkdsk] = useState<LastChkdskInfo | null>(null);
  const [chkdskRunning, setChkdskRunning] = useState<string | null>(null);
  const [chkdskResult, setChkdskResult] = useState<ChkdskResult | null>(null);
  const [chkdskError, setChkdskError] = useState<string | null>(null);

  const [pendingConfirm, setPendingConfirm] = useState<{
    mode: string;
    tier: "Yellow" | "Red";
    title: string;
    message: string;
  } | null>(null);

  useEffect(() => {
    Promise.all([
      invoke<DriveHealthReport>("get_disk_health"),
      invoke<LastChkdskInfo>("get_last_chkdsk"),
    ])
      .then(([d, c]) => {
        setDriveReport(d);
        setLastChkdsk(c);
      })
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const loadDiskSpace = async (drive: string) => {
    setSpaceLoading(true);
    try {
      const data = await invoke<DiskSpaceReport>("get_disk_space", { drive });
      setSpaceData(data);
    } catch (e) {
      console.error("Failed to load disk space:", e);
    } finally {
      setSpaceLoading(false);
    }
  };

  const handleChkdsk = (mode: string) => {
    if (mode === "scan") {
      runChkdsk(mode);
    } else if (mode === "f") {
      setPendingConfirm({
        mode: "f",
        tier: "Yellow",
        title: "Schedule chkdsk /f",
        message:
          "This will schedule a filesystem error check on next reboot. The system volume cannot be checked while Windows is running -a reboot is required. Continue?",
      });
    }
  };

  const runChkdsk = async (mode: string) => {
    setChkdskRunning(mode);
    setChkdskResult(null);
    setChkdskError(null);
    try {
      const result = await invoke<ChkdskResult>("run_chkdsk", {
        mode,
        drive: "",
      });
      setChkdskResult(result);
    } catch (e) {
      console.error("chkdsk failed:", e);
      setChkdskError(String(e));
    } finally {
      setChkdskRunning(null);
    }
  };

  if (loading)
    return <div className="panel-loading">Reading disk health...</div>;
  if (error) return <div className="panel-error">Error: {error}</div>;
  if (!driveReport) return <div className="panel-error">Disk-health query returned no result.</div>;

  const drives = driveReport.drives;

  return (
    <div className="diskhealth-panel">
      {!driveReport.complete && (
        <div className="panel-error">
          Disk inventory is incomplete: {driveReport.errors.join("; ") || "query failed"}
        </div>
      )}
      {/* SMART / Drive Health Cards */}
      <div className="drive-cards">
        {drives.map((d, i) => (
          <div key={`${d.serial || d.model}-${i}`} className="drive-card">
            <div className="drive-card-header">
              <div className="drive-model">{d.model}</div>
              <span
                className={`drive-rating ${RATING_CLASS[d.health_rating] || ""}`}
              >
                {RATING_ICON[d.health_rating] || "?"} {d.health_rating}
              </span>
            </div>
            <div className="drive-meta">
              <span>{d.media_type}</span>
              <span>{d.interface_type}</span>
              <span>{formatBytes(d.size_bytes)}</span>
            </div>
            <div className="drive-stats">
              {d.temperature_c !== null && (
                <div className="drive-stat">
                  <span className="stat-label">Temp</span>
                  <span
                    className={`stat-value ${d.temperature_c >= 70 ? "stat-warn" : ""}`}
                  >
                    {d.temperature_c} C
                  </span>
                </div>
              )}
              {d.wear_percent !== null && (
                <div className="drive-stat">
                  <span className="stat-label">Wear</span>
                  <span
                    className={`stat-value ${d.wear_percent >= 70 ? "stat-warn" : ""}`}
                  >
                    {d.wear_percent}%
                  </span>
                </div>
              )}
              {d.power_on_hours !== null && (
                <div className="drive-stat">
                  <span className="stat-label">Power-On</span>
                  <span className="stat-value">
                    {Math.round(d.power_on_hours / 24)}d
                  </span>
                </div>
              )}
              {d.read_errors !== null && (
                <div className="drive-stat">
                  <span className="stat-label">Read Err</span>
                  <span
                    className={`stat-value ${(d.read_errors ?? 0) > 0 ? "stat-warn" : ""}`}
                  >
                    {d.read_errors}
                  </span>
                </div>
              )}
              {d.write_errors !== null && (
                <div className="drive-stat">
                  <span className="stat-label">Write Err</span>
                  <span
                    className={`stat-value ${(d.write_errors ?? 0) > 0 ? "stat-warn" : ""}`}
                  >
                    {d.write_errors}
                  </span>
                </div>
              )}
              {(d.media_type.includes("SSD") ||
                d.interface_type.includes("NVMe")) && (
                <div className="drive-stat">
                  <span className="stat-label">TRIM</span>
                  <span
                    className={`stat-value ${d.trim_known && !d.trim_enabled ? "stat-warn" : ""}`}
                  >
                    {d.trim_known ? (d.trim_enabled ? "On" : "Off") : "Unknown"}
                  </span>
                </div>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Largest Files */}
      <div className="space-section">
        <div className="space-header">
          <h3>Largest Files</h3>
          <button
            className="scan-btn"
            onClick={() => loadDiskSpace("")}
            disabled={spaceLoading}
          >
            {spaceLoading ? "Scanning..." : "Scan User Files"}
          </button>
        </div>

        {spaceData && (
          <div className="space-content">
            {!spaceData.complete && (
              <div className="panel-error">
                File scan is incomplete: {spaceData.errors.join("; ") || "query failed"}
              </div>
            )}
            {spaceData.total_bytes !== null && spaceData.free_bytes !== null && (
            <div className="space-bar-container">
              <div className="space-bar-bg">
                <div
                  className="space-bar-used"
                  style={{
                    width: `${spaceData.total_bytes > 0 ? ((spaceData.total_bytes - spaceData.free_bytes) / spaceData.total_bytes) * 100 : 0}%`,
                  }}
                />
              </div>
              <div className="space-bar-labels">
                <span>
                  Used:{" "}
                  {formatBytes(spaceData.total_bytes - spaceData.free_bytes)}
                </span>
                <span>Free: {formatBytes(spaceData.free_bytes)}</span>
                <span>Total: {formatBytes(spaceData.total_bytes)}</span>
              </div>
            </div>
            )}

            <div className="file-list">
              {spaceData.largest_files.map((f, i) => (
                <div key={f.path} className="file-row">
                  <span className="file-rank">#{i + 1}</span>
                  <div className="file-info">
                    <div className="file-name-row">
                      <span className="file-name">{f.name}</span>
                      <span className="file-ext">{f.extension}</span>
                    </div>
                    <div className="file-path">{f.path}</div>
                  </div>
                  <span className="file-size">{formatBytes(f.size_bytes)}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* chkdsk Section */}
      <div className="chkdsk-section">
        <h3>Disk Check (chkdsk)</h3>

        {/* Last chkdsk info */}
        {lastChkdsk && (
          <div className="last-chkdsk">
            {!lastChkdsk.complete && <div className="dirty-bit-warn">Disk-check history is incomplete: {lastChkdsk.error || "query failed"}</div>}
            {!lastChkdsk.dirty_bit_known && <div className="dirty-bit-warn">Volume dirty-bit status is unknown.</div>}
            {lastChkdsk.dirty_bit && (
              <div className="dirty-bit-warn">
                <span>{"⚠"}</span> Volume dirty bit is set -a chkdsk may
                run automatically on next boot.
              </div>
            )}
            {lastChkdsk.found ? (
              <div className="last-chkdsk-info">
                <span className="last-label">Last chkdsk:</span>
                <span>
                  {lastChkdsk.timestamp
                    ? new Date(lastChkdsk.timestamp).toLocaleString()
                    : "Unknown"}
                </span>
                {lastChkdsk.result_text && (
                  <div className="last-result-text">
                    {lastChkdsk.result_text.slice(0, 200)}
                    {(lastChkdsk.result_text?.length ?? 0) > 200 ? "..." : ""}
                  </div>
                )}
              </div>
            ) : (
              <div className="no-chkdsk">
                No previous chkdsk result found in Event Log.
              </div>
            )}
          </div>
        )}

        {/* chkdsk buttons */}
        <div className="chkdsk-actions">
          <button
            className="scan-btn primary"
            onClick={() => handleChkdsk("scan")}
            disabled={!!chkdskRunning}
          >
            {chkdskRunning === "scan" ? "Scanning..." : "chkdsk /scan"}
          </button>
          <button
            className="scan-btn chkdsk-yellow"
            onClick={() => handleChkdsk("f")}
            disabled={!!chkdskRunning}
          >
            {chkdskRunning === "f" ? "Scheduling..." : "chkdsk /f"}
          </button>
        </div>
        <div className="chkdsk-hint">
          <span>
            <strong>/scan</strong> -online read-only check (safe, immediate)
          </span>
          <span>
            <strong>/f</strong> -fix filesystem errors (requires reboot)
          </span>
        </div>

        {/* chkdsk result */}
        {chkdskResult && (
          <div
            className={`chkdsk-result ${chkdskResult.success ? "chkdsk-ok" : "chkdsk-fail"}`}
          >
            <div className="chkdsk-result-header">
              <span>
                {chkdskResult.success ? "✔" : "✖"}{" "}
                {chkdskResult.message}
              </span>
              {chkdskResult.scheduled_reboot && (
                <span className="reboot-badge">Reboot Required</span>
              )}
            </div>
            {chkdskResult.output && (
              <pre className="chkdsk-output">{chkdskResult.output}</pre>
            )}
          </div>
        )}

        {chkdskError && (
          <div className="chkdsk-result chkdsk-fail">
            <div className="chkdsk-result-header">
              <span>{"✖"} chkdsk failed to run: {chkdskError}</span>
            </div>
          </div>
        )}
      </div>

      {/* Confirm dialog for chkdsk /f and /r */}
      {pendingConfirm && (
        <ConfirmDialog
          open={true}
          title={pendingConfirm.title}
          message={pendingConfirm.message}
          safetyTier={pendingConfirm.tier}
          onConfirm={() => {
            const mode = pendingConfirm.mode;
            setPendingConfirm(null);
            runChkdsk(mode);
          }}
          onCancel={() => setPendingConfirm(null)}
        />
      )}
    </div>
  );
}
