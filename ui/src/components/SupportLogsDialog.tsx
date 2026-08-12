import { useCallback, useEffect, useId, useRef, useState } from "react";
import { invoke } from "../lib/tauri";
import "./SupportLogsDialog.css";

interface SupportLogReport {
  report: string;
  file_count: number;
  bytes_read: number;
  truncated: boolean;
}

interface Props {
  open: boolean;
  onClose: () => void;
}

export default function SupportLogsDialog({ open, onClose }: Props) {
  const [data, setData] = useState<SupportLogReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const dialogRef = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const descriptionId = useId();

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    setNotice(null);
    try {
      setData(await invoke<SupportLogReport>("get_support_logs"));
    } catch (refreshError) {
      setError(
        `Could not refresh the support log. Any previous snapshot is still shown. ${String(refreshError)}`,
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!open) return;
    const timer = window.setTimeout(() => void refresh(), 0);
    return () => window.clearTimeout(timer);
  }, [open, refresh]);

  useEffect(() => {
    if (!open) return;
    const previouslyFocused =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const dialog = dialogRef.current;
    const focusable = () =>
      Array.from(
        dialog?.querySelectorAll<HTMLElement>(
          'button:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
        ) ?? []
      );
    focusable()[0]?.focus();

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== "Tab") return;
      const items = focusable();
      if (items.length === 0) {
        event.preventDefault();
        dialog?.focus();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      previouslyFocused?.focus();
    };
  }, [open, onClose]);

  if (!open) return null;

  const copyDiagnostics = async () => {
    if (!data) return;
    try {
      await navigator.clipboard.writeText(data.report);
      setNotice("Support log copied. Paste it into the bug report or message.");
      setError(null);
    } catch (copyError) {
      setError(`Could not copy the support log: ${String(copyError)}`);
    }
  };

  const saveDiagnostics = () => {
    if (!data) return;
    try {
      const blob = new Blob([data.report], { type: "text/plain;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      const stamp = new Date().toISOString().replace(/[:.]/g, "-");
      anchor.href = url;
      anchor.download = `cove-support-log-${stamp}.txt`;
      anchor.click();
      setTimeout(() => URL.revokeObjectURL(url), 0);
      setNotice("A sanitized support-log copy was saved.");
      setError(null);
    } catch (saveError) {
      setError(`Could not save the support log: ${String(saveError)}`);
    }
  };

  const openFolder = async () => {
    try {
      await invoke("open_log_folder");
      setNotice("Opened the log folder in File Explorer.");
      setError(null);
    } catch (openError) {
      setError(`Could not open the log folder: ${String(openError)}`);
    }
  };

  return (
    <div className="support-logs-overlay" onClick={onClose} role="presentation">
      <div
        ref={dialogRef}
        className="support-logs-dialog"
        onClick={(event) => event.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
        tabIndex={-1}
      >
        <div className="support-logs-header">
          <div>
            <div className="support-logs-title" id={titleId}>Support logs</div>
            <div className="support-logs-subtitle" id={descriptionId}>
              Review, copy, or save diagnostics when something goes wrong.
            </div>
          </div>
          <button type="button" className="support-logs-close" onClick={onClose} aria-label="Close support logs">
            ×
          </button>
        </div>

        <div className="support-logs-meta">
          <span>{data ? `${data.file_count} log file${data.file_count === 1 ? "" : "s"}` : "Log files"}</span>
          <span>{data ? `${data.bytes_read.toLocaleString()} bytes loaded` : "Waiting for diagnostics"}</span>
          {data?.truncated && <span className="support-logs-truncated">Older entries omitted</span>}
        </div>

        <textarea
          className="support-logs-view"
          readOnly
          spellCheck={false}
          aria-label="Sanitized support log contents"
          value={
            loading && !data
              ? "Loading support logs…"
              : error && !data
                ? "Support logs could not be loaded."
                : data?.report ?? "No support-log data is available."
          }
        />

        <div className="support-logs-privacy">
          User-profile paths, URLs, and common credential fields are redacted before display,
          copy, or save. Nothing is uploaded automatically.
        </div>
        {error && <div className="support-logs-error" role="alert">{error}</div>}
        {notice && <div className="support-logs-notice" role="status">{notice}</div>}

        <div className="support-logs-actions">
          <button type="button" className="support-logs-primary" onClick={copyDiagnostics} disabled={!data || loading}>
            Copy diagnostics
          </button>
          <button type="button" onClick={saveDiagnostics} disabled={!data || loading}>Save diagnostics</button>
          <button type="button" onClick={openFolder}>Open log folder</button>
          <button type="button" onClick={() => void refresh()} disabled={loading}>Refresh</button>
          <span className="support-logs-spacer" />
          <button type="button" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}
