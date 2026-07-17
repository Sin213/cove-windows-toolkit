import { useEffect, useId, useRef } from "react";
import "./ConfirmDialog.css";

interface Props {
  open: boolean;
  title: string;
  message: string;
  safetyTier: "Yellow" | "Red";
  onConfirm: () => void;
  onCancel: () => void;
}

export default function ConfirmDialog({
  open,
  title,
  message,
  safetyTier,
  onConfirm,
  onCancel,
}: Props) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const messageId = useId();

  useEffect(() => {
    if (!open) return;
    const previouslyFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const dialog = dialogRef.current;
    const focusable = () => Array.from(dialog?.querySelectorAll<HTMLElement>(
      'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
    ) ?? []);
    focusable()[0]?.focus();

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onCancel();
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
  }, [open, onCancel]);

  if (!open) return null;

  const tier = safetyTier.toLowerCase();

  return (
    <div className="confirm-overlay" onClick={onCancel} role="presentation">
      <div
        ref={dialogRef}
        className={`confirm-dialog tier-${tier}`}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={messageId}
        tabIndex={-1}
      >
        <span className={`confirm-tier-badge tier-${tier}`}>
          {safetyTier === "Red" ? "Destructive" : "Caution"}
        </span>
        <div className="confirm-title" id={titleId}>{title}</div>
        <div className="confirm-message" id={messageId}>{message}</div>
        <div className="confirm-actions">
          <button className="confirm-cancel-btn" onClick={onCancel}>
            Cancel
          </button>
          <button
            className={`confirm-proceed-btn tier-${tier}`}
            onClick={onConfirm}
          >
            {safetyTier === "Red" ? "Proceed Anyway" : "Continue"}
          </button>
        </div>
      </div>
    </div>
  );
}
