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
  if (!open) return null;

  const tier = safetyTier.toLowerCase();

  return (
    <div className="confirm-overlay" onClick={onCancel}>
      <div
        className={`confirm-dialog tier-${tier}`}
        onClick={(e) => e.stopPropagation()}
      >
        <span className={`confirm-tier-badge tier-${tier}`}>
          {safetyTier === "Red" ? "Destructive" : "Caution"}
        </span>
        <div className="confirm-title">{title}</div>
        <div className="confirm-message">{message}</div>
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
