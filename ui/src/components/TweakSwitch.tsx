import "./TweakSwitch.css";

interface TweakSwitchProps {
  /** Whether the optimized value is currently in place. */
  applied: boolean;
  /** Whether Cove holds the pre-change value needed to put it back. */
  canRevert: boolean;
  busy?: boolean;
  disabled?: boolean;
  /** Accessible name, e.g. the tweak's title. */
  label: string;
  onApply: () => void;
  onRevert: () => void;
}

/**
 * On/off control for a single tweak. Switching on applies it; switching off puts
 * the original value back from the snapshot taken at apply time.
 *
 * A tweak that is already applied but has no snapshot - because it was set
 * before Cove was installed, or by another tool - cannot be put back to a known
 * value, so the switch is locked on and says why rather than silently doing
 * nothing.
 */
export default function TweakSwitch({
  applied,
  canRevert,
  busy = false,
  disabled = false,
  label,
  onApply,
  onRevert,
}: TweakSwitchProps) {
  const lockedOn = applied && !canRevert;
  const isDisabled = disabled || busy || lockedOn;

  return (
    <div className="tweak-switch-wrap">
      <button
        type="button"
        role="switch"
        aria-checked={applied}
        aria-label={label}
        className={`tweak-switch ${applied ? "is-on" : "is-off"} ${busy ? "is-busy" : ""}`}
        disabled={isDisabled}
        title={
          lockedOn
            ? "Applied outside Cove - there is no saved original value to restore"
            : applied
              ? "Switch off to restore the original value"
              : "Switch on to apply this tweak"
        }
        onClick={() => (applied ? onRevert() : onApply())}
      >
        <span className="tweak-switch-track">
          <span className="tweak-switch-thumb" />
        </span>
      </button>
      <span className="tweak-switch-state">
        {busy ? "Working..." : applied ? "On" : "Off"}
        {lockedOn && <span className="tweak-switch-note">no saved original</span>}
      </span>
    </div>
  );
}
