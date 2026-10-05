import ConfirmDialog from "./ConfirmDialog";
import {
  RESULT_NOTICE_COPY,
  UPDATE_STATUS_COPY,
  describeBetterBy,
  formatBytes,
  formatRank,
  showRebootNotice,
  type PreviewView,
  type ResultView,
} from "../lib/driverUpdate";
import type { DriverUpdateFlow, FlowState } from "../lib/driverUpdateFlow";

interface Props {
  state: FlowState;
  flow: DriverUpdateFlow;
  deviceName: string;
}

function expiryText(seconds: number | null): string | null {
  if (seconds === null) return null;
  if (seconds < 60) return "This preview expires in less than a minute.";
  return `This preview expires in about ${Math.round(seconds / 60)} minutes.`;
}

function PreviewCard({
  preview,
  expiresInSeconds,
}: {
  preview: PreviewView;
  expiresInSeconds: number | null;
}) {
  const expiry = expiryText(expiresInSeconds);
  return (
    <dl className="drivers-update-facts">
      <dt>Provider</dt>
      <dd>{preview.provider ?? "Not stated"}</dd>
      <dt>Signer</dt>
      <dd>{preview.signer ?? "Not reported"}</dd>
      <dt>Driver pack</dt>
      <dd className="mono">{preview.pack_name}</dd>
      <dt>INF</dt>
      <dd className="mono">{preview.inf_name}</dd>
      <dt>Version</dt>
      <dd>{preview.candidate_version ?? "Not stated"}</dd>
      <dt>Date</dt>
      <dd>{preview.candidate_date ?? "Not stated"}</dd>
      <dt>Rank</dt>
      <dd>
        <span className="mono">
          Candidate rank: {formatRank(preview.candidate_rank)}
        </span>
        <br />
        <span className="mono">
          Current rank:{" "}
          {preview.current_rank === null
            ? "none"
            : formatRank(preview.current_rank)}
        </span>
        <br />
        <span className="dim">Lower Windows rank is better.</span>
      </dd>
      <dt>Why it is better</dt>
      <dd>{describeBetterBy(preview.better_by)}</dd>
      <dt>Package</dt>
      <dd>
        {preview.package_file_count} files,{" "}
        {formatBytes(preview.package_total_bytes)}
      </dd>
      {expiry && (
        <>
          <dt>Expiry</dt>
          <dd className="dim">{expiry}</dd>
        </>
      )}
    </dl>
  );
}

function ResultCard({
  result,
  onDismiss,
}: {
  result: ResultView;
  onDismiss: () => void;
}) {
  if (result.kind !== "status") {
    const text =
      result.kind === "malformed"
        ? RESULT_NOTICE_COPY.malformed
        : result.during === "check"
          ? RESULT_NOTICE_COPY.transportCheck
          : RESULT_NOTICE_COPY.transportInstall;
    return (
      <div className="drivers-update-card tone-error" role="alert">
        <p className="drivers-update-body">{text}</p>
        <button type="button" className="drivers-update-btn" onClick={onDismiss}>
          Dismiss
        </button>
      </div>
    );
  }

  const copy = UPDATE_STATUS_COPY[result.status];
  const calm = copy.tone === "success" || copy.tone === "info";
  return (
    <>
      <div
        className={`drivers-update-card tone-${copy.tone}`}
        role={calm ? "status" : "alert"}
      >
        <p className="drivers-update-title">{copy.title}</p>
        <p className="drivers-update-body">{copy.body}</p>
        {showRebootNotice(result) && (
          <p className="drivers-update-reboot">
            {RESULT_NOTICE_COPY.rebootRequired}
          </p>
        )}
        {result.publishedInf && (
          <p className="drivers-update-meta">
            Published as <span className="mono">{result.publishedInf}</span>
          </p>
        )}
        {result.postconditionObserved !== null && (
          <p className="drivers-update-meta">
            Expected driver observed: {result.postconditionObserved ? "Yes" : "No"}
          </p>
        )}
        {result.detail && (
          <p className="drivers-update-meta">
            Detail: <span className="mono">{result.detail}</span>
          </p>
        )}
        {result.nativeError !== null && (
          <p className="drivers-update-meta">
            Windows error: {result.nativeError}
          </p>
        )}
        <button type="button" className="drivers-update-btn" onClick={onDismiss}>
          Dismiss
        </button>
      </div>
      {result.cleanupWarning && (
        <div className="drivers-update-card tone-warning" role="alert">
          <p className="drivers-update-body">
            {RESULT_NOTICE_COPY.cleanupWarning}
          </p>
        </div>
      )}
    </>
  );
}

/**
 * Presentation for the driver-update workflow. Holds no authority: it renders
 * the flow's state and forwards explicit user choices. The session token never
 * reaches this component.
 */
export default function DriverUpdateSection({ state, flow, deviceName }: Props) {
  const held =
    state.phase === "ready" ||
    state.phase === "confirm_create" ||
    state.phase === "confirm_skip" ||
    state.phase === "installing" ||
    state.phase === "confirm_ack_unavailable";
  const expires =
    state.phase === "ready" ||
    state.phase === "confirm_create" ||
    state.phase === "confirm_skip"
      ? state.expiresInSeconds
      : null;

  return (
    <>
      {state.phase === "checking" && (
        <div className="drivers-update-card tone-info" role="status">
          <p className="drivers-update-body">Checking local driver packs...</p>
        </div>
      )}

      {held && (
        <div className="drivers-update-card tone-info">
          <p className="drivers-update-title">
            Local driver update preview for {deviceName}
          </p>
          <PreviewCard preview={state.preview} expiresInSeconds={expires} />
          {state.phase === "ready" && state.notice === "busy" && (
            <p className="drivers-update-body" role="status">
              {RESULT_NOTICE_COPY.busyRetry}
            </p>
          )}
          {state.phase === "installing" ? (
            <p className="drivers-update-body" role="status">
              Re-checking package and installing driver...
            </p>
          ) : (
            <div className="drivers-update-actions">
              <button
                type="button"
                className="drivers-update-btn primary"
                disabled={state.phase !== "ready"}
                onClick={() => flow.chooseInstall("create")}
              >
                Create restore point and install
              </button>
              <button
                type="button"
                className="drivers-update-btn caution"
                disabled={state.phase !== "ready"}
                onClick={() => flow.chooseInstall("skip")}
              >
                Install without restore point
              </button>
              <button
                type="button"
                className="drivers-update-btn"
                disabled={state.phase !== "ready"}
                onClick={flow.cancelPreview}
              >
                Cancel Preview
              </button>
            </div>
          )}
        </div>
      )}

      {state.phase === "result" && (
        <ResultCard result={state.result} onDismiss={flow.dismissResult} />
      )}

      <ConfirmDialog
        open={state.phase === "confirm_create"}
        title="Install driver update"
        message="Cove will create a System Restore point, re-check the local package, then update only this exact device if the package is still the unique better match."
        safetyTier="Yellow"
        onConfirm={flow.confirmInstall}
        onCancel={flow.declineInstall}
      />
      <ConfirmDialog
        open={state.phase === "confirm_skip"}
        title="Install without a restore point"
        message="No restore point will be created. Cove will still revalidate the package and device before installation, but automatic rollback is not available."
        safetyTier="Red"
        onConfirm={flow.confirmInstall}
        onCancel={flow.declineInstall}
      />
      <ConfirmDialog
        open={state.phase === "confirm_ack_unavailable"}
        title="Restore point could not be created"
        message="Continue without a restore point? The driver has NOT been staged or installed yet. Continuing will explicitly acknowledge that System Restore is unavailable."
        safetyTier="Red"
        onConfirm={flow.confirmAcknowledge}
        onCancel={flow.declineAcknowledge}
      />
    </>
  );
}
