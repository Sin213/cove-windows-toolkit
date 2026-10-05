// Frontend half of the local driver-update IPC contract (Tab 2a-13b).
//
// Pure module: no DOM, no Tauri. It owns the known-status list, the runtime
// response validator (the IPC trust boundary) and the UI-owned copy. Security
// decisions (ranking, signatures, freshness, session expiry) stay in the Rust
// backend; this file only validates shapes and words the outcomes.

/** Every status the three backend commands can return (snake_case). */
export const DRIVER_UPDATE_STATUSES = [
  "ready",
  "no_update",
  "ambiguous_local_update",
  "invalid_request",
  "invalid_sdio_root",
  "invalid_index_corpus",
  "inventory_unavailable",
  "degraded_inventory",
  "device_not_found",
  "unsupported_host",
  "busy",
  "session_expired",
  "session_not_found",
  "session_capacity",
  "cancelled",
  "stale_preview",
  "restore_point_failed",
  "restore_ack_not_allowed",
  "elevation_required",
  "mutation_disabled_in_test_build",
  "installed",
  "installed_pending_reboot",
  "installed_postcondition_mismatch",
  "installed_reconciliation_failed",
  "installed_source_invalidated",
  "driver_store_staged_install_refused",
  "driver_store_staged_device_install_failed",
  "driver_store_staged_source_invalidated",
  "stage_failed_unknown",
  "temporary_cleanup_failed",
  "internal_error",
] as const;

export type DriverUpdateStatus = (typeof DRIVER_UPDATE_STATUSES)[number];

export const BETTER_BY = ["no_current_driver", "rank", "date", "version"] as const;
export type BetterBy = (typeof BETTER_BY)[number];

export type RestoreAction = "create" | "skip" | "acknowledge_unavailable";

export interface PreviewView {
  provider: string | null;
  signer: string | null;
  pack_name: string;
  inf_name: string;
  candidate_version: string | null;
  candidate_date: string | null;
  candidate_rank: number;
  current_rank: number | null;
  better_by: BetterBy;
  package_file_count: number;
  package_total_bytes: number;
}

export interface Diagnostics {
  catalogs: number;
  host_compatible_candidates: number;
  missing_packs: number;
  unsupported_candidates: number;
  rejected_candidates: number;
  failed_candidates: number;
  no_action_candidates: number;
  ready_candidates: number;
}

export interface DriverUpdateResponse {
  success: boolean;
  partial: boolean;
  status: DriverUpdateStatus;
  message: string;
  detail: string | null;
  session_id: string | null;
  retry_session_id: string | null;
  expires_in_seconds: number | null;
  preview: PreviewView | null;
  diagnostics: Diagnostics | null;
  published_inf: string | null;
  reboot_required: boolean | null;
  native_error: number | null;
  postcondition_observed: boolean | null;
  cleanup_warning: boolean;
}

// ---------------------------------------------------------------------------
// Runtime validation (fail closed)
// ---------------------------------------------------------------------------

const isRecord = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === "object" && !Array.isArray(v);
const isUint = (v: unknown): v is number =>
  typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
const isString = (v: unknown): v is string => typeof v === "string";
const isBool = (v: unknown): v is boolean => typeof v === "boolean";
const nullOr = (v: unknown, ok: (x: unknown) => boolean): boolean =>
  v === null || ok(v);

const DIAGNOSTIC_FIELDS = [
  "catalogs",
  "host_compatible_candidates",
  "missing_packs",
  "unsupported_candidates",
  "rejected_candidates",
  "failed_candidates",
  "no_action_candidates",
  "ready_candidates",
] as const;

function isPreviewView(v: unknown): v is PreviewView {
  if (!isRecord(v)) return false;
  return (
    nullOr(v.provider, isString) &&
    nullOr(v.signer, isString) &&
    isString(v.pack_name) &&
    isString(v.inf_name) &&
    nullOr(v.candidate_version, isString) &&
    nullOr(v.candidate_date, isString) &&
    isUint(v.candidate_rank) &&
    nullOr(v.current_rank, isUint) &&
    (BETTER_BY as readonly unknown[]).includes(v.better_by) &&
    isUint(v.package_file_count) &&
    isUint(v.package_total_bytes)
  );
}

function isDiagnostics(v: unknown): v is Diagnostics {
  return isRecord(v) && DIAGNOSTIC_FIELDS.every((f) => isUint(v[f]));
}

/**
 * Trust boundary for all three commands. Every field must be present (the
 * backend always serializes nulls) with the right type, and the status must be
 * one this build knows; an unknown future status is never treated as success.
 */
export function isDriverUpdateResponse(value: unknown): value is DriverUpdateResponse {
  if (!isRecord(value)) return false;
  const v = value;
  return (
    isBool(v.success) &&
    isBool(v.partial) &&
    (DRIVER_UPDATE_STATUSES as readonly unknown[]).includes(v.status) &&
    isString(v.message) &&
    nullOr(v.detail, isString) &&
    nullOr(v.session_id, isString) &&
    nullOr(v.retry_session_id, isString) &&
    nullOr(v.expires_in_seconds, isUint) &&
    nullOr(v.preview, isPreviewView) &&
    nullOr(v.diagnostics, isDiagnostics) &&
    nullOr(v.published_inf, isString) &&
    nullOr(v.reboot_required, isBool) &&
    nullOr(v.native_error, isUint) &&
    nullOr(v.postcondition_observed, isBool) &&
    isBool(v.cleanup_warning)
  );
}

// ---------------------------------------------------------------------------
// Result view model (never carries session tokens, paths or backend message)
// ---------------------------------------------------------------------------

export type ResultView =
  | {
      kind: "status";
      status: DriverUpdateStatus;
      detail: string | null;
      publishedInf: string | null;
      rebootRequired: boolean;
      nativeError: number | null;
      postconditionObserved: boolean | null;
      cleanupWarning: boolean;
    }
  | { kind: "malformed" }
  | { kind: "transport"; during: "check" | "install" };

// ---------------------------------------------------------------------------
// UI-owned copy
// ---------------------------------------------------------------------------

export type Tone = "success" | "info" | "warning" | "error";

export interface StatusCopy {
  tone: Tone;
  title: string;
  body: string;
  /** Windows may have changed: refresh the read-only inventory afterwards. */
  mutated: boolean;
}

const copy = (tone: Tone, title: string, body: string, mutated = false): StatusCopy => ({
  tone,
  title,
  body,
  mutated,
});

/** Record over the status union: adding a backend status breaks the build here. */
export const UPDATE_STATUS_COPY: Record<DriverUpdateStatus, StatusCopy> = {
  ready: copy("info", "Update preview ready", "A better local driver package was found. Review it before installing."),
  no_update: copy("info", "No update found", "No better compatible local driver was found."),
  ambiguous_local_update: copy(
    "warning",
    "More than one best match",
    "More than one local driver tied as the best match. Cove did not choose one automatically.",
  ),
  invalid_request: copy("error", "Invalid request", "The request was not valid. Check the device and folder, then try again."),
  invalid_sdio_root: copy(
    "error",
    "SDIO folder not valid",
    "The selected folder is not a valid local SDIO layout. Cove expects an indexes\\SDI folder and a drivers folder inside it.",
  ),
  invalid_index_corpus: copy("error", "SDIO index not usable", "The SDIO index set could not be safely loaded."),
  inventory_unavailable: copy(
    "error",
    "Driver inventory unavailable",
    "Cove could not read the current driver inventory. Rescan and try again.",
  ),
  degraded_inventory: copy(
    "warning",
    "Inventory is degraded",
    "This host only produced a degraded driver inventory, so local update checks are unavailable.",
  ),
  device_not_found: copy("warning", "Device not found", "The device is no longer present. Rescan the inventory and try again."),
  unsupported_host: copy("warning", "Host not supported", "Local driver updates are not supported on this Windows host."),
  busy: copy("warning", "Another driver operation is running", "Wait for it to finish, then try again."),
  session_expired: copy("warning", "Preview expired", "The preview expired before it was used. Check Local Update again."),
  session_not_found: copy("warning", "Preview no longer valid", "This preview is no longer available. Check Local Update again."),
  session_capacity: copy(
    "warning",
    "Too many open previews",
    "Too many update previews are already open. Cancel an existing preview and try again.",
  ),
  cancelled: copy("info", "Preview cancelled", "The preview was cancelled and nothing was changed."),
  stale_preview: copy(
    "warning",
    "Preview out of date",
    "The device or the local package changed since the preview, so Cove did not install it. Check Local Update again.",
  ),
  restore_point_failed: copy(
    "error",
    "Restore point failed",
    "The restore point could not be created, so the driver was not installed.",
  ),
  restore_ack_not_allowed: copy(
    "warning",
    "Restore choice not allowed",
    "That restore point choice is not allowed for this preview. Check Local Update again.",
  ),
  elevation_required: copy(
    "error",
    "Administrator required",
    "Cove must be running as Administrator to install this driver.",
  ),
  mutation_disabled_in_test_build: copy(
    "warning",
    "Installation disabled",
    "Driver installation is disabled in this test build.",
  ),
  installed: copy("success", "Driver installed", "Windows installed the driver update for this device.", true),
  installed_pending_reboot: copy(
    "success",
    "Driver installed, restart required",
    "Windows accepted the driver update. A restart is required before Cove can verify the new driver as active.",
    true,
  ),
  installed_postcondition_mismatch: copy(
    "warning",
    "Install result uncertain",
    "Windows reported the install succeeded, but Cove did not observe the expected driver afterward. Do not automatically retry. Rescan the device first.",
    true,
  ),
  installed_reconciliation_failed: copy(
    "warning",
    "Installed, not verified",
    "The install completed, but Cove could not verify the final driver state. Rescan the device to check.",
    true,
  ),
  installed_source_invalidated: copy(
    "warning",
    "Source changed during verification",
    "The driver install completed or may already be complete, but the local source changed during final verification. Rescan before taking any further action.",
    true,
  ),
  driver_store_staged_install_refused: copy(
    "warning",
    "Staged, not applied",
    "The driver package was added to the Windows Driver Store, but Cove refused to apply it to the device because the final safety checks no longer passed. Do not retry automatically.",
    true,
  ),
  driver_store_staged_device_install_failed: copy(
    "warning",
    "Staged, device not updated",
    "The package was added to the Driver Store, but Windows did not complete the device update.",
    true,
  ),
  driver_store_staged_source_invalidated: copy(
    "warning",
    "Staged, source changed",
    "The package was staged, but the local source changed before device installation. The device was not intentionally updated by Cove after that check.",
    true,
  ),
  stage_failed_unknown: copy(
    "warning",
    "Staging failed, state unknown",
    "Driver Store staging failed and Windows may have partially changed Driver Store state. Do not automatically retry. Rescan before further action.",
    true,
  ),
  temporary_cleanup_failed: copy(
    "error",
    "Cleanup failed",
    "Cove could not safely remove its temporary driver files. No clean update result was produced.",
  ),
  internal_error: copy("error", "Update check failed", "Something went wrong inside Cove. Rescan and try again."),
};

export const RESULT_NOTICE_COPY = {
  malformed: "The driver update command returned an unexpected response.",
  transportCheck: "The driver check could not run. Try again.",
  transportInstall:
    "The result could not be determined. Check again before trying another update.",
  busyRetry: "Another driver operation is running. Try again shortly.",
  rebootRequired: "Restart Windows to finish applying the driver.",
  cleanupWarning: "Cove could not remove all temporary driver files.",
} as const;

const BETTER_BY_COPY: Record<BetterBy, string> = {
  no_current_driver: "No current compatible driver was found.",
  rank: "Windows ranks this package better.",
  date: "Rank is equal, but this driver is newer.",
  version: "Rank and date are equal, but this version is newer.",
};

export const describeBetterBy = (b: BetterBy): string => BETTER_BY_COPY[b];

export const formatRank = (rank: number): string =>
  `0x${rank.toString(16).toUpperCase().padStart(8, "0")}`;

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(1)} ${units[unit]}`;
}

/** `oemNN.inf` leaf only: never show a directory. */
export const publishedLeaf = (inf: string): string => inf.split(/[\\/]/).pop() ?? inf;

/** Pending reboot already carries its own restart wording in the body. */
export function showRebootNotice(result: ResultView): boolean {
  return (
    result.kind === "status" &&
    result.rebootRequired &&
    result.status !== "installed_pending_reboot"
  );
}
