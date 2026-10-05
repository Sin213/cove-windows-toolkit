// Browser-development mocks for the three driver-update commands (Tab 2a-13b).
//
// Every response uses the COMPLETE backend shape. Scenario comes from the
// `?driver_update_mock=<name>` query parameter:
//   (none)         check -> ready, install -> installed (oem42.inf)
//   restore_fail   install(create) -> restore_point_failed + retry token,
//                  install(acknowledge_unavailable) -> installed
//   partial        install -> driver_store_staged_device_install_failed
//   pending_reboot install -> installed_pending_reboot
//   stale          install -> stale_preview
//   no_update | ambiguous | invalid_root | malformed   check outcomes
// Fake data only: no real paths, device IDs or tokens. Mock state is
// module-local and never persisted.

import type { DriverUpdateResponse, DriverUpdateStatus } from "./driverUpdate.ts";

const CHECK = "check_local_driver_update";
const INSTALL = "install_local_driver_update";
const CANCEL = "cancel_local_driver_update";

const SUCCESS: readonly DriverUpdateStatus[] = [
  "ready",
  "no_update",
  "cancelled",
  "installed",
  "installed_pending_reboot",
];
const PARTIAL: readonly DriverUpdateStatus[] = [
  "installed_postcondition_mismatch",
  "installed_reconciliation_failed",
  "installed_source_invalidated",
  "driver_store_staged_install_refused",
  "driver_store_staged_device_install_failed",
  "driver_store_staged_source_invalidated",
  "stage_failed_unknown",
];

let sequence = 0;
// The one token the simulated backend currently honours. `retry` marks the
// replacement token handed out after a restore-point failure: only it may
// acknowledge "no restore point". Consumed on every install, like the backend.
let held: { token: string; retry: boolean } | null = null;

export function resetDriverUpdateMock(): void {
  sequence = 0;
  held = null;
}

function full(
  status: DriverUpdateStatus,
  overrides: Partial<DriverUpdateResponse> = {},
): DriverUpdateResponse {
  return {
    success: SUCCESS.includes(status),
    partial: PARTIAL.includes(status),
    status,
    message: status,
    detail: null,
    session_id: null,
    retry_session_id: null,
    expires_in_seconds: null,
    preview: null,
    diagnostics: null,
    published_inf: null,
    reboot_required: null,
    native_error: null,
    postcondition_observed: null,
    cleanup_warning: false,
    ...overrides,
  };
}

const DIAGNOSTICS = {
  catalogs: 3,
  host_compatible_candidates: 2,
  missing_packs: 0,
  unsupported_candidates: 0,
  rejected_candidates: 0,
  failed_candidates: 0,
  no_action_candidates: 1,
  ready_candidates: 1,
};

function mockCheck(scenario: string | null): unknown {
  switch (scenario) {
    case "malformed":
      return { success: true };
    case "no_update":
      return full("no_update", { diagnostics: DIAGNOSTICS });
    case "ambiguous":
      return full("ambiguous_local_update", { diagnostics: DIAGNOSTICS });
    case "invalid_root":
      return full("invalid_sdio_root", { detail: "missing_index_directory" });
    default:
      sequence += 1;
      held = { token: `mock-session-${sequence}`, retry: false };
      return full("ready", {
        session_id: held.token,
        expires_in_seconds: 600,
        diagnostics: DIAGNOSTICS,
        preview: {
          provider: "Fake Provider Inc.",
          signer: "Fake Signer CA",
          pack_name: "DP_Fake_Chipset_01.7z",
          inf_name: "fakechip.inf",
          candidate_version: "10.1.19444.8378",
          candidate_date: "2026-03-14",
          candidate_rank: 0x00ff0000,
          current_rank: 0x01ff0000,
          better_by: "rank",
          package_file_count: 14,
          package_total_bytes: 4_718_592,
        },
      });
  }
}

function mockInstall(args: Record<string, unknown> | undefined, scenario: string | null): unknown {
  const restoreAction = args?.restoreAction;
  // The IPC layer rejects bad enums before the service (and its token) is touched.
  if (
    (args?.decision !== "confirmed" && args?.decision !== "cancelled") ||
    (restoreAction !== "create" && restoreAction !== "skip" && restoreAction !== "acknowledge_unavailable")
  ) {
    return full("invalid_request");
  }
  const session = held;
  if (session === null || args?.sessionId !== session.token) {
    return full("session_not_found");
  }
  held = null; // one-shot: consumed before eligibility, exactly like the backend
  if (args?.decision === "cancelled") return full("cancelled");
  if (restoreAction === "acknowledge_unavailable" && !session.retry) {
    return full("restore_ack_not_allowed");
  }
  switch (scenario) {
    case "restore_fail":
      if (restoreAction === "create") {
        sequence += 1;
        held = { token: `mock-retry-${sequence}`, retry: true };
        return full("restore_point_failed", { retry_session_id: held.token });
      }
      return full("installed", { published_inf: "oem42.inf", reboot_required: false });
    case "partial":
      return full("driver_store_staged_device_install_failed", {
        published_inf: "oem42.inf",
        native_error: 1603,
        cleanup_warning: true,
      });
    case "pending_reboot":
      return full("installed_pending_reboot", { published_inf: "oem42.inf", reboot_required: true });
    case "stale":
      return full("stale_preview");
    default:
      return full("installed", { published_inf: "oem42.inf", reboot_required: false });
  }
}

/** Returns undefined for any command that is not a driver-update command. */
export function driverUpdateMock(
  cmd: string,
  args: Record<string, unknown> | undefined,
  scenario: string | null,
): unknown {
  switch (cmd) {
    case CHECK:
      return mockCheck(scenario);
    case INSTALL:
      return mockInstall(args, scenario);
    case CANCEL:
      if (held !== null && args?.sessionId === held.token) held = null;
      return full("cancelled");
    default:
      return undefined;
  }
}
