// Driver-update workflow state machine (Tab 2a-13b).
//
// Mirrors the backend's one-operation, one-shot-session model. The opaque
// session token lives only in this closure: it is never part of the observable
// state, so rendering code cannot display, log or persist it. Nothing here
// retries a mutating command; every retry after uncertainty needs a fresh
// check.

import {
  UPDATE_STATUS_COPY,
  isDriverUpdateResponse,
  publishedLeaf,
  type DriverUpdateResponse,
  type PreviewView,
  type ResultView,
  type RestoreAction,
} from "./driverUpdate.ts";

const CHECK = "check_local_driver_update";
const INSTALL = "install_local_driver_update";
const CANCEL = "cancel_local_driver_update";

const MAX_DETAIL = 120;

export type FlowState =
  | { phase: "idle" }
  | { phase: "checking"; deviceId: string }
  | {
      phase: "ready";
      deviceId: string;
      preview: PreviewView;
      expiresInSeconds: number | null;
      notice: "busy" | null;
    }
  | {
      phase: "confirm_create" | "confirm_skip";
      deviceId: string;
      preview: PreviewView;
      expiresInSeconds: number | null;
    }
  | { phase: "installing"; deviceId: string; preview: PreviewView }
  | { phase: "confirm_ack_unavailable"; deviceId: string; preview: PreviewView }
  | { phase: "result"; deviceId: string; result: ResultView };

export type FlowPhase = FlowState["phase"];

/** The SDIO root may change only when no preview/session exists. */
export const isRootEditable = (s: { phase: FlowPhase }): boolean =>
  s.phase === "idle" || s.phase === "result";

/** A new check may start (replacing a held preview) but never mid-operation. */
export const canStartCheck = (s: { phase: FlowPhase }): boolean =>
  s.phase === "idle" || s.phase === "result" || s.phase === "ready";

/** Rescan is blocked while an operation or confirmation is in progress. */
export const isOperationActive = (s: { phase: FlowPhase }): boolean =>
  !canStartCheck(s);

export interface FlowDeps {
  invoke: (cmd: string, args: Record<string, unknown>) => Promise<unknown>;
}

const nonEmpty = (v: string | null): v is string => typeof v === "string" && v.length > 0;

function summarize(r: DriverUpdateResponse): ResultView {
  return {
    kind: "status",
    status: r.status,
    detail: r.detail === null ? null : r.detail.slice(0, MAX_DETAIL),
    publishedInf: r.published_inf === null ? null : publishedLeaf(r.published_inf),
    rebootRequired: r.reboot_required === true,
    nativeError: r.native_error,
    postconditionObserved: r.postcondition_observed,
    cleanupWarning: r.cleanup_warning,
  };
}

export function createDriverUpdateFlow({ invoke }: FlowDeps) {
  let state: FlowState = { phase: "idle" };
  let token: string | null = null;
  let expiresInSeconds: number | null = null;
  let generation = 0;
  const listeners = new Set<() => void>();
  const outcomeListeners = new Set<() => void>();

  const set = (next: FlowState) => {
    state = next;
    listeners.forEach((listener) => listener());
  };

  const call = (cmd: string, args: Record<string, unknown>): Promise<unknown> => {
    try {
      return Promise.resolve(invoke(cmd, args));
    } catch (error) {
      return Promise.reject(error);
    }
  };

  const cancelBestEffort = (sessionId: string) => {
    call(CANCEL, { sessionId }).catch(() => {
      // Cancelling an unknown or expired session is safe and best effort.
    });
  };

  const finish = (deviceId: string, result: ResultView, refresh: boolean) => {
    set({ phase: "result", deviceId, result });
    if (refresh) outcomeListeners.forEach((listener) => listener());
  };

  const onCheckResponse = (mine: number, deviceId: string, raw: unknown) => {
    if (mine !== generation) {
      // Abandoned while checking: a late session must not stay open.
      if (isDriverUpdateResponse(raw) && raw.status === "ready" && nonEmpty(raw.session_id)) {
        cancelBestEffort(raw.session_id);
      }
      return;
    }
    if (!isDriverUpdateResponse(raw)) {
      finish(deviceId, { kind: "malformed" }, false);
      return;
    }
    if (raw.status !== "ready") {
      finish(deviceId, summarize(raw), false);
      return;
    }
    if (!nonEmpty(raw.session_id) || raw.preview === null) {
      finish(deviceId, { kind: "malformed" }, false);
      return;
    }
    token = raw.session_id;
    expiresInSeconds = raw.expires_in_seconds;
    set({ phase: "ready", deviceId, preview: raw.preview, expiresInSeconds, notice: null });
  };

  const onInstallResponse = (
    raw: unknown,
    deviceId: string,
    preview: PreviewView,
    action: RestoreAction,
  ) => {
    if (!isDriverUpdateResponse(raw) || raw.status === "ready") {
      token = null;
      finish(deviceId, { kind: "malformed" }, true);
      return;
    }
    if (raw.status === "internal_error") {
      // The blocking install task failed: Windows may already have changed.
      token = null;
      finish(deviceId, { kind: "transport", during: "install" }, true);
      return;
    }
    if (raw.status === "busy") {
      // Operation locking precedes session consumption: keep the session and
      // return to the step the user was on (the retry token only fits the
      // acknowledgement step).
      if (action === "acknowledge_unavailable") {
        set({ phase: "confirm_ack_unavailable", deviceId, preview });
      } else {
        set({ phase: "ready", deviceId, preview, expiresInSeconds, notice: "busy" });
      }
      return;
    }
    if (raw.status === "restore_point_failed" && action !== "acknowledge_unavailable") {
      if (!nonEmpty(raw.retry_session_id)) {
        token = null;
        finish(deviceId, { kind: "malformed" }, true);
        return;
      }
      token = raw.retry_session_id;
      set({ phase: "confirm_ack_unavailable", deviceId, preview });
      return;
    }
    token = null;
    finish(deviceId, summarize(raw), UPDATE_STATUS_COPY[raw.status].mutated);
  };

  const submitInstall = (action: RestoreAction) => {
    if (token === null) return;
    if (
      state.phase !== "confirm_create" &&
      state.phase !== "confirm_skip" &&
      state.phase !== "confirm_ack_unavailable"
    ) {
      return;
    }
    const { deviceId, preview } = state;
    set({ phase: "installing", deviceId, preview });
    call(INSTALL, { sessionId: token, decision: "confirmed", restoreAction: action }).then(
      (raw) => onInstallResponse(raw, deviceId, preview, action),
      () => {
        // The one-shot session may or may not be consumed: drop authority.
        token = null;
        finish(deviceId, { kind: "transport", during: "install" }, true);
      },
    );
  };

  return {
    getState: (): FlowState => state,
    subscribe: (listener: () => void) => {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },

    /**
     * Called after a result where Windows may have changed (and after an
     * undeterminable install). The listener must only run a read-only
     * inventory refresh, never another update command.
     */
    onSystemOutcome: (listener: () => void) => {
      outcomeListeners.add(listener);
      return () => {
        outcomeListeners.delete(listener);
      };
    },

    check(deviceId: string, sdioRoot: string) {
      if (!canStartCheck(state)) return;
      if (token !== null) {
        cancelBestEffort(token);
        token = null;
      }
      const mine = ++generation;
      set({ phase: "checking", deviceId });
      call(CHECK, { deviceInstanceId: deviceId, sdioRoot }).then(
        (raw) => onCheckResponse(mine, deviceId, raw),
        () => {
          if (mine === generation) {
            finish(deviceId, { kind: "transport", during: "check" }, false);
          }
        },
      );
    },

    chooseInstall(mode: "create" | "skip") {
      if (state.phase !== "ready") return;
      const { deviceId, preview } = state;
      set({
        phase: mode === "create" ? "confirm_create" : "confirm_skip",
        deviceId,
        preview,
        expiresInSeconds,
      });
    },

    declineInstall() {
      if (state.phase !== "confirm_create" && state.phase !== "confirm_skip") return;
      const { deviceId, preview } = state;
      set({ phase: "ready", deviceId, preview, expiresInSeconds, notice: null });
    },

    confirmInstall() {
      if (state.phase === "confirm_create") submitInstall("create");
      else if (state.phase === "confirm_skip") submitInstall("skip");
    },

    confirmAcknowledge() {
      if (state.phase === "confirm_ack_unavailable") submitInstall("acknowledge_unavailable");
    },

    declineAcknowledge() {
      if (state.phase !== "confirm_ack_unavailable") return;
      if (token !== null) cancelBestEffort(token);
      token = null;
      set({ phase: "idle" });
    },

    cancelPreview() {
      if (state.phase !== "ready") return;
      if (token !== null) cancelBestEffort(token);
      token = null;
      set({ phase: "idle" });
    },

    /** Rescan/unmount: release any held session. Never during an install. */
    abandon() {
      switch (state.phase) {
        case "checking":
          generation += 1;
          set({ phase: "idle" });
          return;
        case "ready":
        case "confirm_create":
        case "confirm_skip":
        case "confirm_ack_unavailable":
          if (token !== null) cancelBestEffort(token);
          token = null;
          set({ phase: "idle" });
          return;
        default:
          return;
      }
    },

    dismissResult() {
      if (state.phase === "result") set({ phase: "idle" });
    },
  };
}

export type DriverUpdateFlow = ReturnType<typeof createDriverUpdateFlow>;
