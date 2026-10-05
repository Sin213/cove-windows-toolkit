// Tab 2a-13b1: frontend/backend contract + flow behavior for local driver
// updates. Runs on Node's built-in test runner (native TypeScript stripping);
// the pure modules under src/lib have no DOM/Tauri imports.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const ROOT = fileURLToPath(new URL("../../", import.meta.url));
const UI = fileURLToPath(new URL("../", import.meta.url));
const read = (rel, base = ROOT) => readFile(base + rel, "utf8");
const stripComments = (src) =>
  src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");

const lib = await import("../src/lib/driverUpdate.ts");
const { createDriverUpdateFlow, isRootEditable, canStartCheck } = await import(
  "../src/lib/driverUpdateFlow.ts"
);

const rustSrc = await read("crates/optimizer-app/src/driver_updates.rs");
const mainSrc = await read("crates/optimizer-app/src/main.rs");

// ---------------------------------------------------------------------------
// Rust source parsing (narrow and deterministic)
// ---------------------------------------------------------------------------

const snakeOf = (name) => name.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
const camelOf = (name) => name.replace(/_([a-z])/g, (_, c) => c.toUpperCase());

function rustEnum(name) {
  const m = rustSrc.match(new RegExp(`pub enum ${name} \\{([\\s\\S]*?)\\n\\}`));
  assert.ok(m, `enum ${name} not found`);
  return m[1]
    .split("\n")
    .map((l) => l.replace(/\/\/.*$/, "").trim())
    .filter((l) => l && !l.startsWith("#"))
    .map((l) => snakeOf(l.replace(/,$/, "")));
}

function rustFields(name) {
  const m = rustSrc.match(new RegExp(`pub struct ${name} \\{([\\s\\S]*?)\\n\\}`));
  assert.ok(m, `struct ${name} not found`);
  return m[1]
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.startsWith("pub "))
    .map((l) => l.match(/^pub (\w+):/)[1]);
}

function rustParams(fn) {
  const m = rustSrc.match(new RegExp(`pub async fn ${fn}\\(([^)]*)\\)`));
  assert.ok(m, `command ${fn} not found`);
  return m[1]
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean)
    .map((p) => p.split(":")[0].trim());
}

// ---------------------------------------------------------------------------
// Fixtures: full backend response shape
// ---------------------------------------------------------------------------

const SUCCESS = new Set(["ready", "no_update", "cancelled", "installed", "installed_pending_reboot"]);
const PARTIAL = new Set([
  "installed_postcondition_mismatch",
  "installed_reconciliation_failed",
  "installed_source_invalidated",
  "driver_store_staged_install_refused",
  "driver_store_staged_device_install_failed",
  "driver_store_staged_source_invalidated",
  "stage_failed_unknown",
]);
const PREVIEW = {
  provider: "Fake Provider",
  signer: "Fake Signer",
  pack_name: "DP_Fake_01.7z",
  inf_name: "fake.inf",
  candidate_version: "1.2.3.4",
  candidate_date: "2026-01-02",
  candidate_rank: 0x00ff0000,
  current_rank: 0x01ff0000,
  better_by: "rank",
  package_file_count: 12,
  package_total_bytes: 3 * 1024 * 1024,
};
const DIAG = {
  catalogs: 3,
  host_compatible_candidates: 2,
  missing_packs: 0,
  unsupported_candidates: 0,
  rejected_candidates: 0,
  failed_candidates: 0,
  no_action_candidates: 1,
  ready_candidates: 1,
};
const resp = (status, o = {}) => ({
  success: SUCCESS.has(status),
  partial: PARTIAL.has(status),
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
  ...o,
});
const ready = (token = "tok-A") =>
  resp("ready", { session_id: token, expires_in_seconds: 600, preview: PREVIEW, diagnostics: DIAG });

const DEVICE = "PCI\\VEN_FAKE&DEV_0001\\1&2&3";
const ROOT_PATH = "Z:\\FakeSdio";
const flush = () => new Promise((r) => setImmediate(r));
function deferred() {
  let resolve, reject;
  const promise = new Promise((a, b) => ((resolve = a), (reject = b)));
  return { promise, resolve, reject };
}

/** handlers: cmd -> (args, nth) => value | promise. Cancel defaults to ok. */
function harness(handlers = {}) {
  const calls = [];
  const counts = {};
  const invoke = (cmd, args) => {
    calls.push({ cmd, args });
    const nth = (counts[cmd] = (counts[cmd] ?? 0) + 1) - 1;
    const h = handlers[cmd];
    if (!h) {
      if (cmd === "cancel_local_driver_update") return Promise.resolve(resp("cancelled"));
      throw new Error(`unscripted command ${cmd}`);
    }
    return Promise.resolve().then(() => h(args, nth));
  };
  const outcomes = { n: 0 };
  const flow = createDriverUpdateFlow({ invoke });
  flow.onSystemOutcome(() => outcomes.n++);
  const of = (cmd) => calls.filter((c) => c.cmd === cmd);
  return { flow, calls, of, outcomes, state: () => flow.getState() };
}
async function toReady(h, token = "tok-A") {
  h.flow.check(DEVICE, ROOT_PATH);
  await flush();
  assert.equal(h.state().phase, "ready", "fixture failed to reach ready");
  return token;
}

const CHECK = "check_local_driver_update";
const INSTALL = "install_local_driver_update";
const CANCEL = "cancel_local_driver_update";

/** A new check cancels any token still held, so a stale token is observable. */
async function assertNoHeldToken(h) {
  const before = h.of(CANCEL).length;
  h.flow.dismissResult();
  h.flow.check(DEVICE, ROOT_PATH);
  await flush();
  assert.equal(h.of(CANCEL).length, before, "a stale session token was still held");
}

// ---------------------------------------------------------------------------
// 1. Contract parity with the committed backend
// ---------------------------------------------------------------------------

test("frontend known statuses equal the backend UpdateStatus variants", () => {
  assert.deepEqual([...lib.DRIVER_UPDATE_STATUSES].sort(), rustEnum("UpdateStatus").sort());
  assert.equal(lib.DRIVER_UPDATE_STATUSES.length, 31);
});

test("every known status has intentional UI copy and nothing else does", () => {
  assert.deepEqual(Object.keys(lib.UPDATE_STATUS_COPY).sort(), [...lib.DRIVER_UPDATE_STATUSES].sort());
  for (const [status, copy] of Object.entries(lib.UPDATE_STATUS_COPY)) {
    assert.ok(copy.title.length > 3 && copy.body.length > 10, status);
    assert.notEqual(copy.body, status, `${status}: copy must not be the machine status`);
    assert.doesNotMatch(copy.title + copy.body, /_/, `${status}: copy leaks a machine token`);
  }
});

test("better_by and response/preview/diagnostics fields match the backend", () => {
  assert.deepEqual([...lib.BETTER_BY].sort(), rustEnum("BetterBy").sort());
  assert.deepEqual(Object.keys(resp("ready")).sort(), rustFields("DriverUpdateResponse").sort());
  assert.deepEqual(Object.keys(PREVIEW).sort(), rustFields("PreviewView").sort());
  assert.deepEqual(Object.keys(DIAG).sort(), rustFields("Diagnostics").sort());
  assert.deepEqual(rustEnum("RestoreAction").sort(), ["acknowledge_unavailable", "create", "skip"]);
  assert.deepEqual(rustEnum("UpdateDecision").sort(), ["cancelled", "confirmed"]);
});

test("the three IPC commands are registered and invoked with the Rust parameter names", async () => {
  for (const c of [CHECK, INSTALL, CANCEL]) assert.match(mainSrc, new RegExp(`driver_updates::${c}`));
  const h = harness({
    [CHECK]: () => ready("tok-A"),
    [INSTALL]: () => resp("installed"),
  });
  await toReady(h);
  h.flow.chooseInstall("create");
  h.flow.confirmInstall();
  await flush();
  h.flow.dismissResult();
  h.flow.check(DEVICE, ROOT_PATH);
  await flush();
  h.flow.cancelPreview();
  await flush();
  assert.deepEqual(Object.keys(h.of(CHECK)[0].args).sort(), rustParams(CHECK).map(camelOf).sort());
  assert.deepEqual(Object.keys(h.of(INSTALL)[0].args).sort(), rustParams(INSTALL).map(camelOf).sort());
  assert.deepEqual(Object.keys(h.of(CANCEL)[0].args).sort(), rustParams(CANCEL).map(camelOf).sort());
});

// ---------------------------------------------------------------------------
// 2. Runtime IPC validator (fail closed)
// ---------------------------------------------------------------------------

test("validator accepts a full valid response for every known status", () => {
  for (const s of lib.DRIVER_UPDATE_STATUSES) {
    assert.equal(lib.isDriverUpdateResponse(resp(s)), true, s);
  }
  assert.equal(lib.isDriverUpdateResponse(ready()), true);
});

test("validator rejects an unknown backend status", () => {
  assert.equal(lib.isDriverUpdateResponse(resp("installed_but_different")), false);
  assert.equal(lib.isDriverUpdateResponse(resp("Installed")), false);
  assert.equal(lib.isDriverUpdateResponse(resp("")), false);
});

test("validator rejects non-objects and removes of any required field", () => {
  for (const bad of [null, undefined, 7, "installed", [], [resp("installed")]]) {
    assert.equal(lib.isDriverUpdateResponse(bad), false);
  }
  for (const field of rustFields("DriverUpdateResponse")) {
    const r = ready();
    delete r[field];
    assert.equal(lib.isDriverUpdateResponse(r), false, `missing ${field}`);
  }
});

test("validator rejects wrong scalar and nullable field types", () => {
  const cases = {
    success: "true",
    partial: 1,
    message: 5,
    detail: 5,
    session_id: 5,
    retry_session_id: 5,
    expires_in_seconds: "600",
    published_inf: 5,
    reboot_required: "no",
    native_error: "5",
    postcondition_observed: 0,
    cleanup_warning: null,
    diagnostics: "x",
    preview: "x",
  };
  for (const [field, value] of Object.entries(cases)) {
    assert.equal(lib.isDriverUpdateResponse({ ...ready(), [field]: value }), false, field);
  }
});

test("validator requires non-negative integers for ranks, counts and bytes", () => {
  const badNumbers = [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, "3"];
  for (const field of ["candidate_rank", "current_rank", "package_file_count", "package_total_bytes"]) {
    for (const n of badNumbers) {
      const r = ready();
      r.preview = { ...PREVIEW, [field]: n };
      assert.equal(lib.isDriverUpdateResponse(r), false, `${field}=${String(n)}`);
    }
  }
  for (const field of Object.keys(DIAG)) {
    for (const n of badNumbers) {
      const r = ready();
      r.diagnostics = { ...DIAG, [field]: n };
      assert.equal(lib.isDriverUpdateResponse(r), false, `diag ${field}=${String(n)}`);
    }
  }
  for (const field of ["expires_in_seconds", "native_error"]) {
    for (const n of [-1, 1.5, Number.NaN]) {
      assert.equal(lib.isDriverUpdateResponse({ ...ready(), [field]: n }), false, field);
    }
  }
});

test("validator allows null current_rank/provider/signer/version/date but not a bad better_by", () => {
  const r = ready();
  r.preview = {
    ...PREVIEW,
    provider: null,
    signer: null,
    candidate_version: null,
    candidate_date: null,
    current_rank: null,
    better_by: "no_current_driver",
  };
  assert.equal(lib.isDriverUpdateResponse(r), true);
  for (const bad of ["better", "", null, 3, "Rank"]) {
    assert.equal(lib.isDriverUpdateResponse({ ...ready(), preview: { ...PREVIEW, better_by: bad } }), false);
  }
  for (const f of ["pack_name", "inf_name"]) {
    assert.equal(lib.isDriverUpdateResponse({ ...ready(), preview: { ...PREVIEW, [f]: null } }), false, f);
  }
});

// ---------------------------------------------------------------------------
// 3. Status presentation (compile-time-exhaustive table, behavioral claims)
// ---------------------------------------------------------------------------

test("installed_pending_reboot is presented as success with a restart requirement", () => {
  const c = lib.UPDATE_STATUS_COPY.installed_pending_reboot;
  assert.equal(c.tone, "success");
  assert.match(c.body, /restart/i);
  assert.match(c.body, /accepted/i);
  assert.equal(lib.UPDATE_STATUS_COPY.installed.tone, "success");
});

test("every partial backend state stays visibly partial with its own copy", () => {
  const copies = [...PARTIAL].map((s) => lib.UPDATE_STATUS_COPY[s]);
  for (const c of copies) assert.equal(c.tone, "warning");
  assert.equal(new Set(copies.map((c) => c.title)).size, PARTIAL.size, "partial titles must be distinct");
  const generic = lib.UPDATE_STATUS_COPY.internal_error;
  for (const c of copies) assert.notEqual(c.body, generic.body);
  assert.match(lib.UPDATE_STATUS_COPY.installed_postcondition_mismatch.body, /did not observe/i);
  assert.match(lib.UPDATE_STATUS_COPY.driver_store_staged_install_refused.body, /Driver Store/);
  assert.match(lib.UPDATE_STATUS_COPY.driver_store_staged_device_install_failed.body, /did not complete/i);
  assert.match(lib.UPDATE_STATUS_COPY.driver_store_staged_source_invalidated.body, /changed/i);
  assert.match(lib.UPDATE_STATUS_COPY.stage_failed_unknown.body, /partially changed/i);
  assert.match(lib.UPDATE_STATUS_COPY.installed_source_invalidated.body, /Rescan/i);
});

test("no partial copy implies rollback and none tells the user to retry automatically", () => {
  for (const s of PARTIAL) {
    const text = lib.UPDATE_STATUS_COPY[s].body;
    assert.doesNotMatch(text, /rolled back|reverted|restored/i, s);
  }
});

test("mutated statuses are exactly the system-outcome refresh set", () => {
  const expected = [
    "installed",
    "installed_pending_reboot",
    "installed_postcondition_mismatch",
    "installed_reconciliation_failed",
    "installed_source_invalidated",
    "driver_store_staged_install_refused",
    "driver_store_staged_device_install_failed",
    "driver_store_staged_source_invalidated",
    "stage_failed_unknown",
  ];
  const actual = lib.DRIVER_UPDATE_STATUSES.filter((s) => lib.UPDATE_STATUS_COPY[s].mutated);
  assert.deepEqual([...actual].sort(), expected.sort());
});

test("rank, better-by, byte and leaf formatting helpers", () => {
  assert.equal(lib.formatRank(0x00ff0000), "0x00FF0000");
  assert.equal(lib.formatRank(0), "0x00000000");
  assert.match(lib.describeBetterBy("no_current_driver"), /No current compatible driver/);
  assert.match(lib.describeBetterBy("rank"), /ranks this package better/);
  assert.match(lib.describeBetterBy("date"), /newer/);
  assert.match(lib.describeBetterBy("version"), /version is newer/);
  assert.equal(lib.formatBytes(3 * 1024 * 1024), "3.0 MB");
  assert.equal(lib.publishedLeaf("C:\\Windows\\INF\\oem42.inf"), "oem42.inf");
  assert.equal(lib.publishedLeaf("oem42.inf"), "oem42.inf");
});

test("reboot notice shows for installed variants and not duplicated for pending reboot", () => {
  const r = (s, reboot) => ({ kind: "status", status: s, rebootRequired: reboot });
  assert.equal(lib.showRebootNotice(r("installed", true)), true);
  assert.equal(lib.showRebootNotice(r("installed", false)), false);
  assert.equal(lib.showRebootNotice(r("installed_reconciliation_failed", true)), true);
  assert.equal(lib.showRebootNotice(r("installed_pending_reboot", true)), false);
});

// ---------------------------------------------------------------------------
// 4. Flow: check + ready
// ---------------------------------------------------------------------------

test("check sends only the device instance id and the SDIO root", async () => {
  const h = harness({ [CHECK]: () => ready() });
  h.flow.check(DEVICE, ROOT_PATH);
  assert.equal(h.state().phase, "checking");
  await flush();
  assert.deepEqual(h.of(CHECK)[0].args, { deviceInstanceId: DEVICE, sdioRoot: ROOT_PATH });
  assert.equal(h.state().phase, "ready");
  assert.equal(h.state().preview.inf_name, "fake.inf");
});

test("ready without session_id never offers install (malformed)", async () => {
  const h = harness({ [CHECK]: () => ({ ...ready(), session_id: null }) });
  h.flow.check(DEVICE, ROOT_PATH);
  await flush();
  assert.equal(h.state().phase, "result");
  assert.equal(h.state().result.kind, "malformed");
  h.flow.chooseInstall("create");
  h.flow.confirmInstall();
  await flush();
  assert.equal(h.of(INSTALL).length, 0);
});

test("ready with an empty session_id or without a preview never offers install", async () => {
  for (const bad of [{ ...ready(), session_id: "" }, { ...ready(), preview: null }]) {
    const h = harness({ [CHECK]: () => bad });
    h.flow.check(DEVICE, ROOT_PATH);
    await flush();
    assert.equal(h.state().phase, "result");
    assert.equal(h.state().result.kind, "malformed");
    h.flow.chooseInstall("skip");
    h.flow.confirmInstall();
    await flush();
    assert.equal(h.of(INSTALL).length, 0);
  }
});

test("unknown or malformed check responses fail closed and retain no session", async () => {
  for (const bad of [resp("brand_new_status", { session_id: "tok-X", preview: PREVIEW }), { success: true }, null, "ok"]) {
    const h = harness({ [CHECK]: () => bad });
    h.flow.check(DEVICE, ROOT_PATH);
    await flush();
    assert.equal(h.state().phase, "result");
    assert.equal(h.state().result.kind, "malformed");
    h.flow.chooseInstall("create");
    h.flow.confirmInstall();
    await flush();
    assert.equal(h.of(INSTALL).length, 0);
    assert.equal(h.of(CANCEL).length, 0);
  }
});

test("a rejected check shows a transport failure and is not retried", async () => {
  const h = harness({
    [CHECK]: () => {
      throw new Error("ipc down");
    },
  });
  h.flow.check(DEVICE, ROOT_PATH);
  await flush();
  assert.equal(h.state().phase, "result");
  assert.deepEqual(h.state().result, { kind: "transport", during: "check" });
  assert.equal(h.of(CHECK).length, 1);
});

test("non-ready check statuses leave no session and offer no install", async () => {
  for (const s of ["no_update", "ambiguous_local_update", "invalid_sdio_root", "invalid_index_corpus", "degraded_inventory", "busy", "session_capacity"]) {
    const h = harness({ [CHECK]: () => resp(s, { detail: "bounded_reason" }) });
    h.flow.check(DEVICE, ROOT_PATH);
    await flush();
    assert.equal(h.state().phase, "result", s);
    assert.equal(h.state().result.status, s);
    assert.equal(h.state().result.detail, "bounded_reason");
    h.flow.chooseInstall("create");
    assert.equal(h.state().phase, "result", s);
  }
});

test("a second check while checking is ignored", async () => {
  const d = deferred();
  const h = harness({ [CHECK]: () => d.promise });
  h.flow.check(DEVICE, ROOT_PATH);
  h.flow.check("OTHER\\DEV", ROOT_PATH);
  assert.equal(h.of(CHECK).length, 1);
  d.resolve(ready());
  await flush();
  assert.equal(h.state().phase, "ready");
});

// ---------------------------------------------------------------------------
// 5. Flow: session privacy, abandon, cancel
// ---------------------------------------------------------------------------

test("session tokens never appear in observable flow state", async () => {
  const seen = [];
  const h = harness({
    [CHECK]: () => ready("SECRET-TOKEN-A"),
    [INSTALL]: (a, n) => (n === 0 ? resp("restore_point_failed", { retry_session_id: "SECRET-RETRY-B" }) : resp("installed", { session_id: "SECRET-LEAK-C" })),
  });
  h.flow.subscribe(() => seen.push(JSON.stringify(h.flow.getState())));
  await toReady(h);
  h.flow.chooseInstall("create");
  h.flow.confirmInstall();
  await flush();
  assert.equal(h.state().phase, "confirm_ack_unavailable");
  h.flow.confirmAcknowledge();
  await flush();
  assert.equal(h.state().phase, "result");
  const all = seen.join("\n") + JSON.stringify(h.state());
  assert.doesNotMatch(all, /SECRET-/);
});

test("backend message text never reaches observable state", async () => {
  const h = harness({ [CHECK]: () => resp("invalid_sdio_root", { message: "BACKEND-MESSAGE-SENTINEL" }) });
  h.flow.check(DEVICE, ROOT_PATH);
  await flush();
  assert.doesNotMatch(JSON.stringify(h.state()), /BACKEND-MESSAGE-SENTINEL/);
});

test("explicit cancel preview cancels the exact token and clears authority", async () => {
  const h = harness({ [CHECK]: () => ready("tok-A") });
  await toReady(h);
  h.flow.cancelPreview();
  assert.equal(h.state().phase, "idle");
  assert.deepEqual(h.of(CANCEL).map((c) => c.args), [{ sessionId: "tok-A" }]);
  h.flow.chooseInstall("create");
  h.flow.confirmInstall();
  await flush();
  assert.equal(h.of(INSTALL).length, 0);
});

test("a rejected cancel is swallowed", async () => {
  const h = harness({
    [CHECK]: () => ready("tok-A"),
    [CANCEL]: () => {
      throw new Error("gone");
    },
  });
  await toReady(h);
  h.flow.cancelPreview();
  await flush();
  assert.equal(h.state().phase, "idle");
});

test("starting a new check cancels the previous ready token first", async () => {
  const h = harness({ [CHECK]: (a, n) => ready(n === 0 ? "tok-A" : "tok-B") });
  await toReady(h);
  h.flow.check("OTHER\\DEV", ROOT_PATH);
  assert.deepEqual(h.calls.map((c) => c.cmd), [CHECK, CANCEL, CHECK]);
  assert.deepEqual(h.of(CANCEL)[0].args, { sessionId: "tok-A" });
  await flush();
  h.flow.chooseInstall("create");
  assert.equal(h.state().phase, "confirm_create");
});

test("abandon (rescan/unmount) cancels an active ready preview", async () => {
  const h = harness({ [CHECK]: () => ready("tok-A") });
  await toReady(h);
  h.flow.abandon();
  assert.equal(h.state().phase, "idle");
  assert.deepEqual(h.of(CANCEL).map((c) => c.args), [{ sessionId: "tok-A" }]);
  h.flow.abandon();
  assert.equal(h.of(CANCEL).length, 1, "abandon with no token must not call cancel");
});

test("abandon during checking cancels a late ready session and ignores it", async () => {
  const d = deferred();
  const h = harness({ [CHECK]: () => d.promise });
  h.flow.check(DEVICE, ROOT_PATH);
  h.flow.abandon();
  assert.equal(h.state().phase, "idle");
  d.resolve(ready("tok-LATE"));
  await flush();
  assert.equal(h.state().phase, "idle");
  assert.deepEqual(h.of(CANCEL).map((c) => c.args), [{ sessionId: "tok-LATE" }]);
});

test("changing the SDIO root requires abandoning the preview (root locked while a session exists)", async () => {
  for (const phase of ["checking", "ready", "confirm_create", "confirm_skip", "installing", "confirm_ack_unavailable"]) {
    assert.equal(isRootEditable({ phase }), false, phase);
  }
  for (const phase of ["idle", "result"]) assert.equal(isRootEditable({ phase }), true, phase);
  for (const phase of ["idle", "result", "ready"]) assert.equal(canStartCheck({ phase }), true, phase);
  for (const phase of ["checking", "installing", "confirm_create", "confirm_skip", "confirm_ack_unavailable"]) {
    assert.equal(canStartCheck({ phase }), false, phase);
  }
});

// ---------------------------------------------------------------------------
// 6. Flow: confirmation and install
// ---------------------------------------------------------------------------

test("choosing install never installs; only the confirmation does (create is the default path)", async () => {
  const h = harness({ [CHECK]: () => ready("tok-A"), [INSTALL]: () => resp("installed", { published_inf: "oem42.inf", reboot_required: false }) });
  await toReady(h);
  h.flow.confirmInstall();
  await flush();
  assert.equal(h.of(INSTALL).length, 0, "confirm without a choice must not install");
  h.flow.chooseInstall("create");
  assert.equal(h.state().phase, "confirm_create");
  assert.equal(h.of(INSTALL).length, 0, "choosing must not install");
  h.flow.confirmInstall();
  assert.equal(h.state().phase, "installing");
  await flush();
  assert.deepEqual(h.of(INSTALL).map((c) => c.args), [{ sessionId: "tok-A", decision: "confirmed", restoreAction: "create" }]);
  assert.equal(h.state().result.status, "installed");
  assert.equal(h.state().result.publishedInf, "oem42.inf");
});

test("skip is explicit: only the skip choice sends restoreAction=skip", async () => {
  const h = harness({ [CHECK]: () => ready("tok-A"), [INSTALL]: () => resp("installed") });
  await toReady(h);
  h.flow.chooseInstall("skip");
  assert.equal(h.state().phase, "confirm_skip");
  h.flow.confirmInstall();
  await flush();
  assert.equal(h.of(INSTALL)[0].args.restoreAction, "skip");
});

test("declining a confirmation returns to ready without any backend call", async () => {
  const h = harness({ [CHECK]: () => ready("tok-A") });
  await toReady(h);
  for (const mode of ["create", "skip"]) {
    h.flow.chooseInstall(mode);
    h.flow.declineInstall();
    assert.equal(h.state().phase, "ready");
  }
  assert.equal(h.calls.length, 1);
});

test("a double confirm submits exactly one install", async () => {
  const d = deferred();
  const h = harness({ [CHECK]: () => ready("tok-A"), [INSTALL]: () => d.promise });
  await toReady(h);
  h.flow.chooseInstall("create");
  h.flow.confirmInstall();
  h.flow.confirmInstall();
  assert.equal(h.of(INSTALL).length, 1);
  d.resolve(resp("installed"));
  await flush();
});

test("restore failure replaces authority with ONLY the retry token", async () => {
  const h = harness({
    [CHECK]: () => ready("tok-A"),
    [INSTALL]: (a, n) => (n === 0 ? resp("restore_point_failed", { retry_session_id: "tok-RETRY" }) : resp("installed")),
  });
  await toReady(h);
  h.flow.chooseInstall("create");
  h.flow.confirmInstall();
  await flush();
  assert.equal(h.state().phase, "confirm_ack_unavailable");
  h.flow.confirmAcknowledge();
  assert.equal(h.state().phase, "installing");
  await flush();
  const installs = h.of(INSTALL).map((c) => c.args);
  assert.deepEqual(installs[1], { sessionId: "tok-RETRY", decision: "confirmed", restoreAction: "acknowledge_unavailable" });
  assert.equal(installs.filter((a) => a.sessionId === "tok-A").length, 1, "original token reused");
  assert.equal(h.state().result.status, "installed");
});

test("restore failure without a retry token is malformed and clears authority", async () => {
  const h = harness({
    [CHECK]: () => ready("tok-A"),
    [INSTALL]: () => resp("restore_point_failed", { retry_session_id: null }),
  });
  await toReady(h);
  h.flow.chooseInstall("create");
  h.flow.confirmInstall();
  await flush();
  assert.equal(h.state().phase, "result");
  assert.equal(h.state().result.kind, "malformed");
  h.flow.confirmAcknowledge();
  await flush();
  assert.equal(h.of(INSTALL).length, 1);
  await assertNoHeldToken(h);
});

test("acknowledge_unavailable is unreachable from the initial preview path", async () => {
  const h = harness({ [CHECK]: () => ready("tok-A"), [INSTALL]: () => resp("installed") });
  await toReady(h);
  h.flow.confirmAcknowledge();
  h.flow.chooseInstall("create");
  h.flow.confirmAcknowledge();
  await flush();
  assert.equal(h.of(INSTALL).length, 0);
  assert.equal(h.state().phase, "confirm_create");
});

test("declining the acknowledgement cancels ONLY the retry token and clears the preview", async () => {
  const h = harness({
    [CHECK]: () => ready("tok-A"),
    [INSTALL]: () => resp("restore_point_failed", { retry_session_id: "tok-RETRY" }),
  });
  await toReady(h);
  h.flow.chooseInstall("create");
  h.flow.confirmInstall();
  await flush();
  h.flow.declineAcknowledge();
  assert.equal(h.state().phase, "idle");
  assert.deepEqual(h.of(CANCEL).map((c) => c.args), [{ sessionId: "tok-RETRY" }]);
});

test("a second restore_point_failed after acknowledging is shown, never looped", async () => {
  const h = harness({
    [CHECK]: () => ready("tok-A"),
    [INSTALL]: () => resp("restore_point_failed", { retry_session_id: "tok-RETRY" }),
  });
  await toReady(h);
  h.flow.chooseInstall("create");
  h.flow.confirmInstall();
  await flush();
  h.flow.confirmAcknowledge();
  await flush();
  assert.equal(h.state().phase, "result");
  assert.equal(h.state().result.status, "restore_point_failed");
  assert.equal(h.of(INSTALL).length, 2);
});

test("nothing can cancel or restart while an install is in flight", async () => {
  const d = deferred();
  const h = harness({ [CHECK]: () => ready("tok-A"), [INSTALL]: () => d.promise });
  await toReady(h);
  h.flow.chooseInstall("create");
  h.flow.confirmInstall();
  h.flow.abandon();
  h.flow.cancelPreview();
  h.flow.declineInstall();
  h.flow.declineAcknowledge();
  h.flow.dismissResult();
  h.flow.check(DEVICE, ROOT_PATH);
  assert.equal(h.state().phase, "installing");
  assert.equal(h.of(CANCEL).length, 0);
  assert.equal(h.of(CHECK).length, 1);
  d.resolve(resp("installed"));
  await flush();
  assert.equal(h.of(CANCEL).length, 0);
});

test("an explicit busy response keeps the preview and session for a later retry", async () => {
  const h = harness({
    [CHECK]: () => ready("tok-A"),
    [INSTALL]: (a, n) => (n === 0 ? resp("busy") : resp("installed")),
  });
  await toReady(h);
  h.flow.chooseInstall("create");
  h.flow.confirmInstall();
  await flush();
  assert.equal(h.state().phase, "ready");
  assert.equal(h.state().notice, "busy");
  assert.equal(h.state().preview.inf_name, "fake.inf");
  h.flow.chooseInstall("create");
  h.flow.confirmInstall();
  await flush();
  assert.deepEqual(h.of(INSTALL).map((c) => c.args.sessionId), ["tok-A", "tok-A"]);
  assert.equal(h.state().result.status, "installed");
});

test("busy after acknowledging returns to the acknowledgement step with the retry token", async () => {
  const h = harness({
    [CHECK]: () => ready("tok-A"),
    [INSTALL]: (a, n) => {
      if (n === 0) return resp("restore_point_failed", { retry_session_id: "tok-RETRY" });
      return n === 1 ? resp("busy") : resp("installed");
    },
  });
  await toReady(h);
  h.flow.chooseInstall("create");
  h.flow.confirmInstall();
  await flush();
  h.flow.confirmAcknowledge();
  await flush();
  assert.equal(h.state().phase, "confirm_ack_unavailable");
  assert.equal(h.of(CANCEL).length, 0);
  h.flow.confirmAcknowledge();
  await flush();
  const installs = h.of(INSTALL).map((c) => c.args);
  assert.equal(installs.length, 3);
  assert.deepEqual(installs[2], { sessionId: "tok-RETRY", decision: "confirmed", restoreAction: "acknowledge_unavailable" });
  assert.equal(installs.filter((a) => a.restoreAction === "create").length, 1, "restore creation was repeated");
  assert.equal(h.state().result.status, "installed");
});

test("busy after acknowledging can still be declined, cancelling only the retry token", async () => {
  const h = harness({
    [CHECK]: () => ready("tok-A"),
    [INSTALL]: (a, n) => (n === 0 ? resp("restore_point_failed", { retry_session_id: "tok-RETRY" }) : resp("busy")),
  });
  await toReady(h);
  h.flow.chooseInstall("create");
  h.flow.confirmInstall();
  await flush();
  h.flow.confirmAcknowledge();
  await flush();
  h.flow.declineAcknowledge();
  assert.equal(h.state().phase, "idle");
  assert.deepEqual(h.of(CANCEL).map((c) => c.args), [{ sessionId: "tok-RETRY" }]);
});

test("an install-time internal_error is an uncertain outcome with a read-only refresh", async () => {
  const h = harness({
    [CHECK]: () => ready("tok-A"),
    [INSTALL]: () => resp("internal_error", { detail: "task_failed" }),
  });
  await toReady(h);
  h.flow.chooseInstall("create");
  h.flow.confirmInstall();
  await flush();
  assert.deepEqual(h.state().result, { kind: "transport", during: "install" });
  assert.equal(h.outcomes.n, 1);
  assert.equal(h.of(INSTALL).length, 1);
  assert.equal(h.of(CHECK).length, 1);
  await assertNoHeldToken(h);
});

test("a check-time internal_error stays a plain error and does not refresh", async () => {
  const h = harness({ [CHECK]: () => resp("internal_error", { detail: "task_failed" }) });
  h.flow.check(DEVICE, ROOT_PATH);
  await flush();
  assert.equal(h.state().result.status, "internal_error");
  assert.equal(h.outcomes.n, 0);
});

test("a rejected install clears authority, is never retried, and refreshes inventory read-only", async () => {
  const h = harness({
    [CHECK]: () => ready("tok-A"),
    [INSTALL]: () => {
      throw new Error("ipc dropped");
    },
  });
  await toReady(h);
  h.flow.chooseInstall("create");
  h.flow.confirmInstall();
  await flush();
  assert.deepEqual(h.state().result, { kind: "transport", during: "install" });
  assert.equal(h.of(INSTALL).length, 1);
  assert.equal(h.of(CANCEL).length, 0);
  assert.equal(h.outcomes.n, 1);
  h.flow.confirmInstall();
  h.flow.confirmAcknowledge();
  await flush();
  assert.equal(h.of(INSTALL).length, 1);
  await assertNoHeldToken(h);
});

test("a malformed or ready-status install response clears authority and shows malformed", async () => {
  for (const bad of [{ success: true }, ready("tok-ECHO"), resp("surprise_status")]) {
    const h = harness({ [CHECK]: () => ready("tok-A"), [INSTALL]: () => bad });
    await toReady(h);
    h.flow.chooseInstall("create");
    h.flow.confirmInstall();
    await flush();
    assert.equal(h.state().result.kind, "malformed");
    h.flow.chooseInstall("create");
    h.flow.confirmInstall();
    await flush();
    assert.equal(h.of(INSTALL).length, 1);
    await assertNoHeldToken(h);
  }
});

test("stale-session statuses clear the preview and ask for a fresh check", async () => {
  for (const s of ["session_expired", "session_not_found", "stale_preview", "restore_ack_not_allowed"]) {
    const h = harness({ [CHECK]: () => ready("tok-A"), [INSTALL]: () => resp(s) });
    await toReady(h);
    h.flow.chooseInstall("create");
    h.flow.confirmInstall();
    await flush();
    assert.equal(h.state().phase, "result", s);
    assert.equal(h.state().result.status, s);
    assert.match(lib.UPDATE_STATUS_COPY[s].body, /Check Local Update again/i, s);
    h.flow.confirmInstall();
    await flush();
    assert.equal(h.of(INSTALL).length, 1, s);
    await assertNoHeldToken(h);
  }
});

test("pending reboot, partial and success outcomes keep their own status and flags", async () => {
  const cases = [
    resp("installed_pending_reboot", { published_inf: "oem7.inf", reboot_required: true }),
    resp("driver_store_staged_device_install_failed", { native_error: 123, cleanup_warning: true }),
    resp("installed_source_invalidated", { postcondition_observed: true, reboot_required: true }),
  ];
  for (const r of cases) {
    const h = harness({ [CHECK]: () => ready("tok-A"), [INSTALL]: () => r });
    await toReady(h);
    h.flow.chooseInstall("create");
    h.flow.confirmInstall();
    await flush();
    const v = h.state().result;
    assert.equal(v.kind, "status");
    assert.equal(v.status, r.status);
    assert.equal(v.cleanupWarning, r.cleanup_warning);
    assert.equal(v.nativeError, r.native_error);
    assert.equal(v.rebootRequired, r.reboot_required === true);
    assert.equal(v.postconditionObserved, r.postcondition_observed);
  }
});

test("cleanup_warning is a flag beside the primary outcome, never a replacement", async () => {
  const h = harness({
    [CHECK]: () => ready("tok-A"),
    [INSTALL]: () => resp("installed", { cleanup_warning: true, published_inf: "oem1.inf" }),
  });
  await toReady(h);
  h.flow.chooseInstall("create");
  h.flow.confirmInstall();
  await flush();
  assert.equal(h.state().result.status, "installed");
  assert.equal(h.state().result.cleanupWarning, true);
});

test("system outcomes trigger exactly one read-only refresh and never another update call", async () => {
  for (const s of lib.DRIVER_UPDATE_STATUSES) {
    // internal_error from install is an uncertain outcome (covered separately).
    if (s === "ready" || s === "busy" || s === "restore_point_failed" || s === "internal_error") continue;
    const h = harness({ [CHECK]: () => ready("tok-A"), [INSTALL]: () => resp(s) });
    await toReady(h);
    h.flow.chooseInstall("create");
    h.flow.confirmInstall();
    await flush();
    assert.equal(h.outcomes.n, lib.UPDATE_STATUS_COPY[s].mutated ? 1 : 0, s);
    assert.equal(h.of(CHECK).length, 1, s);
    assert.equal(h.of(INSTALL).length, 1, s);
  }
});

// ---------------------------------------------------------------------------
// 7. Structural gates on the lib sources
// ---------------------------------------------------------------------------

const LIB_SRC = {
  copy: stripComments(await read("src/lib/driverUpdate.ts", UI)),
  flow: stripComments(await read("src/lib/driverUpdateFlow.ts", UI)),
};

test("lib code is pure and never persists, logs or navigates", () => {
  for (const [name, src] of Object.entries(LIB_SRC)) {
    assert.doesNotMatch(src, /localStorage|sessionStorage|indexedDB|document\.cookie/i, name);
    assert.doesNotMatch(src, /console\.|recordUiEvent/, name);
    assert.doesNotMatch(src, /\blocation\b|history\.(push|replace)State/, name);
    assert.doesNotMatch(src, /from ["'](react|@tauri-apps)|\bwindow\b|\bdocument\b/, name);
  }
});

test("the flow never reads the backend message and has a single install call site", () => {
  assert.doesNotMatch(LIB_SRC.flow, /\.message\b|["']message["']/);
  assert.equal((LIB_SRC.flow.match(/install_local_driver_update/g) ?? []).length, 1);
});

test("the flow has no automatic retry machinery and sends no device metadata", () => {
  assert.doesNotMatch(LIB_SRC.flow, /setTimeout|setInterval|retry\(|while\s*\(|for\s*\(/);
  assert.doesNotMatch(LIB_SRC.flow, /hardware_ids|compatible_ids|rank|installed_inf/);
});
