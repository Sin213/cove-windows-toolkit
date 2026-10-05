// Tab 2a-13b2: browser mocks and UI source gates for the local driver-update
// workflow. The lib contract/flow behavior is covered by
// driver-update-contract.test.mjs (Tab 2a-13b1).
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
const { createDriverUpdateFlow } = await import("../src/lib/driverUpdateFlow.ts");
const mockLib = await import("../src/lib/driverUpdateMock.ts");

const rustSrc = await read("crates/optimizer-app/src/driver_updates.rs");
function rustFields(name) {
  const m = rustSrc.match(new RegExp(`pub struct ${name} \\{([\\s\\S]*?)\\n\\}`));
  assert.ok(m, `struct ${name} not found`);
  return m[1]
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.startsWith("pub "))
    .map((l) => l.match(/^pub (\w+):/)[1]);
}

const DEVICE = "PCI\\VEN_FAKE&DEV_0001\\1&2&3";
const ROOT_PATH = "Z:\\FakeSdio";
const flush = () => new Promise((r) => setImmediate(r));
const CHECK = "check_local_driver_update";
const INSTALL = "install_local_driver_update";
const CANCEL = "cancel_local_driver_update";

// ---------------------------------------------------------------------------
// 7. Browser mocks use the exact IPC shape and drive the real flow
// ---------------------------------------------------------------------------

async function mockRun(scenario, steps) {
  mockLib.resetDriverUpdateMock();
  const invoke = async (cmd, args) => mockLib.driverUpdateMock(cmd, args, scenario);
  const flow = createDriverUpdateFlow({ invoke });
  await steps(flow);
  return flow;
}

test("every mock scenario returns the complete backend shape (except the malformed probe)", async () => {
  for (const scenario of [null, "restore_fail", "partial", "pending_reboot", "no_update", "ambiguous", "invalid_root", "stale"]) {
    mockLib.resetDriverUpdateMock();
    const check = mockLib.driverUpdateMock(CHECK, { deviceInstanceId: DEVICE, sdioRoot: ROOT_PATH }, scenario);
    assert.equal(lib.isDriverUpdateResponse(check), true, `check ${scenario}`);
    assert.deepEqual(Object.keys(check).sort(), rustFields("DriverUpdateResponse").sort());
    for (const restoreAction of ["create", "skip", "acknowledge_unavailable"]) {
      const sid = check.session_id ?? "mock-token";
      const r = mockLib.driverUpdateMock(INSTALL, { sessionId: sid, decision: "confirmed", restoreAction }, scenario);
      assert.equal(lib.isDriverUpdateResponse(r), true, `install ${scenario} ${restoreAction}`);
      assert.deepEqual(Object.keys(r).sort(), rustFields("DriverUpdateResponse").sort());
    }
    assert.equal(lib.isDriverUpdateResponse(mockLib.driverUpdateMock(CANCEL, { sessionId: "x" }, scenario)), true);
  }
  assert.equal(lib.isDriverUpdateResponse(mockLib.driverUpdateMock(CHECK, {}, "malformed")), false);
  assert.equal(mockLib.driverUpdateMock("get_system_info", {}, null), undefined);
});

test("default mock: ready, then installed oem42.inf without reboot", async () => {
  const flow = await mockRun(null, async (f) => {
    f.check(DEVICE, ROOT_PATH);
    await flush();
    assert.equal(f.getState().phase, "ready");
    f.chooseInstall("create");
    f.confirmInstall();
    await flush();
  });
  const v = flow.getState().result;
  assert.equal(v.status, "installed");
  assert.equal(v.publishedInf, "oem42.inf");
  assert.equal(v.rebootRequired, false);
});

test("restore_fail mock proves the second-confirmation flow end to end", async () => {
  const flow = await mockRun("restore_fail", async (f) => {
    f.check(DEVICE, ROOT_PATH);
    await flush();
    f.chooseInstall("create");
    f.confirmInstall();
    await flush();
    assert.equal(f.getState().phase, "confirm_ack_unavailable");
    f.confirmAcknowledge();
    await flush();
  });
  assert.equal(flow.getState().phase, "result");
  assert.equal(flow.getState().result.kind, "status");
  assert.equal(flow.getState().result.status, "installed");
});

test("partial, no_update, ambiguous, invalid_root, stale and malformed mocks reach the intended UI states", async () => {
  const expect = { partial: "driver_store_staged_device_install_failed", pending_reboot: "installed_pending_reboot", stale: "stale_preview" };
  for (const [scenario, status] of Object.entries(expect)) {
    const flow = await mockRun(scenario, async (f) => {
      f.check(DEVICE, ROOT_PATH);
      await flush();
      f.chooseInstall("create");
      f.confirmInstall();
      await flush();
    });
    assert.equal(flow.getState().result.status, status, scenario);
  }
  const checks = { no_update: "no_update", ambiguous: "ambiguous_local_update", invalid_root: "invalid_sdio_root" };
  for (const [scenario, status] of Object.entries(checks)) {
    const flow = await mockRun(scenario, async (f) => {
      f.check(DEVICE, ROOT_PATH);
      await flush();
    });
    assert.equal(flow.getState().result.status, status, scenario);
  }
  const bad = await mockRun("malformed", async (f) => {
    f.check(DEVICE, ROOT_PATH);
    await flush();
  });
  assert.equal(bad.getState().result.kind, "malformed");
});

test("restore_fail mock is stateful: only the issued retry token may acknowledge", () => {
  const install = (sessionId, restoreAction) =>
    mockLib.driverUpdateMock(INSTALL, { sessionId, decision: "confirmed", restoreAction }, "restore_fail");
  mockLib.resetDriverUpdateMock();
  const check = mockLib.driverUpdateMock(CHECK, {}, "restore_fail");
  // An acknowledgement with the ORIGINAL token (or any unknown token) is refused.
  assert.equal(install("never-issued", "acknowledge_unavailable").status, "session_not_found");
  // Production consumes the session BEFORE checking ack eligibility, so a rejected
  // acknowledgement burns the token and a fresh preview is needed afterwards.
  assert.equal(install(check.session_id, "acknowledge_unavailable").status, "restore_ack_not_allowed");
  assert.equal(install(check.session_id, "create").status, "session_not_found");
  // Create fails once and hands back a fresh retry token.
  const fresh = mockLib.driverUpdateMock(CHECK, {}, "restore_fail");
  const failed = install(fresh.session_id, "create");
  assert.equal(failed.status, "restore_point_failed");
  assert.ok(failed.retry_session_id && failed.retry_session_id !== fresh.session_id);
  // The consumed original token cannot be reused; the retry token works once.
  assert.equal(install(fresh.session_id, "create").status, "session_not_found");
  assert.equal(install(failed.retry_session_id, "acknowledge_unavailable").status, "installed");
  assert.equal(install(failed.retry_session_id, "acknowledge_unavailable").status, "session_not_found");
});

test("mock sessions are one-shot in every scenario", () => {
  mockLib.resetDriverUpdateMock();
  const check = mockLib.driverUpdateMock(CHECK, {}, null);
  const args = { sessionId: check.session_id, decision: "confirmed", restoreAction: "create" };
  assert.equal(mockLib.driverUpdateMock(INSTALL, args, null).status, "installed");
  assert.equal(mockLib.driverUpdateMock(INSTALL, args, null).status, "session_not_found");
  assert.equal(mockLib.driverUpdateMock(INSTALL, { ...args, sessionId: "bogus" }, null).status, "session_not_found");
});

// ---------------------------------------------------------------------------
// 8. Real-module SSR scenario matrix (substitute for browser automation)
//    Real DriverUpdateSection + ConfirmDialog through Vite SSR, driven by the
//    real 13b1 flow and the real browser mock module.
// ---------------------------------------------------------------------------

const { createServer } = await import("vite");
const { renderToStaticMarkup } = await import("react-dom/server");
const { createElement } = await import("react");
const vite = await createServer({
  root: UI,
  appType: "custom",
  logLevel: "silent",
  server: { middlewareMode: true, hmr: false },
});
const Section = (await vite.ssrLoadModule("/src/components/DriverUpdateSection.tsx")).default;
const NOTICE = lib.RESULT_NOTICE_COPY;
const COPY = lib.UPDATE_STATUS_COPY;
const html = (flow) =>
  renderToStaticMarkup(createElement(Section, { state: flow.getState(), flow, deviceName: "Fake Device" }));
const mockInvoke = (scenario) => async (cmd, args) => mockLib.driverUpdateMock(cmd, args, scenario);
const pending = () => new Promise(() => {});

async function reach(scenario, steps, invoke = mockInvoke(scenario)) {
  mockLib.resetDriverUpdateMock();
  const flow = createDriverUpdateFlow({ invoke });
  for (const step of steps) {
    if (step === "check") flow.check(DEVICE, ROOT_PATH);
    else if (step === "create" || step === "skip") flow.chooseInstall(step);
    else if (step === "confirm") flow.confirmInstall();
    else if (step === "ack") flow.confirmAcknowledge();
    await flush();
  }
  return flow;
}
const FULL = ["check", "create", "confirm"];

test("SSR: checking shows the exact progress copy as a status", async () => {
  const flow = await reach("x", ["check"], async () => pending());
  const out = html(flow);
  assert.match(out, /role="status"[^>]*>[\s\S]*?Checking local driver packs\.\.\./);
  assert.doesNotMatch(out, /role="dialog"/);
});

test("SSR: ready preview shows rank, expiry and the three explicit actions, no dialog", async () => {
  const out = html(await reach(null, ["check"]));
  assert.match(out, /Candidate rank: 0x00FF0000/);
  assert.match(out, /Current rank:[\s\S]*?0x01FF0000/);
  assert.match(out, /Lower Windows rank is better\./);
  assert.match(out, /expires in about 10 minutes/);
  assert.match(out, /DP_Fake_Chipset_01\.7z/);
  assert.match(out, /4\.5 MB/);
  assert.match(out, /Create restore point and install/);
  assert.match(out, /Install without restore point/);
  assert.match(out, /Cancel Preview/);
  assert.doesNotMatch(out, /role="dialog"/);
  assert.doesNotMatch(out, /mock-session|mock-retry|session/i, "token or session text leaked");
});

test("SSR: create confirmation is Yellow, skip confirmation is Red with the rollback warning", async () => {
  const create = html(await reach(null, ["check", "create"]));
  assert.match(create, /role="dialog"/);
  assert.match(create, /tier-yellow/);
  assert.match(create, /Install driver update/);
  assert.match(create, /create a System Restore point/);
  const skip = html(await reach(null, ["check", "skip"]));
  assert.match(skip, /tier-red/);
  assert.match(skip, /No restore point will be created\./);
  assert.match(skip, /automatic rollback is not available/);
  assert.match(skip, /revalidate the package and device before installation/);
});

test("SSR: restore failure raises the second Red acknowledgement and never an install result", async () => {
  const flow = await reach("restore_fail", FULL);
  const out = html(flow);
  assert.equal(flow.getState().phase, "confirm_ack_unavailable");
  assert.match(out, /tier-red/);
  assert.match(out, /Restore point could not be created/);
  assert.match(out, /NOT been staged or installed yet/);
  assert.match(out, /Continue without a restore point\?/);
  assert.doesNotMatch(out, /mock-retry/);
  const done = html(await reach("restore_fail", [...FULL, "ack"]));
  assert.match(done, /Driver installed/);
  assert.match(done, /oem42\.inf/);
});

test("SSR: installing is a non-dismissible status with no dialog and no enabled actions", async () => {
  const flow = await reach("x", ["check", "create"], async (cmd) =>
    cmd === CHECK ? mockLib.driverUpdateMock(CHECK, {}, null) : pending(),
  );
  flow.confirmInstall();
  await flush();
  assert.equal(flow.getState().phase, "installing");
  const out = html(flow);
  assert.match(out, /role="status"[^>]*>Re-checking package and installing driver\.\.\./);
  assert.doesNotMatch(out, /role="dialog"/);
  assert.doesNotMatch(out, /Cancel Preview|Create restore point|Install without restore point/);
});

test("SSR: partial staged outcome is a distinct alert with INF leaf, native error and a second cleanup alert", async () => {
  const out = html(await reach("partial", FULL));
  const copy = COPY.driver_store_staged_device_install_failed;
  assert.match(out, new RegExp(`tone-warning" role="alert"[^>]*>[\\s\\S]*?${copy.title}`));
  assert.match(out, /Published as <span class="mono">oem42\.inf<\/span>/);
  assert.match(out, /Windows error: 1603/);
  assert.match(out, new RegExp(NOTICE.cleanupWarning));
  assert.ok((out.match(/role="alert"/g) ?? []).length >= 2, "cleanup warning must be a separate alert");
  assert.doesNotMatch(out, /tone-success/);
});

test("SSR: pending reboot is a success status with a single restart wording", async () => {
  const out = html(await reach("pending_reboot", FULL));
  assert.match(out, /tone-success" role="status"/);
  assert.match(out, /Driver installed, restart required/);
  assert.equal((out.match(/Restart Windows to finish applying the driver\./g) ?? []).length, 0);
  assert.doesNotMatch(out, /tone-error|role="alert"/);
});

test("SSR: stale, no_update, ambiguous and invalid_root use the reviewed copy", async () => {
  const cases = [
    ["stale", FULL, "stale_preview"],
    ["no_update", ["check"], "no_update"],
    ["ambiguous", ["check"], "ambiguous_local_update"],
    ["invalid_root", ["check"], "invalid_sdio_root"],
  ];
  for (const [scenario, steps, status] of cases) {
    const out = html(await reach(scenario, steps));
    assert.ok(out.includes(COPY[status].title), `${scenario} title`);
    assert.ok(out.includes(COPY[status].body),`${scenario} body`);
    assert.match(out, /Dismiss/);
  }
});

test("SSR: malformed response fails closed with no preview or install authority", async () => {
  const flow = await reach("malformed", ["check"]);
  const out = html(flow);
  assert.match(out, new RegExp(NOTICE.malformed));
  assert.match(out, /role="alert"/);
  assert.doesNotMatch(out, /Create restore point|Install without restore point|Candidate rank/);
  flow.chooseInstall("create");
  flow.confirmInstall();
  assert.equal(flow.getState().phase, "result");
});

test("SSR: busy keeps the Ready preview and shows the retry notice", async () => {
  let installs = 0;
  const flow = await reach("x", FULL, async (cmd, args) => {
    if (cmd === INSTALL) {
      installs += 1;
      return { ...mockLib.driverUpdateMock(CANCEL, {}, null), status: "busy", success: false };
    }
    return mockLib.driverUpdateMock(cmd, args, null);
  });
  assert.equal(installs, 1);
  assert.equal(flow.getState().phase, "ready");
  const out = html(flow);
  assert.match(out, new RegExp(NOTICE.busyRetry));
  assert.match(out, /Candidate rank/);
});

test("SSR: the backend message, raw status ids and the postcondition are rendered from UI-owned copy only", async () => {
  const flow = await reach("x", FULL, async (cmd, args) => {
    const base = mockLib.driverUpdateMock(cmd, args, null);
    return cmd === INSTALL
      ? {
          ...base,
          status: "installed_source_invalidated",
          success: false,
          partial: true,
          message: "SECRET-BACKEND-MESSAGE C:\\Secret\\Path",
          postcondition_observed: true,
          published_inf: "C:\\Windows\\System32\\DriverStore\\FileRepository\\oem9.inf",
        }
      : base;
  });
  const out = html(flow);
  assert.doesNotMatch(out, /SECRET-BACKEND-MESSAGE|Secret|FileRepository|installed_source_invalidated/);
  assert.match(out, /Expected driver observed: Yes/);
  assert.match(out, /oem9\.inf/);
});

test.after(() => vite.close());

// ---------------------------------------------------------------------------
// 9. Structural gates on the committed UI source
// ---------------------------------------------------------------------------

const SRC = {
  panel: stripComments(await read("src/components/DriversPanel.tsx", UI)),
  section: stripComments(await read("src/components/DriverUpdateSection.tsx", UI)),
  flow: stripComments(await read("src/lib/driverUpdateFlow.ts", UI)),
  copy: stripComments(await read("src/lib/driverUpdate.ts", UI)),
  mock: stripComments(await read("src/lib/driverUpdateMock.ts", UI)),
  tauri: stripComments(await read("src/lib/tauri.ts", UI)),
  registry: await read("src/components/panelRegistry.ts", UI),
};

test("driver-update code never persists the root or session authority", () => {
  for (const [name, src] of Object.entries({ panel: SRC.panel, section: SRC.section, flow: SRC.flow, copy: SRC.copy, mock: SRC.mock })) {
    assert.doesNotMatch(src, /localStorage|sessionStorage|indexedDB/i, name);
    assert.doesNotMatch(src, /document\.cookie/, name);
  }
  for (const [name, src] of Object.entries({ panel: SRC.panel, section: SRC.section, flow: SRC.flow, copy: SRC.copy })) {
    assert.doesNotMatch(src, /\blocation\b|history\.(push|replace)State/, name);
  }
});

test("neither the root, nor device ids, nor tokens are logged", () => {
  for (const [name, src] of Object.entries({ panel: SRC.panel, section: SRC.section, flow: SRC.flow, copy: SRC.copy, mock: SRC.mock })) {
    assert.doesNotMatch(src, /console\./, name);
    assert.doesNotMatch(src, /recordUiEvent/, name);
  }
  const tauriInvoke = SRC.tauri.slice(SRC.tauri.indexOf("export async function invoke"));
  assert.doesNotMatch(tauriInvoke, /JSON\.stringify\(args\)|errorText\(args\)/, "invoke logger must not record args");
});

test("rendering code never touches session tokens", () => {
  assert.doesNotMatch(SRC.panel, /session_?id|retry_?session/i, "DriversPanel");
  assert.doesNotMatch(SRC.section, /session_?id|retry_?session/i, "DriverUpdateSection");
});

test("the section never reads the backend message and renders UI-owned copy", () => {
  assert.doesNotMatch(SRC.section, /\.message\b/);
  assert.doesNotMatch(SRC.flow, /\.message\b|["']message["']/);
  assert.match(SRC.section, /UPDATE_STATUS_COPY/);
});

test("the flow has a single install call site and no automatic retry machinery", () => {
  const installCalls = SRC.flow.match(/install_local_driver_update/g) ?? [];
  assert.equal(installCalls.length, 1, "install must be submitted from exactly one place");
  assert.doesNotMatch(SRC.flow, /setTimeout|setInterval|retry\(|while\s*\(|for\s*\(/);
  assert.doesNotMatch(SRC.section + SRC.panel, /setTimeout|setInterval/);
});

test("restore choices: yellow primary confirmation, red skip and red acknowledgement", () => {
  assert.match(SRC.section, /Create restore point and install/);
  assert.match(SRC.section, /Install without restore point/);
  assert.match(SRC.section, /Cancel Preview/);
  assert.match(SRC.section, /safetyTier="Yellow"/);
  assert.equal((SRC.section.match(/safetyTier="Red"/g) ?? []).length, 2);
  assert.match(SRC.section, /Restore point could not be created/);
  assert.match(SRC.section, /Continue without a restore point\?/);
  assert.match(SRC.section, /ConfirmDialog/);
});

test("dialogs close and controls lock while installing", () => {
  assert.match(SRC.section, /open=\{state\.phase === "confirm_create"\}/);
  assert.match(SRC.section, /open=\{state\.phase === "confirm_skip"\}/);
  assert.match(SRC.section, /open=\{state\.phase === "confirm_ack_unavailable"\}/);
  assert.match(SRC.section, /role="status"/);
  assert.match(SRC.section, /role="alert"/);
});

test("DriversPanel wires abandon on rescan and unmount, a root input, and never auto-runs an update", () => {
  assert.ok((SRC.panel.match(/flow\.abandon\(\)/g) ?? []).length >= 2, "abandon on unmount and rescan");
  assert.match(SRC.panel, /maxLength=\{1024\}/);
  assert.match(SRC.panel, /Local SDIO folder/);
  assert.match(SRC.panel, /isRootEditable/);
  const fetchBody = SRC.panel.slice(SRC.panel.indexOf("const fetchReport"), SRC.panel.indexOf("useEffect("));
  assert.ok(fetchBody.length > 50);
  assert.doesNotMatch(fetchBody, /\.check\(|install|flow\./, "inventory refresh must not run updates");
  assert.doesNotMatch(SRC.panel, /does not install or modify anything/);
  assert.match(SRC.panel, /explicitly\s+confirm/);
});

test("the root is held only in React state and the check sends nothing but id and root", () => {
  assert.match(SRC.panel, /useState\(""\)/);
  assert.doesNotMatch(SRC.flow, /hardware_ids|compatible_ids|rank|installed_inf/);
  assert.doesNotMatch(SRC.section + SRC.panel, /flow\.check\([^)]*hardware|flow\.check\([^)]*compatible/);
});

test("DriversPanel stays lazy-loaded and is not imported by the startup graph", async () => {
  assert.match(SRC.registry, /drivers:\s*\(\)\s*=>\s*import\("\.\/DriversPanel"\)/);
  for (const rel of ["src/main.tsx", "src/App.tsx"]) {
    const src = await read(rel, UI).catch(() => "");
    assert.doesNotMatch(src, /from ["'].*DriversPanel/, rel);
    assert.doesNotMatch(src, /from ["'].*driverUpdate/, rel);
  }
});

test("the mock is only reachable from the browser (non-Tauri) path", () => {
  const i = SRC.tauri.indexOf("setTimeout(r, 120 + Math.random()");
  assert.ok(i > 0);
  assert.match(SRC.tauri.slice(i), /driverUpdateMock/);
  assert.doesNotMatch(SRC.tauri.slice(0, i), /driverUpdateMock\(/);
});

test("Rescan only abandons the held preview and re-reads the inventory (never checks or installs)", () => {
  const start = SRC.panel.indexOf("const rescan");
  const body = SRC.panel.slice(start, SRC.panel.indexOf("};", start));
  assert.ok(body.length > 20, "rescan handler not found");
  assert.match(body, /flow\.abandon\(\)/);
  assert.match(body, /fetchReport\(\)/);
  assert.doesNotMatch(body, /\.check\(|chooseInstall|confirm|check_local_driver_update|install_local_driver_update/);
  assert.match(SRC.panel, /disabled=\{isOperationActive\(updateState\)\}/);
});

test("the post-outcome callback only runs the silent read-only inventory refresh", () => {
  const m = SRC.panel.match(/flow\.onSystemOutcome\(([\s\S]*?)\)\);/);
  assert.ok(m, "onSystemOutcome subscription not found");
  assert.match(m[1], /fetchReport\(true\)/);
  assert.doesNotMatch(m[1], /\.check\(|abandon|cancelPreview|install|confirm/);
});

test("a failed background refresh is surfaced without clearing the update result", () => {
  assert.match(SRC.panel, /Inventory refresh failed/);
  const fetchBody = SRC.panel.slice(SRC.panel.indexOf("const fetchReport"), SRC.panel.indexOf("useEffect("));
  assert.doesNotMatch(fetchBody, /silent[^;]*setReport\(null\)|silent[^;]*setError\(/);
});

test("there is one flow per panel and the check sends only the instance id and the root", () => {
  assert.equal((SRC.panel.match(/createDriverUpdateFlow\(/g) ?? []).length, 1);
  assert.equal((SRC.panel.match(/flow\.check\(/g) ?? []).length, 1);
  assert.match(SRC.panel, /flow\.check\(device\.instance_id, sdioRoot\)/);
  assert.match(SRC.panel, /disabled=\{!isRootEditable\(updateState\)\}/);
  assert.match(SRC.panel, /inventoryUsable[\s\S]*?report\.complete[\s\S]*?!report\.degraded/);
  assert.match(SRC.panel, /canStartCheck\(updateState\)/);
});

test("no reboot, rollback, download or raw-response affordances exist in the presentation code", () => {
  for (const [name, src] of Object.entries({ panel: SRC.panel, section: SRC.section })) {
    assert.doesNotMatch(src, /Restart Now|shutdown|Rollback driver|Uninstall|Download|torrent|Open SDIO/i, name);
    assert.doesNotMatch(src, /DriverUpdateResponse|isDriverUpdateResponse/, name);
  }
});

test("the section routes every action through the reviewed flow methods", () => {
  // Ready buttons only choose; only the dialogs confirm. No button installs directly.
  assert.equal((SRC.section.match(/confirmInstall/g) ?? []).length, 2, "confirmInstall only as the two dialog confirms");
  assert.equal((SRC.section.match(/confirmAcknowledge/g) ?? []).length, 1);
  assert.match(SRC.section, /onClick=\{\(\) => flow\.chooseInstall\("create"\)\}[\s\S]{0,120}Create restore point and install/);
  assert.match(SRC.section, /onClick=\{\(\) => flow\.chooseInstall\("skip"\)\}[\s\S]{0,120}Install without restore point/);
  assert.match(SRC.section, /onClick=\{flow\.cancelPreview\}[\s\S]{0,120}Cancel Preview/);
  assert.match(SRC.section, /onConfirm=\{flow\.confirmAcknowledge\}\s+onCancel=\{flow\.declineAcknowledge\}/);
  assert.equal((SRC.section.match(/onCancel=\{flow\.declineInstall\}/g) ?? []).length, 2);
  assert.match(SRC.section, /onDismiss=\{flow\.dismissResult\}/);
});

test("the panel releases a held preview on unmount", () => {
  assert.match(SRC.panel, /useEffect\(\(\) => \(\) => flow\.abandon\(\), \[flow\]\)/);
});

test("SSR: create-and-install is the only primary action; skip is the cautioned secondary", async () => {
  const out = html(await reach(null, ["check"]));
  assert.match(out, /drivers-update-btn primary"[^>]*>Create restore point and install/);
  assert.match(out, /drivers-update-btn caution"[^>]*>Install without restore point/);
  assert.equal((out.match(/btn primary/g) ?? []).length, 1);
});

// ---------------------------------------------------------------------------
// 10. Unmount while an install is in flight (challenge-1 finding)
// ---------------------------------------------------------------------------

function deferredInstallFlow() {
  mockLib.resetDriverUpdateMock();
  const calls = [];
  let settle;
  const invoke = (cmd, args) => {
    calls.push({ cmd, args });
    if (cmd === INSTALL) return new Promise((resolve) => (settle = resolve));
    return Promise.resolve(mockLib.driverUpdateMock(cmd, args, null));
  };
  return { calls, settle: (raw) => settle(raw), flow: createDriverUpdateFlow({ invoke }) };
}
const installing = async (ctx) => {
  ctx.flow.check(DEVICE, ROOT_PATH);
  await flush();
  ctx.flow.chooseInstall("create");
  ctx.flow.confirmInstall();
  await flush();
  assert.equal(ctx.flow.getState().phase, "installing");
};
const cancelsOf = (ctx) => ctx.calls.filter((c) => c.cmd === CANCEL).map((c) => c.args.sessionId);

test("abandon during an install never cancels it, but a retry token that arrives afterwards is released", async () => {
  const ctx = deferredInstallFlow();
  await installing(ctx);
  ctx.flow.abandon(); // panel unmounted mid-install
  assert.equal(ctx.flow.getState().phase, "installing");
  assert.deepEqual(cancelsOf(ctx), [], "an active install must not be cancelled");
  ctx.settle({
    ...mockLib.driverUpdateMock(CANCEL, {}, null),
    status: "restore_point_failed",
    retry_session_id: "retry-after-unmount",
  });
  await flush();
  assert.deepEqual(cancelsOf(ctx), ["retry-after-unmount"], "stranded retry session must be released");
  assert.notEqual(ctx.flow.getState().phase, "confirm_ack_unavailable");
  ctx.flow.confirmAcknowledge();
  assert.equal(ctx.calls.filter((c) => c.cmd === INSTALL).length, 1, "no further install may be submitted");
});

test("abandon during an install releases a session kept by a busy response", async () => {
  const ctx = deferredInstallFlow();
  await installing(ctx);
  const token = ctx.calls.find((c) => c.cmd === INSTALL).args.sessionId;
  ctx.flow.abandon();
  ctx.settle({ ...mockLib.driverUpdateMock(CANCEL, {}, null), status: "busy", success: false });
  await flush();
  assert.deepEqual(cancelsOf(ctx), [token]);
  assert.equal(ctx.flow.getState().phase, "idle");
});

test("abandon during an install lets a terminal result settle without any cancel", async () => {
  const ctx = deferredInstallFlow();
  await installing(ctx);
  ctx.flow.abandon();
  ctx.settle({ ...mockLib.driverUpdateMock(CANCEL, {}, null), status: "installed", success: true });
  await flush();
  assert.deepEqual(cancelsOf(ctx), []);
  assert.equal(ctx.flow.getState().phase, "result");
});

test("without an unmount, restore failure still reaches the acknowledgement step (default path)", async () => {
  const ctx = deferredInstallFlow();
  await installing(ctx);
  ctx.settle({
    ...mockLib.driverUpdateMock(CANCEL, {}, null),
    status: "restore_point_failed",
    retry_session_id: "retry-normal",
  });
  await flush();
  assert.equal(ctx.flow.getState().phase, "confirm_ack_unavailable");
  assert.deepEqual(cancelsOf(ctx), []);
});

test("mock install validates its authorization arguments like the IPC contract", () => {
  const open = () => {
    mockLib.resetDriverUpdateMock();
    return mockLib.driverUpdateMock(CHECK, {}, null).session_id;
  };
  const install = (args) => mockLib.driverUpdateMock(INSTALL, args, null);
  // Missing/invalid enums are rejected BEFORE the token is consumed.
  const sid = open();
  assert.equal(install({ sessionId: sid, restoreAction: "create" }).status, "invalid_request", "missing decision");
  assert.equal(install({ sessionId: sid, decision: "yes", restoreAction: "create" }).status, "invalid_request");
  assert.equal(install({ sessionId: sid, decision: "confirmed" }).status, "invalid_request", "missing restoreAction");
  assert.equal(install({ sessionId: sid, decision: "confirmed", restoreAction: "nuke" }).status, "invalid_request");
  assert.equal(install({ sessionId: sid, decision: "confirmed", restoreAction: "create" }).status, "installed", "token survived validation");
  // A cancelled decision consumes the token and never installs.
  const sid2 = open();
  const cancelled = install({ sessionId: sid2, decision: "cancelled", restoreAction: "create" });
  assert.equal(cancelled.status, "cancelled");
  assert.equal(cancelled.published_inf, null);
  assert.equal(install({ sessionId: sid2, decision: "confirmed", restoreAction: "create" }).status, "session_not_found");
});
