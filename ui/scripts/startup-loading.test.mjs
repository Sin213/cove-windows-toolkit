import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

const DIST_ASSETS = join(process.cwd(), "dist", "assets");
const PANEL_NAMES = [
  "PerformancePanel",
  "VisualPanel",
  "PrivacyPanel",
  "ServicesPanel",
  "StartupPanel",
  "CleanupPanel",
  "BloatwarePanel",
  "PowerPanel",
  "HealthPanel",
  "EventLogPanel",
  "BsodPanel",
  "NetDiagPanel",
  "UpdatesPanel",
  "UninstallPanel",
  "SysInfoPanel",
  "TempsPanel",
  "SfcPanel",
  "RestorePanel",
  "HistoryPanel",
  "DiffPanel",
  "SecurityPanel",
  "RuntimesPanel",
  "DiskHealthPanel",
  "ToolsPanel",
];

async function builtAssets() {
  return readdir(DIST_ASSETS);
}

test("startup entry keeps feature panel implementations out of the initial chunk", async () => {
  const assets = await builtAssets();
  const entryName = assets.find((name) => /^index-[^/]+\.js$/.test(name));
  assert.ok(entryName, "vite did not emit an application entry chunk");

  const entry = await readFile(join(DIST_ASSETS, entryName), "utf8");
  const entryBytes = Buffer.byteLength(entry);

  // The pre-split entry was 379.31 kB. Leave headroom for normal app growth
  // while failing if the feature panels are accidentally made eager again.
  assert.ok(
    entryBytes < 330_000,
    `initial chunk grew to ${(entryBytes / 1024).toFixed(2)} kB; feature panels may be eager`,
  );
  assert.doesNotMatch(
    entry,
    /startup-summary/,
    "startup panel implementation leaked into the initial chunk",
  );

  for (const panelName of PANEL_NAMES) {
    assert.ok(
      assets.some((name) => name.startsWith(`${panelName}-`) && name.endsWith(".js")),
      `missing lazy chunk for ${panelName}`,
    );
  }
});

test("startup panel is emitted as a route chunk with its implementation", async () => {
  const assets = await builtAssets();
  const startupChunk = assets.find(
    (name) => name.startsWith("StartupPanel-") && name.endsWith(".js"),
  );
  assert.ok(startupChunk, "vite did not emit the startup route chunk");

  const source = await readFile(join(DIST_ASSETS, startupChunk), "utf8");
  assert.match(source, /get_startup_items/);
});
