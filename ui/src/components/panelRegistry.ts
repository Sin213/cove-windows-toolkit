import type { ComponentType } from "react";
import type { View } from "../App";

/**
 * A feature panel is loaded only when its route is visited. Keep these imports
 * explicit so Vite can create a stable, independently cacheable chunk for
 * every panel instead of pulling every feature into the startup bundle.
 */
export type PanelView = Exclude<View, "dashboard">;
export type PanelLoader = () => Promise<{ default: ComponentType }>;

export const PANEL_LOADERS = {
  performance: () => import("./PerformancePanel"),
  visual: () => import("./VisualPanel"),
  privacy: () => import("./PrivacyPanel"),
  services: () => import("./ServicesPanel"),
  startup: () => import("./StartupPanel"),
  cleanup: () => import("./CleanupPanel"),
  bloatware: () => import("./BloatwarePanel"),
  power: () => import("./PowerPanel"),
  health: () => import("./HealthPanel"),
  eventlog: () => import("./EventLogPanel"),
  bsod: () => import("./BsodPanel"),
  netdiag: () => import("./NetDiagPanel"),
  updates: () => import("./UpdatesPanel"),
  uninstall: () => import("./UninstallPanel"),
  sysinfo: () => import("./SysInfoPanel"),
  temps: () => import("./TempsPanel"),
  sfc: () => import("./SfcPanel"),
  restore: () => import("./RestorePanel"),
  history: () => import("./HistoryPanel"),
  diff: () => import("./DiffPanel"),
  security: () => import("./SecurityPanel"),
  runtimes: () => import("./RuntimesPanel"),
  diskhealth: () => import("./DiskHealthPanel"),
  tools: () => import("./ToolsPanel"),
} satisfies Record<PanelView, PanelLoader>;
