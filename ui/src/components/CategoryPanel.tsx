import { lazy, Suspense, type ComponentType, type LazyExoticComponent } from "react";
import type { View } from "../App";
import Icon from "./Icon";
import "./CategoryPanel.css";
import { PANEL_LOADERS } from "./panelRegistry";

interface Props {
  view: View;
  onBack: () => void;
}

const VIEW_META: Record<string, { title: string; description: string }> = {
  performance: {
    title: "Performance Tweaks",
    description:
      "Registry-based optimizations for filesystem, memory, CPU scheduling, and boot -all reversible.",
  },
  visual: {
    title: "Visual Effects",
    description:
      "Toggle cosmetic effects that consume GPU/CPU resources. All changes are instantly reversible.",
  },
  privacy: {
    title: "Privacy & Telemetry",
    description:
      "Control Windows data collection, advertising, and tracking features.",
  },
  services: {
    title: "Service Optimizer",
    description:
      "Disable unnecessary background services to free RAM and CPU.",
  },
  startup: {
    title: "Startup Manager",
    description: "Control what programs run at boot.",
  },
  cleanup: {
    title: "Disk Cleanup",
    description:
      "Remove temp files, caches, and Windows bloat to free disk space.",
  },
  bloatware: {
    title: "Bloatware Remover",
    description:
      "Uninstall preinstalled Microsoft, OEM, and sponsored apps you don't use.",
  },
  power: {
    title: "Power Plan",
    description: "Switch power plans and adjust sleep/hibernate settings.",
  },
  health: {
    title: "System Health",
    description: "Quick triage - disk, RAM, CPU, SMART status.",
  },
  eventlog: {
    title: "Event Log Analyzer",
    description:
      "Filter and analyze Critical/Error/Warning events from System and Application logs.",
  },
  bsod: {
    title: "BSOD Analyzer",
    description:
      "Read minidump files and decode blue screen bug check codes.",
  },
  netdiag: {
    title: "Network Diagnostics",
    description:
      "DNS, ping, traceroute, Wi-Fi signal, adapter health checks.",
  },
  updates: {
    title: "Windows Update Status",
    description:
      "Pending updates, CBS log errors, component store health.",
  },
  uninstall: {
    title: "Deep Uninstaller",
    description:
      "Run a program's standard uninstaller, then find and optionally remove leftover application folders.",
  },
  sysinfo: {
    title: "System Information",
    description:
      "Detailed hardware and software specs -CPU, RAM, motherboard, GPU, storage, audio, and network.",
  },
  temps: {
    title: "Temperatures",
    description:
      "Monitor CPU, GPU, and disk temperatures in real time.",
  },
  sfc: {
    title: "DISM / SFC Repair",
    description:
      "Scan and repair Windows system file corruption using DISM and SFC.",
  },
  restore: {
    title: "System Restore",
    description:
      "Create restore points before optimizing and roll back Windows if anything goes wrong.",
  },
  security: {
    title: "Security Scan",
    description: "Windows Defender status and heuristic scan for suspicious activity, persistence, and integrity issues.",
  },
  runtimes: {
    title: "Installed Runtimes",
    description: ".NET, Visual C++ Redistributables, DirectX, and Java installations.",
  },
  diskhealth: {
    title: "Disk Health",
    description: "SMART health monitoring, disk space breakdown, and chkdsk tools.",
  },
  diff: {
    title: "What Changed",
    description: "Compare the current machine state to the last visit's snapshot.",
  },
  history: {
    title: "Change History",
    description: "View and undo all changes made by the optimizer.",
  },
  tools: {
    title: "Tools",
    description: "Trusted third-party stress-testing and diagnostic utilities. Links open the official vendor site in your browser.",
  },
};

const PANELS: Record<string, LazyExoticComponent<ComponentType>> =
  Object.fromEntries(
    Object.entries(PANEL_LOADERS).map(([view, load]) => [view, lazy(load)]),
  );

export default function CategoryPanel({ view, onBack }: Props) {
  const meta = VIEW_META[view] || { title: view, description: "" };
  const PanelComponent = PANELS[view];

  return (
    <div className="category-panel">
      <div className="panel-head">
        <button className="back-btn" onClick={onBack} aria-label="Back">
          <Icon name="back" size={18} />
        </button>
        <span className="panel-icon"><Icon name={view} size={20} /></span>
        <div className="panel-titles">
          <h1>{meta.title}</h1>
          <p>{meta.description}</p>
        </div>
      </div>

      {PanelComponent ? (
        <Suspense
          fallback={
            <div className="panel-loading" role="status">
              Loading {meta.title}...
            </div>
          }
        >
          <PanelComponent />
        </Suspense>
      ) : (
        <div className="coming-soon">
          <div className="coming-soon-icon">?</div>
          <h2>Unknown module</h2>
          <p>This view does not have a panel yet.</p>
        </div>
      )}
    </div>
  );
}
