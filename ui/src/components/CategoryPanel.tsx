import type { View } from "../App";
import "./CategoryPanel.css";

import PerformancePanel from "./PerformancePanel";
import VisualPanel from "./VisualPanel";
import PrivacyPanel from "./PrivacyPanel";
import ServicesPanel from "./ServicesPanel";
import StartupPanel from "./StartupPanel";
import CleanupPanel from "./CleanupPanel";
import PowerPanel from "./PowerPanel";
import HealthPanel from "./HealthPanel";
import EventLogPanel from "./EventLogPanel";
import BsodPanel from "./BsodPanel";
import DriversPanel from "./DriversPanel";
import NetDiagPanel from "./NetDiagPanel";
import UpdatesPanel from "./UpdatesPanel";
import UninstallPanel from "./UninstallPanel";
import SysInfoPanel from "./SysInfoPanel";
import TempsPanel from "./TempsPanel";
import SfcPanel from "./SfcPanel";
import RestorePanel from "./RestorePanel";
import HistoryPanel from "./HistoryPanel";

interface Props {
  view: View;
  onBack: () => void;
}

const VIEW_META: Record<string, { title: string; description: string }> = {
  performance: {
    title: "Performance Tweaks",
    description:
      "Registry-based optimizations for filesystem, memory, CPU scheduling, and boot — all reversible.",
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
  power: {
    title: "Power Plan",
    description: "Switch power plans and adjust sleep/hibernate settings.",
  },
  health: {
    title: "System Health",
    description: "Quick triage - disk, RAM, CPU, battery, SMART status.",
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
  drivers: {
    title: "Driver Auditor",
    description: "List all drivers, flag outdated or unsigned ones.",
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
      "Completely remove programs and all leftover files, registry keys, services, and scheduled tasks.",
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
  history: {
    title: "Change History",
    description: "View and undo all changes made by the optimizer.",
  },
};

const PANELS: Record<string, React.ComponentType> = {
  performance: PerformancePanel,
  visual: VisualPanel,
  privacy: PrivacyPanel,
  services: ServicesPanel,
  startup: StartupPanel,
  cleanup: CleanupPanel,
  power: PowerPanel,
  health: HealthPanel,
  eventlog: EventLogPanel,
  bsod: BsodPanel,
  drivers: DriversPanel,
  netdiag: NetDiagPanel,
  updates: UpdatesPanel,
  uninstall: UninstallPanel,
  sysinfo: SysInfoPanel,
  temps: TempsPanel,
  sfc: SfcPanel,
  restore: RestorePanel,
  history: HistoryPanel,
};

export default function CategoryPanel({ view, onBack }: Props) {
  const meta = VIEW_META[view] || { title: view, description: "" };
  const PanelComponent = PANELS[view];

  return (
    <div className="category-panel">
      <button className="back-btn" onClick={onBack}>
        &larr; Dashboard
      </button>
      <div className="panel-header">
        <h1>{meta.title}</h1>
        <p>{meta.description}</p>
      </div>

      {PanelComponent ? (
        <PanelComponent />
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
