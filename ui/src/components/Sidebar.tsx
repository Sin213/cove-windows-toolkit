import type { View } from "../App";
import "./Sidebar.css";

interface Props {
  current: View;
  onNavigate: (v: View) => void;
}

interface NavItem {
  id: View;
  label: string;
  icon: string;
  section: "optimize" | "diagnose" | "system";
}

const NAV_ITEMS: NavItem[] = [
  { id: "dashboard", label: "Dashboard", icon: "⌂", section: "system" },
  { id: "visual", label: "Visual Effects", icon: "◑", section: "optimize" },
  { id: "privacy", label: "Privacy", icon: "◉", section: "optimize" },
  { id: "services", label: "Services", icon: "⚙", section: "optimize" },
  { id: "startup", label: "Startup", icon: "▶", section: "optimize" },
  { id: "cleanup", label: "Disk Cleanup", icon: "⊘", section: "optimize" },
  { id: "power", label: "Power Plan", icon: "⚡", section: "optimize" },
  { id: "health", label: "System Health", icon: "♥", section: "diagnose" },
  { id: "eventlog", label: "Event Logs", icon: "☰", section: "diagnose" },
  { id: "bsod", label: "BSOD Analyzer", icon: "⬛", section: "diagnose" },
  { id: "drivers", label: "Drivers", icon: "⊞", section: "diagnose" },
  { id: "netdiag", label: "Net Diagnostics", icon: "⇆", section: "diagnose" },
  { id: "updates", label: "Windows Update", icon: "↻", section: "diagnose" },
  { id: "uninstall", label: "Uninstaller", icon: "✖", section: "system" },
  { id: "sysinfo", label: "System Info", icon: "ℹ", section: "system" },
  { id: "temps", label: "Temperatures", icon: "🌡", section: "system" },
  { id: "sfc", label: "DISM / SFC", icon: "⛏", section: "system" },
  { id: "restore", label: "System Restore", icon: "🛡", section: "system" },
  { id: "history", label: "Change History", icon: "↺", section: "system" },
];

export default function Sidebar({ current, onNavigate }: Props) {
  const sections = [
    { key: "system" as const, label: "" },
    { key: "optimize" as const, label: "OPTIMIZE" },
    { key: "diagnose" as const, label: "DIAGNOSE" },
  ];

  return (
    <nav className="sidebar">
      <div className="sidebar-header">
        <span className="logo">◆</span>
        <span className="title">Cove</span>
      </div>
      {sections.map((section) => {
        const items = NAV_ITEMS.filter((i) => i.section === section.key);
        if (!items.length) return null;
        return (
          <div key={section.key} className="nav-section">
            {section.label && (
              <div className="nav-section-label">{section.label}</div>
            )}
            {items.map((item) => (
              <button
                key={item.id}
                className={`nav-item ${current === item.id ? "active" : ""}`}
                onClick={() => onNavigate(item.id)}
              >
                <span className="nav-icon">{item.icon}</span>
                <span className="nav-label">{item.label}</span>
              </button>
            ))}
          </div>
        );
      })}
    </nav>
  );
}
