import { useEffect, useState } from "react";
import type { View } from "../App";
import { invoke } from "../lib/tauri";
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
  { id: "performance", label: "Performance", icon: "⏱", section: "optimize" },
  { id: "visual", label: "Visual Effects", icon: "◑", section: "optimize" },
  { id: "privacy", label: "Privacy", icon: "◉", section: "optimize" },
  { id: "services", label: "Services", icon: "⚙", section: "optimize" },
  { id: "startup", label: "Startup", icon: "▶", section: "optimize" },
  { id: "cleanup", label: "Disk Cleanup", icon: "⊘", section: "optimize" },
  { id: "bloatware", label: "Bloatware", icon: "🗑", section: "optimize" },
  { id: "power", label: "Power Plan", icon: "⚡", section: "optimize" },
  { id: "health", label: "System Health", icon: "♥", section: "diagnose" },
  { id: "temps", label: "Temperatures", icon: "🌡", section: "diagnose" },
  { id: "eventlog", label: "Event Logs", icon: "☰", section: "diagnose" },
  { id: "bsod", label: "BSOD Analyzer", icon: "⬛", section: "diagnose" },
  { id: "netdiag", label: "Net Diagnostics", icon: "⇆", section: "diagnose" },
  { id: "updates", label: "Windows Update", icon: "↻", section: "diagnose" },
  { id: "security", label: "Security Scan", icon: "🔒", section: "diagnose" },
  { id: "runtimes", label: "Runtimes", icon: "⊞", section: "diagnose" },
  { id: "diskhealth", label: "Disk Health", icon: "💾", section: "diagnose" },
  { id: "uninstall", label: "Uninstaller", icon: "✖", section: "system" },
  { id: "sysinfo", label: "System Info", icon: "ℹ", section: "system" },
  { id: "sfc", label: "DISM / SFC", icon: "⛏", section: "system" },
  { id: "restore", label: "System Restore", icon: "🛡", section: "system" },
  { id: "diff", label: "What Changed", icon: "⇄", section: "system" },
  { id: "history", label: "Change History", icon: "↺", section: "system" },
];

export default function Sidebar({ current, onNavigate }: Props) {
  const [isAdmin, setIsAdmin] = useState<boolean | null>(null);

  useEffect(() => {
    invoke<{ is_admin: boolean }>("check_admin_status")
      .then((r) => setIsAdmin(r.is_admin))
      .catch(() => setIsAdmin(null));
  }, []);

  const sections = [
    { key: "system" as const, label: "" },
    { key: "optimize" as const, label: "OPTIMIZE" },
    { key: "diagnose" as const, label: "DIAGNOSE" },
  ];

  return (
    <nav className="sidebar">
      {isAdmin !== null && (
        <div className={`admin-badge ${isAdmin ? "admin-yes" : "admin-no"}`}>
          <span className="admin-icon">{isAdmin ? "🛡" : "⚠"}</span>
          <span className="admin-label">
            {isAdmin ? "Admin" : "Not Admin"}
          </span>
        </div>
      )}
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
