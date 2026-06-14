/* ============================================================
   Cove icon set - consistent 1.6px stroke line icons.
   <Icon name="..." size={18} />
   Ported from the Cove redesign handoff (icons.jsx).
   ============================================================ */
import type { CSSProperties, ReactNode } from "react";

const ICON_PATHS: Record<string, ReactNode> = {
  // System / shell
  dashboard: (
    <>
      <rect x="3" y="3" width="7" height="7" rx="1.5" />
      <rect x="14" y="3" width="7" height="7" rx="1.5" />
      <rect x="3" y="14" width="7" height="7" rx="1.5" />
      <rect x="14" y="14" width="7" height="7" rx="1.5" />
    </>
  ),
  uninstall: (
    <>
      <rect x="4" y="4" width="16" height="16" rx="3" />
      <path d="M9 9l6 6M15 9l-6 6" />
    </>
  ),
  sysinfo: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v5M12 7.5h.01" />
    </>
  ),
  sfc: <path d="M14.7 6.3a4 4 0 0 0-5.2 5.2L4 17v3h3l5.5-5.5a4 4 0 0 0 5.2-5.2l-2.6 2.6-2.2-.4-.4-2.2z" />,
  restore: (
    <>
      <path d="M3 12a9 9 0 1 0 3-6.7" />
      <path d="M3 4v4h4" />
      <path d="M12 8v4l3 2" />
    </>
  ),
  diff: (
    <>
      <circle cx="6" cy="6" r="2.4" />
      <circle cx="18" cy="18" r="2.4" />
      <path d="M8.4 6H15a2.5 2.5 0 0 1 2.5 2.5v7M6 8.4V18" />
    </>
  ),
  history: (
    <>
      <path d="M3 3v5h5" />
      <path d="M3.5 9a9 9 0 1 1-1 5.5" />
      <path d="M12 8v4l3 2" />
    </>
  ),
  // Optimize
  performance: (
    <>
      <path d="M12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4z" />
      <path d="M12 12l4-3" />
      <path d="M5.5 18a9 9 0 1 1 13 0" />
    </>
  ),
  visual: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 3a9 9 0 0 1 0 18z" fill="currentColor" stroke="none" />
    </>
  ),
  privacy: (
    <>
      <path d="M12 3l7 3v5c0 4.5-3 7.7-7 9-4-1.3-7-4.5-7-9V6z" />
      <circle cx="12" cy="11" r="2.2" />
      <path d="M12 13.2V16" />
    </>
  ),
  services: (
    <>
      <circle cx="12" cy="12" r="3" />
      <path d="M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1" />
    </>
  ),
  startup: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M10 8.5l5 3.5-5 3.5z" fill="currentColor" stroke="none" />
    </>
  ),
  cleanup: (
    <>
      <path d="M5 8h14M9 8V5.5A1.5 1.5 0 0 1 10.5 4h3A1.5 1.5 0 0 1 15 5.5V8" />
      <path d="M6.5 8l1 11a1.5 1.5 0 0 0 1.5 1.4h6a1.5 1.5 0 0 0 1.5-1.4l1-11" />
      <path d="M10 11.5v6M14 11.5v6" />
    </>
  ),
  bloatware: (
    <>
      <path d="M4 7h16M10 4h4M6.5 7l1 12.5a1.5 1.5 0 0 0 1.5 1.4h6a1.5 1.5 0 0 0 1.5-1.4L18 7" />
    </>
  ),
  power: <path d="M13 2L4.5 13.5H11l-1 8.5 8.5-11.5H12z" fill="currentColor" stroke="none" />,
  // Diagnose
  health: <path d="M3 12h4l2-5 3 9 2-4h7" />,
  temps: (
    <>
      <path d="M10 13.5V5a2 2 0 1 1 4 0v8.5a4 4 0 1 1-4 0z" />
      <path d="M12 14v-3" />
    </>
  ),
  eventlog: <path d="M4 6h16M4 12h16M4 18h10" />,
  bsod: (
    <>
      <rect x="3" y="4" width="18" height="14" rx="2" />
      <path d="M8 21h8M12 18v3" />
      <path d="M12 8v3.5M12 14h.01" />
    </>
  ),
  netdiag: (
    <>
      <circle cx="12" cy="5" r="2.2" />
      <circle cx="5" cy="19" r="2.2" />
      <circle cx="19" cy="19" r="2.2" />
      <path d="M12 7.2v3.3M10.5 12.5L6.5 17M13.5 12.5L17.5 17" />
      <circle cx="12" cy="12" r="0.6" fill="currentColor" />
    </>
  ),
  updates: (
    <>
      <path d="M21 12a9 9 0 1 1-2.6-6.4" />
      <path d="M21 4v4h-4" />
    </>
  ),
  security: (
    <>
      <rect x="5" y="10.5" width="14" height="10" rx="2" />
      <path d="M8 10.5V8a4 4 0 0 1 8 0v2.5" />
      <circle cx="12" cy="15" r="1.3" />
    </>
  ),
  runtimes: (
    <>
      <path d="M12 3l8 4.5-8 4.5-8-4.5z" />
      <path d="M4 12l8 4.5 8-4.5M4 16.5L12 21l8-4.5" />
    </>
  ),
  diskhealth: (
    <>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <circle cx="12" cy="13" r="3" />
      <path d="M12 8V5.5M12 16v2.5" />
    </>
  ),
  // misc
  bolt: <path d="M13 2L4.5 13.5H11l-1 8.5 8.5-11.5H12z" fill="currentColor" stroke="none" />,
  shield: (
    <>
      <path d="M12 3l7 3v5c0 4.5-3 7.7-7 9-4-1.3-7-4.5-7-9V6z" />
      <path d="M9 12l2 2 4-4" />
    </>
  ),
  warn: (
    <>
      <path d="M12 3l9.5 16.5h-19z" />
      <path d="M12 9.5v4M12 16.5h.01" />
    </>
  ),
  export: (
    <>
      <path d="M12 15V3M8 7l4-4 4 4" />
      <path d="M5 14v4a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-4" />
    </>
  ),
  play: <path d="M7 4.5l13 7.5-13 7.5z" fill="currentColor" stroke="none" />,
  back: <path d="M15 5l-7 7 7 7" />,
  check: <path d="M4 12l5 5L20 6" />,
  refresh: (
    <>
      <path d="M21 12a9 9 0 1 1-2.6-6.4" />
      <path d="M21 4v4h-4" />
    </>
  ),
  spark: <path d="M12 3v4M12 17v4M3 12h4M17 12h4M6 6l2.5 2.5M15.5 15.5L18 18M18 6l-2.5 2.5M8.5 15.5L6 18" />,
};

interface IconProps {
  name: string;
  size?: number;
  stroke?: number;
  className?: string;
  style?: CSSProperties;
}

export default function Icon({ name, size = 18, stroke = 1.6, className = "", style }: IconProps) {
  const path = ICON_PATHS[name] || ICON_PATHS.dashboard;
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={stroke}
      strokeLinecap="round"
      strokeLinejoin="round"
      style={style}
      aria-hidden="true"
    >
      {path}
    </svg>
  );
}
