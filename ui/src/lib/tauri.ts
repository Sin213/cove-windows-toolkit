import { invoke as tauriInvoke } from "@tauri-apps/api/core";

const IS_TAURI = "__TAURI__" in window || "__TAURI_INTERNALS__" in window;

// ---------------------------------------------------------------------------
// Mock data for browser development
// ---------------------------------------------------------------------------

const MOCKS: Record<string, unknown> = {
  get_system_info: {
    hostname: "DEV-PC",
    os: "linux",
    platform: "linux (dev mode)",
  },

  // ── Health ───────────────────────────────────────────────────────────
  get_health_report: {
    score: 72,
    findings: [
      {
        id: "disk.free_space",
        severity: "Warning",
        title: "System Drive Free Space",
        detail: "45.0 GB free of 500.0 GB (9.0%)",
        metric: { Percent: 9.0 },
        remediation: "Run Disk Cleanup to free space on the system drive",
      },
      {
        id: "ram.available",
        severity: "Ok",
        title: "Available RAM",
        detail: "8.5 GB available of 16.0 GB (53.1%)",
        metric: { Percent: 53.1 },
        remediation: null,
      },
      {
        id: "cpu.temp",
        severity: "Ok",
        title: "CPU Temperature",
        detail: "62 C - within normal operating range",
        metric: { Integer: 62 },
        remediation: null,
      },
      {
        id: "smart.status",
        severity: "Ok",
        title: "SMART Disk Health",
        detail: "All drives report healthy SMART status",
        metric: null,
        remediation: null,
      },
      {
        id: "uptime",
        severity: "Info",
        title: "System Uptime",
        detail: "4 days, 7 hours - reboot recommended weekly",
        metric: { Integer: 370800 },
        remediation: "Restart the computer to clear stale resources",
      },
    ],
  },

  // ── Performance Tweaks ────────────────────────────────────────────────
  get_performance_tweaks: [
    {
      id: "perf.ntfs_last_access",
      name: "Disable NTFS Last Access Timestamp",
      description: "Skip updating the last-access time on every file read -reduces disk I/O, especially on HDDs",
      category: "Filesystem",
      safety_tier: "Yellow",
      registry_path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem",
      current_value: "1",
      optimized_value: "80000003",
      warning: null,
    },
    {
      id: "perf.ntfs_8dot3",
      name: "Disable 8.3 Short Name Creation",
      description: "Stop generating legacy DOS-compatible short filenames -speeds up directory operations",
      category: "Filesystem",
      safety_tier: "Yellow",
      registry_path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem",
      current_value: "0",
      optimized_value: "1",
      warning: "Very old 16-bit programs may not find files without 8.3 names",
    },
    {
      id: "perf.prefetch",
      name: "Disable Prefetcher",
      description: "Turn off the prefetch cache -unnecessary on SSDs where random reads are fast",
      category: "Memory",
      safety_tier: "Yellow",
      registry_path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters",
      current_value: "3",
      optimized_value: "0",
      warning: "First launch of apps may be slightly slower without prefetch data",
    },
    {
      id: "perf.superfetch",
      name: "Disable Superfetch (SysMain)",
      description: "Stop preloading frequently used apps into RAM -frees memory on low-RAM machines and reduces disk I/O on SSDs",
      category: "Memory",
      safety_tier: "Yellow",
      registry_path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters",
      current_value: "3",
      optimized_value: "0",
      warning: null,
    },
    {
      id: "perf.priority_separation",
      name: "Boost Foreground App Priority",
      description: "Give the active window more CPU time -makes the desktop feel snappier",
      category: "CPU",
      safety_tier: "Yellow",
      registry_path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl",
      current_value: "2",
      optimized_value: "38",
      warning: null,
    },
    {
      id: "perf.game_bar",
      name: "Disable Game Bar",
      description: "Turn off the Xbox Game Bar overlay -saves background resources on non-gaming machines",
      category: "Gaming",
      safety_tier: "Green",
      registry_path: "HKCU\\Software\\Microsoft\\GameBar",
      current_value: "1",
      optimized_value: "0",
      warning: null,
    },
    {
      id: "perf.game_dvr",
      name: "Disable Game DVR",
      description: "Stop background game recording -reclaims GPU and disk bandwidth",
      category: "Gaming",
      safety_tier: "Green",
      registry_path: "HKCU\\System\\GameConfigStore",
      current_value: "1",
      optimized_value: "0",
      warning: null,
    },
    {
      id: "perf.fast_startup",
      name: "Disable Fast Startup",
      description: "Turn off hybrid shutdown -ensures a clean boot every time, avoids stale driver state",
      category: "Boot",
      safety_tier: "Yellow",
      registry_path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power",
      current_value: "1",
      optimized_value: "0",
      warning: "Cold boot will take a few seconds longer without hybrid shutdown",
    },
  ],
  apply_performance_tweak: { success: true, message: "Applied" },
  undo_performance_tweak: { success: true, message: "Reverted" },

  // ── Activation Status ───────────────────────────────────────────────
  get_activation_status: {
    activated: true,
    edition: "Windows 11 Pro",
    status: "Licensed",
    detail: "Windows is activated with a digital license.",
  },

  // ── Visual Tweaks ────────────────────────────────────────────────────
  get_visual_tweaks: [
    {
      id: "visual.transparency",
      name: "Disable Transparency",
      description: "Turn off window transparency effects to reduce GPU load",
      category: "Visual Effects",
      safety_tier: "Green",
      current_value: "1",
      optimized_value: "0",
    },
    {
      id: "visual.animations",
      name: "Disable Minimize/Maximize Animations",
      description: "Remove window animation effects for snappier feel",
      category: "Visual Effects",
      safety_tier: "Green",
      current_value: "1",
      optimized_value: "0",
    },
    {
      id: "visual.taskbar_anim",
      name: "Disable Taskbar Animations",
      description: "Stop taskbar button animations",
      category: "Visual Effects",
      safety_tier: "Green",
      current_value: "1",
      optimized_value: "0",
    },
    {
      id: "visual.peek",
      name: "Disable Aero Peek",
      description: "Turn off desktop peek on taskbar hover",
      category: "Visual Effects",
      safety_tier: "Green",
      current_value: "1",
      optimized_value: "0",
    },
    {
      id: "visual.shadows",
      name: "Disable Icon Shadows",
      description: "Remove text shadows under desktop icons",
      category: "Visual Effects",
      safety_tier: "Green",
      current_value: "1",
      optimized_value: "0",
    },
    {
      id: "visual.smooth_scroll",
      name: "Disable Smooth Scrolling",
      description: "Turn off smooth scrolling in lists",
      category: "Visual Effects",
      safety_tier: "Green",
      current_value: "1",
      optimized_value: "0",
    },
  ],

  // ── Privacy Tweaks ───────────────────────────────────────────────────
  get_privacy_tweaks: {
    basic: [
      {
        id: "priv.advertising_id",
        name: "Disable Advertising ID",
        description: "Prevent apps from using your advertising ID for targeted ads",
        tier: "green",
        path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo\\Enabled",
        current: "1",
        optimized: "0",
      },
      {
        id: "priv.tailored_experiences",
        name: "Disable Tailored Experiences",
        description: "Stop Microsoft from using diagnostic data to personalize tips and ads",
        tier: "green",
        path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\UserProfileEngagement\\ScoobeSystemSettingEnabled",
        current: "1",
        optimized: "0",
      },
      {
        id: "priv.suggested_content",
        name: "Disable Suggested Content in Settings",
        description: "Remove Microsoft app suggestions in Settings",
        tier: "green",
        path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\\SubscribedContent-338393Enabled",
        current: "1",
        optimized: "0",
      },
      {
        id: "priv.start_suggestions",
        name: "Disable Start Menu Suggestions",
        description: "Remove app install suggestions from Start menu",
        tier: "green",
        path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager\\SystemPaneSuggestionsEnabled",
        current: "1",
        optimized: "0",
      },
    ],
    standard: [
      {
        id: "priv.telemetry_basic",
        name: "Set Telemetry to Required Only",
        description: "Reduce Windows diagnostic data to the minimum required level",
        tier: "yellow",
        path: "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\\AllowTelemetry",
        current: "3",
        optimized: "0",
        warning: "May affect personalized troubleshooting from Microsoft",
      },
      {
        id: "priv.activity_history",
        name: "Disable Activity History",
        description: "Stop Windows from collecting activity history for timeline",
        tier: "yellow",
        path: "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\EnableActivityFeed",
        current: "1",
        optimized: "0",
      },
      {
        id: "priv.location",
        name: "Disable Location Services",
        description: "Turn off system-wide location access",
        tier: "yellow",
        path: "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors\\DisableLocation",
        current: "0",
        optimized: "1",
        warning: "Weather and map apps will not auto-detect location",
      },
      {
        id: "priv.feedback_frequency",
        name: "Disable Feedback Prompts",
        description: "Stop Windows from asking for feedback",
        tier: "green",
        path: "HKCU\\Software\\Microsoft\\Siuf\\Rules\\NumberOfSIUFInPeriod",
        current: "1",
        optimized: "0",
      },
    ],
    advanced: [
      {
        id: "priv.connected_experiences",
        name: "Disable Connected Experiences",
        description: "Turn off cloud-powered features in Office and Windows",
        tier: "red",
        path: "HKCU\\Software\\Policies\\Microsoft\\office\\16.0\\common\\privacy\\disconnectedstate",
        current: "0",
        optimized: "2",
        warning: "Some Office cloud features will stop working",
      },
      {
        id: "priv.cortana",
        name: "Disable Cortana",
        description: "Completely disable the Cortana assistant",
        tier: "red",
        path: "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search\\AllowCortana",
        current: "1",
        optimized: "0",
        warning: "Voice assistant will be fully disabled",
      },
      {
        id: "priv.web_search",
        name: "Disable Web Search in Start",
        description: "Remove Bing web results from Start menu search",
        tier: "yellow",
        path: "HKCU\\Software\\Policies\\Microsoft\\Windows\\Explorer\\DisableSearchBoxSuggestions",
        current: "0",
        optimized: "1",
      },
    ],
  },

  // ── Services ─────────────────────────────────────────────────────────
  get_services_tweaks: {
    conservative: [
      {
        id: "svc.sysmain",
        name: "SysMain (Superfetch)",
        service: "SysMain",
        description: "Preloads frequently used apps into memory. Unnecessary on SSD.",
        tier: "green",
        current: "Automatic",
        optimized: "Manual",
        impact: "Frees RAM and reduces disk I/O on SSDs",
      },
      {
        id: "svc.diagtrack",
        name: "DiagTrack",
        service: "DiagTrack",
        description: "Collects and sends diagnostic data to Microsoft.",
        tier: "green",
        current: "Automatic",
        optimized: "Manual",
        impact: "Stops telemetry data upload",
      },
      {
        id: "svc.fax",
        name: "Fax",
        service: "Fax",
        description: "Enables sending and receiving faxes.",
        tier: "green",
        current: "Manual",
        optimized: "Disabled",
        impact: "No fax capability",
      },
      {
        id: "svc.mapsbroker",
        name: "Downloaded Maps Manager",
        service: "MapsBroker",
        description: "Application access to downloaded maps.",
        tier: "green",
        current: "Automatic (Delayed)",
        optimized: "Disabled",
        impact: "Offline maps will not auto-update",
      },
      {
        id: "svc.retaildemo",
        name: "Retail Demo Service",
        service: "RetailDemo",
        description: "Controls retail demo mode for store display devices.",
        tier: "green",
        current: "Manual",
        optimized: "Disabled",
        impact: "No effect on non-retail machines",
      },
    ],
    advanced: [
      {
        id: "svc.wsearch",
        name: "Windows Search",
        service: "WSearch",
        description: "Content indexing and property caching for file search.",
        tier: "yellow",
        current: "Automatic (Delayed)",
        optimized: "Disabled",
        impact: "Search works but first query is slower",
      },
      {
        id: "svc.wbiosrvc",
        name: "Windows Biometric Service",
        service: "WbioSrvc",
        description: "Captures, compares, and stores biometric data.",
        tier: "red",
        current: "Automatic",
        optimized: "Disabled",
        impact: "Windows Hello and fingerprint login will not work",
        warning: "Disables biometric authentication entirely",
      },
      {
        id: "svc.tabletinput",
        name: "Touch Keyboard and Handwriting",
        service: "TabletInputService",
        description: "Enables touch keyboard and handwriting pen functionality.",
        tier: "yellow",
        current: "Automatic",
        optimized: "Disabled",
        impact: "No touch keyboard or handwriting input",
      },
    ],
  },

  // ── Startup Items ────────────────────────────────────────────────────
  get_startup_items: [
    {
      id: "startup.onedrive",
      name: "Microsoft OneDrive",
      path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      command: "C:\\Users\\User\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe /background",
      impact: "High",
      enabled: true,
    },
    {
      id: "startup.discord",
      name: "Discord",
      path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      command: "C:\\Users\\User\\AppData\\Local\\Discord\\Update.exe --processStart Discord.exe",
      impact: "High",
      enabled: true,
    },
    {
      id: "startup.spotify",
      name: "Spotify",
      path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      command: "C:\\Users\\User\\AppData\\Roaming\\Spotify\\Spotify.exe /minimized",
      impact: "Medium",
      enabled: true,
    },
    {
      id: "startup.steam",
      name: "Steam Client Bootstrapper",
      path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      command: "\"C:\\Program Files (x86)\\Steam\\steam.exe\" /silent",
      impact: "High",
      enabled: true,
    },
    {
      id: "startup.teams",
      name: "Microsoft Teams",
      path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      command: "C:\\Users\\User\\AppData\\Local\\Microsoft\\Teams\\Update.exe --processStart Teams.exe",
      impact: "High",
      enabled: false,
    },
    {
      id: "startup.realtek",
      name: "Realtek HD Audio Manager",
      path: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      command: "\"C:\\Program Files\\Realtek\\Audio\\HDA\\RtkNGUI64.exe\" -s",
      impact: "Low",
      enabled: true,
    },
    {
      id: "startup.sechealth",
      name: "Windows Security Notification",
      path: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      command: "%ProgramFiles%\\Windows Defender\\MSASCuiL.exe",
      impact: "Low",
      enabled: true,
    },
    {
      id: "startup.nvidia",
      name: "NVIDIA GeForce Experience",
      path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      command: "\"C:\\Program Files\\NVIDIA Corporation\\NVIDIA GeForce Experience\\NVIDIA Share.exe\"",
      impact: "Medium",
      enabled: true,
    },
  ],

  // ── Cleanup Targets ──────────────────────────────────────────────────
  get_cleanup_targets: [
    {
      id: "clean.user_temp",
      name: "User Temp Files",
      path: "%TEMP%",
      size_bytes: 2_147_483_648,
      file_count: 12480,
      safety: "green",
    },
    {
      id: "clean.system_temp",
      name: "Windows Temp Files",
      path: "%SystemRoot%\\Temp",
      size_bytes: 536_870_912,
      file_count: 3210,
      safety: "green",
    },
    {
      id: "clean.prefetch",
      name: "Prefetch Cache",
      path: "%SystemRoot%\\Prefetch",
      size_bytes: 134_217_728,
      file_count: 284,
      safety: "green",
    },
    {
      id: "clean.thumbnails",
      name: "Thumbnail Cache",
      path: "%LocalAppData%\\Microsoft\\Windows\\Explorer",
      size_bytes: 314_572_800,
      file_count: 12,
      safety: "green",
    },
    {
      id: "clean.recycle_bin",
      name: "Recycle Bin",
      path: "$Recycle.Bin",
      size_bytes: 1_073_741_824,
      file_count: 89,
      safety: "green",
    },
    {
      id: "clean.wu_cache",
      name: "Windows Update Cleanup",
      path: "%SystemRoot%\\SoftwareDistribution\\Download",
      size_bytes: 3_221_225_472,
      file_count: 1540,
      safety: "yellow",
    },
    {
      id: "clean.crash_dumps",
      name: "Crash Dump Files",
      path: "%SystemRoot%\\Minidump",
      size_bytes: 268_435_456,
      file_count: 5,
      safety: "green",
    },
    {
      id: "clean.delivery_opt",
      name: "Delivery Optimization Files",
      path: "%SystemRoot%\\SoftwareDistribution\\DeliveryOptimization",
      size_bytes: 524_288_000,
      file_count: 48,
      safety: "yellow",
    },
  ],

  // ── Power ────────────────────────────────────────────────────────────
  get_power_info: {
    current_plan: "Balanced",
    current_guid: "381b4222-f694-41f0-9685-ff5bb260df2e",
    available_plans: [
      { name: "Balanced", guid: "381b4222-f694-41f0-9685-ff5bb260df2e", active: true },
      { name: "High Performance", guid: "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c", active: false },
      { name: "Power Saver", guid: "a1841308-3541-4fab-bc81-f71556f20b4a", active: false },
    ],
    hdd_sleep_minutes: 20,
    display_off_minutes: 15,
    sleep_minutes: 30,
  },

  // ── Event Log ────────────────────────────────────────────────────────
  get_event_log_summary: {
    system: {
      critical: 2,
      error: 18,
      warning: 142,
      recent_events: [
        { id: 41, source: "Kernel-Power", level: "Critical", message: "The system has rebooted without cleanly shutting down first.", time: "2026-06-08T02:14:00Z" },
        { id: 7034, source: "Service Control Manager", level: "Error", message: "The Windows Audio service terminated unexpectedly.", time: "2026-06-07T18:30:00Z" },
        { id: 10016, source: "DistributedCOM", level: "Error", message: "The application-specific permission settings do not grant Local Activation permission.", time: "2026-06-07T15:22:00Z" },
        { id: 134, source: "Time-Service", level: "Warning", message: "NtpClient was unable to set a domain peer to use as a time source.", time: "2026-06-08T06:00:00Z" },
      ],
    },
    application: {
      critical: 0,
      error: 8,
      warning: 64,
      recent_events: [
        { id: 1000, source: "Application Error", level: "Error", message: "Faulting application name: explorer.exe", time: "2026-06-07T14:08:00Z" },
        { id: 1002, source: "Application Hang", level: "Error", message: "The program msedge.exe stopped interacting with Windows.", time: "2026-06-06T22:15:00Z" },
      ],
    },
  },

  // ── BSOD ─────────────────────────────────────────────────────────────
  get_bsod_dumps: [
    {
      file: "C:\\Windows\\Minidump\\060726-12500-01.dmp",
      date: "2026-06-07T02:14:22Z",
      bug_check: "See details",
      bug_check_name: "MINIDUMP_FOUND",
      faulting_module: "Requires WinDbg",
      description: "Minidump found. Use WinDbg or BlueScreenView for bug check analysis.",
      recommendation: "Update drivers and run memory diagnostics if crashes are frequent.",
    },
    {
      file: "C:\\Windows\\Minidump\\060526-18200-01.dmp",
      date: "2026-06-05T14:38:10Z",
      bug_check: "See details",
      bug_check_name: "MINIDUMP_FOUND",
      faulting_module: "Requires WinDbg",
      description: "Minidump found. Use WinDbg or BlueScreenView for bug check analysis.",
      recommendation: "Update drivers and run memory diagnostics if crashes are frequent.",
    },
    {
      file: "C:\\Windows\\Minidump\\052826-09100-01.dmp",
      date: "2026-05-28T07:12:45Z",
      bug_check: "See details",
      bug_check_name: "MINIDUMP_FOUND",
      faulting_module: "Requires WinDbg",
      description: "Minidump found. Use WinDbg or BlueScreenView for bug check analysis.",
      recommendation: "Update drivers and run memory diagnostics if crashes are frequent.",
    },
  ],

  // ── Drivers ──────────────────────────────────────────────────────────
  get_driver_audit: {
    total: 142,
    unsigned: 3,
    outdated: 2,
    problematic: [
      { name: "Realtek PCIe GbE Family Controller", device: "Network adapters", version: "10.45.928.2020", date: "2022-03-15", signed: true, status: "outdated" },
      { name: "NVIDIA GeForce RTX 3070", device: "Display adapters", version: "537.70", date: "2023-01-10", signed: true, status: "outdated" },
      { name: "VirtualBox Host-Only Ethernet Adapter", device: "Network adapters", version: "6.1.40", date: "2022-10-20", signed: false, status: "unsigned" },
      { name: "Razer Synapse Driver", device: "Human Interface Devices", version: "1.0.18.2", date: "2023-06-14", signed: false, status: "unsigned" },
      { name: "WinPcap Packet Driver", device: "Network adapters", version: "4.1.3.0", date: "2019-11-08", signed: false, status: "unsigned" },
    ],
    healthy: [
      { name: "Intel(R) UHD Graphics 770", device: "Display adapters", version: "31.0.101.5186", date: "2025-12-01", signed: true, status: "ok" },
      { name: "High Definition Audio Device", device: "Sound, video and game controllers", version: "10.0.22621.1", date: "2024-06-21", signed: true, status: "ok" },
      { name: "Microsoft ACPI-Compliant System", device: "System devices", version: "10.0.22621.3155", date: "2024-08-14", signed: true, status: "ok" },
    ],
  },

  // ── Network Diagnostics ──────────────────────────────────────────────
  get_network_diagnostics: {
    adapter: {
      name: "Ethernet",
      type: "Ethernet",
      speed: "1 Gbps",
      ip: "192.168.1.105",
      gateway: "192.168.1.1",
      dns: ["1.1.1.1", "8.8.8.8"],
      status: "Up",
      signal: null,
    },
    tests: [
      { name: "Gateway Ping", status: "ok", latency_ms: 1, detail: "192.168.1.1 reachable" },
      { name: "DNS Resolution", status: "ok", latency_ms: 12, detail: "Resolved google.com to 142.250.80.46" },
      { name: "Internet Connectivity", status: "ok", latency_ms: 22, detail: "microsoft.com reachable" },
    ],
    wifi: null,
  },

  // ── Windows Updates ──────────────────────────────────────────────────
  get_update_status: {
    last_check: "2026-06-08T04:00:00Z",
    last_install: "2026-06-03T02:15:00Z",
    service_status: "Running",
    pending_updates: [
      { title: "2026-06 Cumulative Update for Windows 11 (KB5039302)", size_mb: 450, severity: "Critical", category: "Security Updates" },
      { title: "2026-06 .NET 8.0.6 Security Update (KB5039293)", size_mb: 52, severity: "Important", category: "Security Updates" },
      { title: "Intel - System - 5/2026", size_mb: 15, severity: "Optional", category: "Driver Updates" },
    ],
    component_store_health: "Healthy",
    days_since_last_update: 7,
  },

  // ── Change History ───────────────────────────────────────────────────
  get_change_history: [
    {
      id: 1,
      timestamp: "2026-06-08T10:30:00Z",
      module: "visual",
      name: "Disable Transparency",
      tier: "green",
      status: "committed",
    },
    {
      id: 2,
      timestamp: "2026-06-08T10:30:01Z",
      module: "visual",
      name: "Disable Animations",
      tier: "green",
      status: "committed",
    },
    {
      id: 3,
      timestamp: "2026-06-08T10:30:02Z",
      module: "visual",
      name: "Disable Taskbar Animations",
      tier: "green",
      status: "committed",
    },
    {
      id: 4,
      timestamp: "2026-06-07T16:45:00Z",
      module: "services",
      name: "DiagTrack",
      tier: "green",
      status: "undone",
    },
    {
      id: 5,
      timestamp: "2026-06-07T16:45:01Z",
      module: "startup",
      name: "Discord auto-start",
      tier: "green",
      status: "committed",
    },
    {
      id: 6,
      timestamp: "2026-06-06T12:00:00Z",
      module: "cleanup",
      name: "User Temp Files",
      tier: "green",
      status: "committed",
    },
    {
      id: 7,
      timestamp: "2026-06-06T12:00:01Z",
      module: "power",
      name: "High Performance plan",
      tier: "green",
      status: "failed",
    },
  ],

  // ── System Restore ────────────────────────────────────────────────────
  get_restore_status: {
    enabled: true,
    message: "System Protection is enabled.",
  },
  get_restore_points: [
    {
      sequence_number: 42,
      description: "Windows Update",
      restore_point_type: "Windows Update",
      creation_time: "2026-06-08T10:30:00-05:00",
    },
    {
      sequence_number: 41,
      description: "Installed Cove Windows Toolkit",
      restore_point_type: "Application Install",
      creation_time: "2026-06-07T14:15:00-05:00",
    },
    {
      sequence_number: 40,
      description: "System Checkpoint",
      restore_point_type: "System Checkpoint",
      creation_time: "2026-06-05T03:00:00-05:00",
    },
  ],
  create_restore_point: { success: true, message: "Restore point created successfully." },
  enable_system_protection: { success: true, message: "System Protection enabled on the system drive." },
  launch_system_restore: { success: true, message: "System Restore wizard launched." },

  // ── Uninstaller ──────────────────────────────────────────────────────
  get_installed_programs: [
    { name: "SignalRGB", publisher: "WhirlwindFX", version: "2.2.40", install_date: "2026-05-15", size_bytes: 524288000, uninstall_string: "\"C:\\Program Files\\SignalRGB\\unins000.exe\"", quiet_uninstall_string: "\"C:\\Program Files\\SignalRGB\\unins000.exe\" /VERYSILENT", install_location: "C:\\Program Files\\SignalRGB", registry_key: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\SignalRGB_is1", is_system: false },
    { name: "Google Chrome", publisher: "Google LLC", version: "125.0.6422.142", install_date: "2026-06-01", size_bytes: 268435456, uninstall_string: "", quiet_uninstall_string: "", install_location: "C:\\Program Files\\Google\\Chrome", registry_key: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Google Chrome", is_system: false },
    { name: "Discord", publisher: "Discord Inc.", version: "1.0.9035", install_date: "2026-05-20", size_bytes: 314572800, uninstall_string: "\"C:\\Users\\User\\AppData\\Local\\Discord\\Update.exe\" --uninstall", quiet_uninstall_string: "", install_location: "", registry_key: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Discord", is_system: false },
    { name: "Steam", publisher: "Valve Corporation", version: "2.10.91.91", install_date: "2026-04-10", size_bytes: 734003200, uninstall_string: "\"C:\\Program Files (x86)\\Steam\\uninstall.exe\"", quiet_uninstall_string: "", install_location: "C:\\Program Files (x86)\\Steam", registry_key: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Steam", is_system: false },
    { name: "7-Zip 24.08 (x64)", publisher: "Igor Pavlov", version: "24.08", install_date: "2026-03-20", size_bytes: 5242880, uninstall_string: "\"C:\\Program Files\\7-Zip\\Uninstall.exe\"", quiet_uninstall_string: "", install_location: "C:\\Program Files\\7-Zip", registry_key: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\7-Zip", is_system: false },
    { name: "Microsoft Visual C++ 2015-2022 Redistributable (x64)", publisher: "Microsoft Corporation", version: "14.38.33135", install_date: "2026-01-15", size_bytes: 25165824, uninstall_string: "", quiet_uninstall_string: "", install_location: "", registry_key: "", is_system: true },
  ],
  uninstall_program: { success: true, message: "Uninstall completed.", output: "" },
  scan_leftovers: {
    leftovers: [
      { path: "C:\\ProgramData\\SignalRGB", category: "Folder", size_bytes: 15728640 },
      { path: "C:\\Users\\User\\AppData\\Local\\SignalRGB", category: "Folder", size_bytes: 8388608 },
      { path: "C:\\Users\\User\\AppData\\Roaming\\SignalRGB", category: "Folder", size_bytes: 2097152 },
      { path: "HKCU\\Software\\SignalRGB", category: "Registry", size_bytes: 0 },
      { path: "HKLM\\SOFTWARE\\WhirlwindFX", category: "Registry", size_bytes: 0 },
      { path: "Task: \\SignalRGB\\UpdateCheck", category: "Scheduled Task", size_bytes: 0 },
    ],
    total_size_bytes: 26214400,
  },
  remove_leftovers: {
    results: [
      { path: "C:\\ProgramData\\SignalRGB", success: true, message: "Removed" },
      { path: "C:\\Users\\User\\AppData\\Local\\SignalRGB", success: true, message: "Removed" },
      { path: "C:\\Users\\User\\AppData\\Roaming\\SignalRGB", success: true, message: "Removed" },
      { path: "HKCU\\Software\\SignalRGB", success: true, message: "Removed" },
      { path: "HKLM\\SOFTWARE\\WhirlwindFX", success: true, message: "Removed" },
      { path: "Task: \\SignalRGB\\UpdateCheck", success: true, message: "Removed" },
    ],
  },

  // ── Full System Info ──────────────────────────────────────────────────
  get_full_sysinfo: {
    os: { name: "Windows 11 Pro", version: "23H2", build: "22631.2506", arch: "64-bit", install_date: "2024-01-15", last_boot: "2026-06-09T08:30:00" },
    cpu: { name: "Intel Core i7-12700K", cores: 12, threads: 20, base_clock_mhz: 3600, max_clock_mhz: 5000, architecture: "x64", temperature_c: 52 },
    ram: { total_bytes: 34359738368, available_bytes: 18000000000, speed_mhz: 3200, slots_used: 2, slots_total: 4, ram_type: "DDR4", modules: [
      { capacity_bytes: 17179869184, speed_mhz: 3200, manufacturer: "Corsair", part_number: "CMK32GX4M2E3200C16", slot: "DIMM 1" },
      { capacity_bytes: 17179869184, speed_mhz: 3200, manufacturer: "Corsair", part_number: "CMK32GX4M2E3200C16", slot: "DIMM 3" },
    ]},
    motherboard: { manufacturer: "ASUS", product: "ROG STRIX Z690-A", serial: "XXXXXXXXXXXX", bios_vendor: "American Megatrends Inc.", bios_version: "2103", bios_date: "2025-08-15" },
    graphics: [{ name: "NVIDIA GeForce RTX 3070", driver_version: "537.70", vram_bytes: 8589934592, status: "OK" }],
    monitors: [{ name: "Generic PnP Monitor", resolution: "2560x1440@165Hz" }],
    storage: [{ model: "Samsung SSD 980 PRO 1TB", interface_type: "NVMe", media_type: "SSD", size_bytes: 1000204886016, status: "OK", partitions: [
      { letter: "C:", label: "Windows", size_bytes: 500000000000, free_bytes: 185000000000, filesystem: "NTFS" },
      { letter: "D:", label: "Data", size_bytes: 499000000000, free_bytes: 320000000000, filesystem: "NTFS" },
    ]}],
    audio: [{ name: "Realtek High Definition Audio", status: "OK" }],
    network: [
      { name: "Intel Wi-Fi 6 AX200", adapter_type: "Wi-Fi", mac: "A4:BB:6D:0C:3E:91", speed: "866 Mbps", ip: "192.168.1.105", status: "Connected" },
      { name: "Intel I225-V", adapter_type: "Ethernet", mac: "9C:2F:9D:B1:44:E2", speed: "2.5 Gbps", ip: "", status: "Disconnected" },
    ],
  },

  // ── Temperatures ─────────────────────────────────────────────────────
  get_temperatures: {
    readings: [
      { sensor: "CPU Package", category: "CPU", temperature_c: 52, max_c: 100, critical_c: 105 },
      { sensor: "CPU Core #0", category: "CPU", temperature_c: 48, max_c: 100, critical_c: 105 },
      { sensor: "CPU Core #1", category: "CPU", temperature_c: 51, max_c: 100, critical_c: 105 },
      { sensor: "CPU Core #2", category: "CPU", temperature_c: 49, max_c: 100, critical_c: 105 },
      { sensor: "CPU Core #3", category: "CPU", temperature_c: 53, max_c: 100, critical_c: 105 },
      { sensor: "GPU Core", category: "GPU", temperature_c: 45, max_c: 93, critical_c: 100 },
      { sensor: "GPU Hot Spot", category: "GPU", temperature_c: 58, max_c: 93, critical_c: 100 },
      { sensor: "Samsung SSD 980 PRO", category: "Disk", temperature_c: 38, max_c: 70, critical_c: 75 },
      { sensor: "WD Blue SN570", category: "Disk", temperature_c: 35, max_c: 70, critical_c: 75 },
    ],
    warnings: [],
  },

  // ── DISM / SFC ───────────────────────────────────────────────────────
  check_admin_status: {
    is_admin: true,
    message: "Running with administrator privileges.",
  },
  run_dism_scan: {
    tool: "DISM",
    success: true,
    exit_code: 0,
    output: "Deployment Image Servicing and Management tool\nVersion: 10.0.22621.1\n\nImage Version: 10.0.22631.2506\n\n[==========================100.0%==========================]\nThe restore operation completed successfully.\nNo component store corruption detected.\nThe operation completed successfully.\n",
    summary: "Component store is healthy. No repairs needed.",
  },
  run_sfc_scan: {
    tool: "SFC",
    success: true,
    exit_code: 0,
    output: "Beginning system scan. This process will take some time.\n\nBeginning verification phase of system scan.\nVerification 100% complete.\n\nWindows Resource Protection did not find any integrity violations.\n",
    summary: "No integrity violations found.",
  },

  // ── Windows Update actions ───────────────────────────────────────────
  reset_windows_update: { success: true, message: "Windows Update components reset successfully. A restart is recommended.", output: "Stopped wuauserv\nStopped bits\nStopped cryptSvc\nStopped msiserver\nRenamed SoftwareDistribution\nRenamed catroot2\nRe-registered WU DLLs\nReset Winsock\nStarted wuauserv\nStarted bits\nStarted cryptSvc\nStarted msiserver" },
  trigger_update_check: { success: true, message: "Windows Update check triggered. The Settings app should open." },

  // ── Network tools ────────────────────────────────────────────────────
  set_dns: { success: true, message: "DNS updated successfully." },
  run_network_command: { success: true, message: "Command completed.", output: "Successfully flushed the DNS Resolver Cache." },

  // ── Runtimes ─────────────────────────────────────────────────────────
  get_installed_runtimes: {
    dotnet: [
      { name: ".NET Framework 4.8", version: "4.8", path: "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319", installed: true, outdated: true, download_url: "https://dotnet.microsoft.com/download/dotnet-framework/net481" },
      { name: ".NET 8.0.3 (runtime)", version: "8.0.3", runtime_type: "runtime", path: "C:\\Program Files\\dotnet", installed: true, outdated: false },
      { name: ".NET Framework 3.5", version: "3.5", path: null, installed: false, outdated: false, download_url: "https://dotnet.microsoft.com/download/dotnet-framework/net35-sp1" },
    ],
    vcredist: [
      { name: "Visual C++ 2015-2022 (x64)", version: "14.38.33135", arch: "x64", installed: true, outdated: true, download_url: "https://aka.ms/vs/17/release/vc_redist.x64.exe" },
      { name: "Visual C++ 2015-2022 (x86)", version: "14.38.33135", arch: "x86", installed: true, outdated: true, download_url: "https://aka.ms/vs/17/release/vc_redist.x86.exe" },
      { name: "Visual C++ 2013 (x64)", version: "12.0.40664", arch: "x64", installed: true, outdated: false },
    ],
    directx: { version: "12.0", feature_level: "12_1", download_url: "https://www.microsoft.com/en-us/download/details.aspx?id=35" },
    java: [],
  },
  open_url: { success: true },
  export_report: { success: true, path: "C:\\Users\\CS\\AppData\\Local\\cove\\optimizer\\reports\\report-20260610-120000.html", filename: "report-20260610-120000.html" },
  run_speed_test: { download_mbps: 94.5, test_url: "http://speedtest.tele2.net/10MB.zip", bytes_downloaded: 10_485_760, duration_ms: 887, status: "ok" },

  // ── Security ────────────────────────────────────────────────────────
  get_security_status: {
    defender: {
      real_time_enabled: true,
      definitions_age_days: 1,
      last_scan: "2026-06-08T14:30:00Z",
      last_scan_type: "Quick",
    },
    heuristic_findings: [],
    scan_available: true,
  },
  run_defender_scan: {
    success: true,
    threats_found: 0,
    message: "No threats detected.",
  },
  run_heuristic_scan: {
    findings: [
      { severity: "Warning", title: "Unsigned process with network activity", detail: "notepad++.exe (PID 4521) - unsigned, 2 active connections", category: "process" },
      { severity: "Warning", title: "Hosts file modified (3 extra entries)", detail: "127.0.0.1 ads.example.com; 127.0.0.1 tracker.example.com; 127.0.0.1 malware.example.com", category: "integrity" },
      { severity: "Info", title: "22 browser extensions installed", detail: "Chrome: 15, Edge: 7", category: "browser" },
    ],
    scan_time_ms: 3200,
  },

  // ── Disk Health ──────────────────────────────────────────────────────
  get_disk_health: [
    {
      model: "Samsung SSD 980 PRO 1TB",
      serial: "S6B1NJ0T123456",
      interface_type: "NVMe",
      media_type: "SSD",
      size_bytes: 1_000_204_886_016,
      status: "Healthy",
      temperature_c: 38,
      wear_percent: 3,
      read_errors: 0,
      write_errors: 0,
      power_on_hours: 8760,
      trim_enabled: true,
      health_rating: "Good",
    },
    {
      model: "WD Blue SN570 500GB",
      serial: "WD-WX42A123456",
      interface_type: "NVMe",
      media_type: "SSD",
      size_bytes: 500_107_862_016,
      status: "Healthy",
      temperature_c: 35,
      wear_percent: 1,
      read_errors: 0,
      write_errors: 0,
      power_on_hours: 4380,
      trim_enabled: true,
      health_rating: "Good",
    },
  ],
  get_disk_space: {
    drive: "C:",
    total_bytes: 500_000_000_000,
    free_bytes: 185_000_000_000,
    largest_files: [
      { name: "Win11_23H2_English_x64.iso", extension: "ISO", path: "C:\\Users\\CS\\Downloads\\Win11_23H2_English_x64.iso", size_bytes: 6_200_000_000 },
      { name: "backup-2026-05.vhdx", extension: "VHDX", path: "C:\\Users\\CS\\Documents\\Backups\\backup-2026-05.vhdx", size_bytes: 4_800_000_000 },
      { name: "gameplay-recording.mp4", extension: "MP4", path: "C:\\Users\\CS\\Videos\\Captures\\gameplay-recording.mp4", size_bytes: 3_100_000_000 },
      { name: "node_modules.tar.gz", extension: "GZ", path: "C:\\Users\\CS\\Downloads\\node_modules.tar.gz", size_bytes: 1_800_000_000 },
      { name: "photoshop-scratch.tmp", extension: "TMP", path: "C:\\Users\\CS\\AppData\\Local\\Temp\\photoshop-scratch.tmp", size_bytes: 950_000_000 },
    ],
  },
  run_chkdsk: {
    success: true,
    mode: "scan",
    scheduled_reboot: false,
    message: "No errors found. Online scan completed successfully.",
    output: "Stage 1: Examining basic file system structure ...\n  262144 file records processed.\nStage 2: Examining file name linkage ...\n  302426 index entries processed.\nStage 3: Examining security descriptors ...\n  Security descriptor verification completed.\nWindows has scanned the file system and found no problems.\nNo further action is required.",
  },
  get_last_chkdsk: {
    found: true,
    timestamp: "2026-06-01T03:15:00-05:00",
    result_text: "Checking file system on C:. Windows has checked the file system and found no problems. No further action is required.",
    dirty_bit: false,
  },

  // ── Run All Diagnostics ─────────────────────────────────────────────
  run_all_diagnostics: {
    overall_severity: "Warning",
    modules: [
      { id: "health", name: "System Health", severity: "Warning" },
      { id: "eventlog", name: "Event Logs", severity: "Critical" },
      { id: "bsod", name: "BSOD Dumps", severity: "Warning" },
      { id: "drivers", name: "Drivers", severity: "Warning" },
      { id: "netdiag", name: "Network", severity: "Ok" },
      { id: "updates", name: "Windows Update", severity: "Warning" },
      { id: "sysinfo", name: "System Info", severity: "Ok" },
      { id: "temps", name: "Temperatures", severity: "Ok" },
      { id: "diskhealth", name: "Disk Health", severity: "Ok" },
    ],
    activated: true,
  },

  // ── Presets ────────────────────────────────────────────────────────
  get_presets: [
    {
      id: "general_tuneup",
      name: "General Tune-Up",
      description: "Apply common safe optimizations - visual effects, performance tweaks, and basic privacy settings",
      actions: [
        { module: "visual", action_id: "visual.transparency", display_name: "Disable Transparency" },
        { module: "visual", action_id: "visual.animations", display_name: "Disable Animations" },
        { module: "visual", action_id: "visual.taskbar_anim", display_name: "Disable Taskbar Animations" },
        { module: "performance", action_id: "perf.game_bar", display_name: "Disable Game Bar" },
        { module: "performance", action_id: "perf.game_dvr", display_name: "Disable Game DVR" },
        { module: "privacy", action_id: "priv.advertising_id", display_name: "Disable Advertising ID" },
        { module: "privacy", action_id: "priv.feedback", display_name: "Disable Feedback Prompts" },
        { module: "privacy", action_id: "priv.tips", display_name: "Disable Tips and Suggestions" },
      ],
    },
  ],
  run_preset: {
    success: true,
    total: 8,
    succeeded: 8,
    failed: 0,
    results: [
      { action_id: "visual.transparency", display_name: "Disable Transparency", success: true },
      { action_id: "visual.animations", display_name: "Disable Animations", success: true },
      { action_id: "visual.taskbar_anim", display_name: "Disable Taskbar Animations", success: true },
      { action_id: "perf.game_bar", display_name: "Disable Game Bar", success: true },
      { action_id: "perf.game_dvr", display_name: "Disable Game DVR", success: true },
      { action_id: "priv.advertising_id", display_name: "Disable Advertising ID", success: true },
      { action_id: "priv.feedback", display_name: "Disable Feedback Prompts", success: true },
      { action_id: "priv.tips", display_name: "Disable Tips and Suggestions", success: true },
    ],
  },

  // ── Snapshot / Diff ────────────────────────────────────────────────
  take_snapshot: { success: true, timestamp: "2026-06-09T10:00:00-05:00", hostname: "DEV-PC" },
  get_machine_diff: {
    has_previous: true,
    previous_timestamp: "2026-05-26T14:30:00-05:00",
    changes: {
      new_startup_items: ["NVIDIA GeForce Experience", "Steam Client Bootstrapper"],
      removed_startup_items: [],
      new_programs: ["SignalRGB"],
      removed_programs: [],
      new_bloatware: [],
      health_score_change: -8,
      disk_free_change: -15000000000,
      temp_size_change: 524288000,
      critical_event_change: 2,
      warning_event_change: 14,
    },
  },

  // ── Apply / Undo commands (return success) ───────────────────────────
  apply_tweak: { success: true, message: "Applied" },
  undo_tweak: { success: true, message: "Reverted" },
  apply_batch: { success: true, applied: 6 },
  toggle_startup: { success: true, message: "Toggled" },
  run_cleanup: { success: true, message: "Cleaned", cleaned: 0 },
  set_power_plan: { success: true, message: "Power plan changed." },
  set_power_timeout: { success: true, message: "Timeout updated." },
  apply_service_change: { success: true, message: "Applied" },
  undo_change: { success: true, message: "Undone" },
};

// ---------------------------------------------------------------------------
// Typed invoke wrapper
// ---------------------------------------------------------------------------

export async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (IS_TAURI) {
    return tauriInvoke<T>(cmd, args);
  }
  // Simulate a brief network delay
  await new Promise((r) => setTimeout(r, 120 + Math.random() * 200));
  if (cmd in MOCKS) {
    // Deep-clone to prevent mutation of mock data
    return JSON.parse(JSON.stringify(MOCKS[cmd])) as T;
  }
  console.warn(`[tauri-mock] No mock for command: ${cmd}`);
  return {} as T;
}
