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
        id: "battery.health",
        severity: "Warning",
        title: "Battery Wear Level",
        detail: "Design capacity 56,000 mWh, current full-charge 41,200 mWh (73.6%)",
        metric: { Percent: 73.6 },
        remediation: "Battery degradation is normal over time. Consider replacement below 50%.",
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
      total: 4280,
      critical: 2,
      error: 18,
      warning: 142,
      events: [
        {
          id: 41,
          source: "Kernel-Power",
          level: "Critical",
          message: "The system has rebooted without cleanly shutting down first.",
          time: "2026-06-08T02:14:00Z",
          count: 2,
        },
        {
          id: 7034,
          source: "Service Control Manager",
          level: "Error",
          message: "The Windows Audio service terminated unexpectedly. It has done this 3 time(s).",
          time: "2026-06-07T18:30:00Z",
          count: 3,
        },
        {
          id: 10016,
          source: "DistributedCOM",
          level: "Error",
          message: "The application-specific permission settings do not grant Local Activation permission for the COM Server application.",
          time: "2026-06-07T15:22:00Z",
          count: 12,
        },
        {
          id: 134,
          source: "Time-Service",
          level: "Warning",
          message: "NtpClient was unable to set a domain peer to use as a time source because of DNS resolution failure.",
          time: "2026-06-08T06:00:00Z",
          count: 8,
        },
        {
          id: 1014,
          source: "DNS Client Events",
          level: "Warning",
          message: "Name resolution for the name wpad timed out after none of the configured DNS servers responded.",
          time: "2026-06-08T05:45:00Z",
          count: 24,
        },
      ],
    },
    application: {
      total: 6150,
      critical: 0,
      error: 8,
      warning: 64,
      events: [
        {
          id: 1000,
          source: "Application Error",
          level: "Error",
          message: "Faulting application name: explorer.exe, version: 10.0.22631.2506",
          time: "2026-06-07T14:08:00Z",
          count: 1,
        },
        {
          id: 1002,
          source: "Application Hang",
          level: "Error",
          message: "The program msedge.exe stopped interacting with Windows and was closed.",
          time: "2026-06-06T22:15:00Z",
          count: 2,
        },
        {
          id: 1026,
          source: ".NET Runtime",
          level: "Error",
          message: "Application: Teams.exe. Framework Version: v4.0.30319. Unhandled exception.",
          time: "2026-06-06T16:42:00Z",
          count: 1,
        },
        {
          id: 11724,
          source: "MsiInstaller",
          level: "Warning",
          message: "Product: Visual C++ 2019 Redistributable -- Configuration completed successfully.",
          time: "2026-06-05T10:30:00Z",
          count: 3,
        },
      ],
    },
  },

  // ── BSOD ─────────────────────────────────────────────────────────────
  get_bsod_dumps: [
    {
      filename: "060726-12500-01.dmp",
      timestamp: "2026-06-07T02:14:22Z",
      bug_check_code: "0x0000009F",
      bug_check_name: "DRIVER_POWER_STATE_FAILURE",
      faulting_module: "ntoskrnl.exe",
      faulting_driver: "usbhub3.sys",
      detail: "A driver has failed to complete a power IRP within a specific time period.",
      recommendation: "Update USB hub drivers. Check for BIOS/firmware updates. Disconnect external USB devices to isolate.",
    },
    {
      filename: "060526-18200-01.dmp",
      timestamp: "2026-06-05T14:38:10Z",
      bug_check_code: "0x000000D1",
      bug_check_name: "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
      faulting_module: "ndis.sys",
      faulting_driver: "rt640x64.sys",
      detail: "A kernel-mode driver attempted to access pageable memory at too high an IRQL.",
      recommendation: "Update Realtek network adapter driver to the latest version from the manufacturer.",
    },
    {
      filename: "052826-09100-01.dmp",
      timestamp: "2026-05-28T07:12:45Z",
      bug_check_code: "0x0000007E",
      bug_check_name: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
      faulting_module: "win32kfull.sys",
      faulting_driver: "nvlddmkm.sys",
      detail: "A system thread generated an exception which the error handler did not catch.",
      recommendation: "Update NVIDIA display driver. Consider rolling back to a previous stable version if crashes persist.",
    },
  ],

  // ── Drivers ──────────────────────────────────────────────────────────
  get_driver_audit: {
    total: 142,
    unsigned: 3,
    outdated: 5,
    problematic: [
      {
        name: "Realtek PCIe GbE Family Controller",
        driver_file: "rt640x64.sys",
        version: "10.45.928.2020",
        date: "2022-03-15",
        signed: true,
        status: "outdated",
        detail: "Driver is 4 years old. Newer version 10.62.301.2024 available.",
      },
      {
        name: "NVIDIA GeForce RTX 3070",
        driver_file: "nvlddmkm.sys",
        version: "537.70",
        date: "2024-01-10",
        signed: true,
        status: "outdated",
        detail: "Associated with BSOD 0x0000007E on 2026-05-28. Update recommended.",
      },
      {
        name: "VirtualBox Host-Only Ethernet Adapter",
        driver_file: "VBoxNetAdp6.sys",
        version: "6.1.40",
        date: "2022-10-20",
        signed: false,
        status: "unsigned",
        detail: "Third-party unsigned driver. May cause issues with Secure Boot.",
      },
      {
        name: "Razer Synapse Driver",
        driver_file: "rzdevmgmt.sys",
        version: "1.0.18.2",
        date: "2023-06-14",
        signed: false,
        status: "unsigned",
        detail: "Unsigned kernel driver. Common source of stability issues.",
      },
      {
        name: "WinPcap Packet Driver",
        driver_file: "npf.sys",
        version: "4.1.3.0",
        date: "2019-11-08",
        signed: false,
        status: "unsigned",
        detail: "Legacy packet capture driver. Consider replacing with npcap.",
      },
    ],
    healthy: [
      {
        name: "Intel(R) UHD Graphics 770",
        driver_file: "igdkmd64.sys",
        version: "31.0.101.5186",
        date: "2025-12-01",
        signed: true,
        status: "ok",
      },
      {
        name: "High Definition Audio Device",
        driver_file: "hdaudio.sys",
        version: "10.0.22621.1",
        date: "2024-06-21",
        signed: true,
        status: "ok",
      },
      {
        name: "Microsoft ACPI-Compliant System",
        driver_file: "acpi.sys",
        version: "10.0.22621.3155",
        date: "2024-08-14",
        signed: true,
        status: "ok",
      },
    ],
  },

  // ── Network Diagnostics ──────────────────────────────────────────────
  get_network_diagnostics: {
    adapters: [
      {
        name: "Ethernet",
        type: "Ethernet",
        mac: "A4:BB:6D:0C:3E:91",
        ipv4: "192.168.1.105",
        ipv6: "fe80::a6bb:6dff:fe0c:3e91",
        gateway: "192.168.1.1",
        dns: ["1.1.1.1", "8.8.8.8"],
        speed: "1 Gbps",
        status: "Connected",
      },
      {
        name: "Wi-Fi",
        type: "WiFi",
        mac: "9C:2F:9D:B1:44:E2",
        ipv4: null,
        ipv6: null,
        gateway: null,
        dns: [],
        speed: null,
        status: "Disconnected",
      },
    ],
    tests: [
      {
        name: "DNS Resolution (1.1.1.1)",
        status: "pass",
        latency_ms: 12,
        detail: "Resolved google.com in 12ms",
      },
      {
        name: "DNS Resolution (8.8.8.8)",
        status: "pass",
        latency_ms: 18,
        detail: "Resolved google.com in 18ms",
      },
      {
        name: "Gateway Ping",
        status: "pass",
        latency_ms: 1,
        detail: "192.168.1.1 responded in 1ms",
      },
      {
        name: "Internet Connectivity",
        status: "pass",
        latency_ms: 22,
        detail: "Connected to microsoft.com in 22ms",
      },
      {
        name: "Packet Loss Test",
        status: "pass",
        latency_ms: null,
        detail: "0% packet loss over 20 pings",
      },
      {
        name: "IPv6 Connectivity",
        status: "warn",
        latency_ms: null,
        detail: "IPv6 not available on current network",
      },
    ],
    wifi: null,
  },

  // ── Windows Updates ──────────────────────────────────────────────────
  get_update_status: {
    last_check: "2026-06-08T04:00:00Z",
    last_install: "2026-06-03T02:15:00Z",
    reboot_required: false,
    pending_updates: [
      {
        title: "2026-06 Cumulative Update for Windows 11 (KB5039302)",
        kb: "KB5039302",
        severity: "Critical",
        size_bytes: 524_288_000,
        classification: "Security Updates",
      },
      {
        title: "2026-06 .NET 8.0.6 Security Update (KB5039293)",
        kb: "KB5039293",
        severity: "Important",
        size_bytes: 52_428_800,
        classification: "Security Updates",
      },
      {
        title: "Intel - System - 5/2026",
        kb: null,
        severity: "Optional",
        size_bytes: 15_728_640,
        classification: "Driver Updates",
      },
    ],
    component_store: {
      health: "Healthy",
      size_bytes: 8_589_934_592,
      last_cleanup: "2026-05-20T10:30:00Z",
      pending_cleanup_bytes: 1_073_741_824,
    },
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
      description: "Installed Cove Windows Optimizer",
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
