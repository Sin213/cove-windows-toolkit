# Cove Windows Toolkit

A desktop toolkit built for tech support teams to diagnose and optimize Windows machines. Built with Tauri v2 (Rust backend + React frontend).

## Download

Grab the latest build from the [Releases page](https://github.com/Sin213/cove-windows-toolkit/releases/latest):

- **`Cove-Windows-Toolkit-{version}-Setup.exe`** — guided installer with a Start-menu shortcut and uninstaller.
- **`Cove-Windows-Toolkit-{version}-Portable.exe`** — single file, no install; just run it.

Requires Windows 10/11. The app runs elevated (administrator) — accept the UAC prompt so diagnostics and repairs can reach system data. Optionally verify your download against `checksums-sha256.txt`.

## What It Does

**Optimize** - Apply safe, reversible tweaks to improve performance:
- Visual effects, transparency, animations
- Privacy and telemetry settings
- Service management (SysMain, DiagTrack, Xbox, etc.)
- Startup program control
- Disk cleanup (temp files, caches, update leftovers)
- Power plan switching
- Registry-based performance tweaks (NTFS, prefetch, CPU scheduling)

**Diagnose** - Read-only scans that surface problems:
- System health score with actionable findings
- Event log analysis (critical errors, warnings, crash patterns)
- BSOD minidump detection
- Driver audit (outdated, unsigned)
- Network diagnostics with speed test
- Windows Update status and pending patches
- Security scan (Defender status, heuristic checks)
- Installed runtimes (.NET, VC++, DirectX, Java) with update links
- Disk health (SMART, wear, temperature, chkdsk)
- Temperature monitoring

**System Tools:**
- Deep uninstaller with leftover scanning
- Bloatware removal
- Full system info (Speccy-style)
- DISM / SFC repair
- System restore management
- What Changed diff (compare machine state between visits)
- Change history with undo
- Export report (full HTML diagnostic summary)

## Safety Model

Every action has a safety tier:
- **Green** - Safe, instantly reversible (visual tweaks, cleanup)
- **Yellow** - Caution, may affect behavior (performance tweaks, service changes)
- **Red** - Destructive or high-impact (camera/mic block, chkdsk /f)

Yellow and Red actions require confirmation before executing.

## Quick Start

### Prerequisites
- [Rust](https://rustup.rs/) (stable)
- [Node.js](https://nodejs.org/) 18+
- [pnpm](https://pnpm.io/) 9+
- Tauri CLI: `cargo install tauri-cli --version "^2"`

### Development

```bash
# Install frontend dependencies
pnpm --prefix ui install

# Run in dev mode (hot reload)
cargo tauri dev
```

The app opens with a browser-based mock backend for UI development. When running inside Tauri, all commands execute real Windows PowerShell queries.

### Build

```bash
# Production build (creates NSIS installer + standalone exe)
cargo tauri build
```

Output (the workspace target lives at the repo root):
- `target/release/bundle/nsis/*.exe` - NSIS installer
- `target/release/optimizer-app.exe` - Standalone portable exe

## Project Structure

```
cove-windows-toolkit/
  crates/
    optimizer-core/     # Shared types (SafetyTier, Severity, Finding)
    optimizer-app/      # Tauri app, commands, main.rs
    mod-visual/         # Visual effects tweaks
    mod-performance/    # Registry-based performance tweaks
    mod-privacy/        # Privacy and telemetry settings
    mod-services/       # Windows service management
    mod-startup/        # Startup program control
    mod-cleanup/        # Temp file and cache cleanup
    mod-power/          # Power plan management
    mod-health/         # System health scoring
    mod-eventlog/       # Windows Event Log queries
    mod-bsod/           # BSOD minidump scanning
    mod-drivers/        # Driver inventory and audit
    mod-netdiag/        # Network diagnostics and speed test
    mod-updates/        # Windows Update status
    mod-sysinfo/        # Full hardware/software info
    mod-temps/          # Temperature monitoring
    mod-sfc/            # DISM and SFC repair
    mod-restore/        # System Restore management
    mod-uninstall/      # Deep uninstaller
    mod-bloatware/      # Bloatware detection and removal
    mod-runtimes/       # .NET, VC++, DirectX, Java detection
    mod-security/       # Defender status and heuristic scanning
    mod-diskhealth/     # SMART health, chkdsk, largest files
    mod-report/         # HTML report generation
  ui/
    src/
      components/       # React panels (one per feature)
      lib/tauri.ts      # Invoke wrapper with dev-mode mocks
      App.tsx            # View routing
```

## Releases

Releases are built via GitHub Actions. Push a `v*` tag to trigger:

```bash
git tag v1.0.0
git push origin v1.0.0
```

Or run manually from the Actions tab with a version number.

Each release includes:
- `Cove-Windows-Toolkit-{version}-Setup.exe` - NSIS installer
- `Cove-Windows-Toolkit-{version}-Portable.exe` - Single-file portable
- `checksums-sha256.txt` - SHA256 verification

## Tech Stack

- **Backend:** Rust, Tauri v2, PowerShell (Windows APIs)
- **Frontend:** React 19, TypeScript, Vite
- **Packaging:** NSIS installer, standalone exe
- **CI/CD:** GitHub Actions

## License

MIT
