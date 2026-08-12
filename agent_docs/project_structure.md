# Project Structure

## Directory Layout

- `crates/`: Rust workspace crates for the application, shared core types, and feature modules.
- `ui/`: React/TypeScript/Vite frontend, including feature panels, shared utilities, and static assets.
- `scripts/`: repository checks and audit-support scripts.
- `.github/workflows/`: CI and release automation.
- `docs/`: dashboard image and smoke-test documentation.
- `audit/`: audit-related project files and approved-warning data.
- `release/`: local release/test artifacts; published checksum authority remains CI.

## Modules and Responsibilities

- `crates/optimizer-core`: shared domain types identified in the README, including safety tiers, severity, and findings.
- `crates/optimizer-app`: Tauri application and command integration.
- `crates/mod-*`: feature-specific modules for visual settings, cleanup, privacy, services, startup, power, network, health, event logs, BSODs, drivers, updates, reporting, restore, SFC, system information, temperatures, uninstall, bloatware, performance, runtimes, security, and disk health.
- `crates/optimizer-helper`: standalone helper crate excluded from the workspace.
- `ui/src/components`: React panels and dialogs for the toolkit's feature views; `ui/src/lib/tauri.ts` is the frontend invoke/mock boundary.

## Main Interfaces and Integration Boundaries

The Tauri command boundary connects the React frontend to Rust feature modules. `ui/src/App.tsx` provides frontend view routing, while the Rust workspace and Windows PowerShell/Windows API integrations provide system operations. CI workflows build and package installer and portable executables.

## Tests and Supporting Assets

`docs/SMOKE-TEST.md` documents smoke testing. `scripts/` contains audit/check scripts, and `.github/workflows/ci.yml` provides CI automation. `docs/dashboard.png` and frontend assets support the UI presentation.
