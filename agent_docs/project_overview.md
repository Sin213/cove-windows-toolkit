# Project Overview

## Purpose

Cove Windows Toolkit is a desktop toolkit for tech-support teams to diagnose and optimize Windows machines.

## Scope

The documented scope includes safe/reversible optimization features, read-only diagnostics, system tools, support-log handling, report export, change history, and system repair or restore workflows. It targets elevated 64-bit Windows 10/11 use.

## Architecture

The application uses a Tauri v2 Rust backend with a React 19/TypeScript/Vite frontend. Rust feature crates under `crates/` provide separate modules for optimization, diagnostics, repair, and system tooling; the frontend presents feature panels and invokes backend commands through `ui/src/lib/tauri.ts`.

## Main Workflows

- Optimize Windows settings, services, startup entries, cleanup targets, and power configuration.
- Diagnose health, event logs, BSODs, drivers, networking, updates, security, runtimes, disks, and temperatures.
- Use system tools such as uninstall, bloatware removal, system information, DISM/SFC, restore management, report export, and support logs.
- Build and distribute installer and portable executables through documented GitHub Actions release workflows.

## Major Decisions

The repository documents a tiered safety/confirmation model and privacy-redacted local support logs. It also separates feature responsibilities into Rust workspace modules and keeps CI-produced release checksums authoritative.
