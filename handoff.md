# Handoff: Portable Mode Support

## Scope

Add portable mode so the app can store all user data next to the exe instead of in `%LOCALAPPDATA%`.

## Changed files

- `crates/optimizer-app/src/portable.rs` (new) - portable mode detection and data directory helpers
- `crates/optimizer-app/src/main.rs` - add `mod portable`, use portable log dir in `init_logging`
- `crates/optimizer-app/src/commands/mod.rs` - route `change_history.json`, `snapshot.json`, and `tweak_snapshots.json` through portable dir when active
- `Cargo.lock` - regenerated from current manifests

## How portable mode activates

- If `cove-app-data/` directory exists next to the exe, OR
- If `portable.marker` file exists next to the exe

## Data paths in portable mode

- Logs: `<exe_dir>/cove-app-data/cove-windows-optimizer/logs/`
- Change history: `<exe_dir>/cove-app-data/cove-windows-optimizer/change_history.json`
- Snapshots: `<exe_dir>/cove-app-data/cove-windows-optimizer/snapshot.json`
- Tweak snapshots: `<exe_dir>/cove-app-data/cove-windows-optimizer/tweak_snapshots.json`

## Verification

- `cargo check -p optimizer-app` passes (Linux cross-check)
- No new errors introduced; all warnings are pre-existing
