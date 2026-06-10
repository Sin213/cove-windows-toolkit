# Handoff: 4 Features for Windows Claude

## Context

Cove Windows Toolkit - Tauri v2 (Rust backend + React frontend).
Workspace with 21 module crates under `crates/`. Most modules are stubs returning hardcoded JSON from `crates/optimizer-app/src/commands/mod.rs`. The undo system in `optimizer-core` (operation.rs, undo.rs) has real infrastructure with SQLite-backed logging.

The UI uses a `View` type in `App.tsx` to route between panels. Sidebar + Dashboard provide navigation. The `invoke()` wrapper in `ui/src/lib/tauri.ts` falls back to mock data when not running in Tauri.

Recent commit `278d2da` added: performance tweaks panel, admin indicator, file logging, activation status.

---

## Feature 1: Confirmation Dialogs for Yellow/Red Operations

**What:** Modal confirmation dialog before any Yellow or Red safety-tier action executes. Green-tier actions execute immediately (no modal).

**Why:** One misclick on a customer machine can break things. The SafetyTier system exists in the type system but has zero UI enforcement.

**Implementation:**

- Create `ui/src/components/ConfirmDialog.tsx` - a reusable modal component
  - Props: `open`, `title`, `message`, `safetyTier`, `onConfirm`, `onCancel`
  - Yellow tier: amber/orange styling, message like "This changes system settings. Continue?"
  - Red tier: red styling, message like "This is a destructive operation. Are you sure?"
  - Show the specific action name and what it will change
  - Create matching `ConfirmDialog.css`

- Wire it into every panel that has apply/action buttons:
  - `PerformancePanel.tsx` - already has `safety_tier` on each tweak, wrap `handleApply` with confirmation for non-Green
  - `VisualPanel.tsx` - same pattern
  - `ServicesPanel.tsx` - service changes are Yellow
  - `StartupPanel.tsx` - toggling startup items
  - `CleanupPanel.tsx` - file deletion is Yellow
  - `PowerPanel.tsx` - power scheme changes are Yellow
  - `UninstallPanel.tsx` - uninstall is Red
  - `BloatwarePanel.tsx` (remove) - Red
  - `RestorePanel.tsx` (create/restore) - Yellow/Red

- Pattern: each panel manages `const [confirmAction, setConfirmAction] = useState<{tweak, action} | null>(null)`. When user clicks apply, set the confirm state instead of executing. On confirm, execute and clear state.

**Complexity:** Low. It's a shared component + state wrapper in each panel.

---

## Feature 2: "Run All Diagnostics" Batch Scan

**What:** A single button on the Dashboard that fires all read-only diagnostic commands in parallel and shows a unified results summary.

**Why:** Currently a tech has to click through 7+ panels one by one. This is the single biggest workflow accelerator.

**Implementation:**

Backend (`crates/optimizer-app/src/commands/mod.rs`):
- Add a new command `run_all_diagnostics` that calls all diagnostic getters in parallel (or sequentially - they're stubs now so it doesn't matter):
  - `get_health_report`
  - `get_event_log_summary`
  - `get_bsod_dumps`
  - `get_driver_audit`
  - `get_network_diagnostics`
  - `get_update_status`
  - `get_activation_status`
  - `get_temperatures`
  - `get_full_sysinfo`
- Return a combined struct with all results + an overall severity (worst-of)
- Register it in `main.rs` invoke handler

Frontend:
- Add the command + mock to `ui/src/lib/tauri.ts`
- Add a "Run All Diagnostics" button on the Dashboard, below the health score ring and above the card grid
- When clicked, show a loading state, then display a summary panel:
  - List each diagnostic module with its worst severity (icon: checkmark for Ok/Info, warning triangle for Warning, X for Critical)
  - Clicking a row navigates to that panel for details (`onNavigate(moduleId)`)
- Style: full-width card with a list of rows, each row = module icon + name + severity badge

Register the view: no new View needed - the results render inline on the Dashboard or as an overlay/expandable section.

**Complexity:** Low. Orchestration of existing commands + a summary UI.

---

## Feature 3: Preset Action Groups ("General Tune-Up" Button)

**What:** One-click curated batch of Green-tier-only tweaks. A "General Tune-Up" preset that applies the most common safe optimizations in one shot.

**Why:** Replaces clicking through 4-5 panels and applying tweaks one by one. This is the core daily workflow for a tech support agent.

**Implementation:**

Backend (`crates/optimizer-app/src/commands/mod.rs`):
- Add a `get_presets` command returning a list of presets:
  ```rust
  struct Preset {
      id: String,
      name: String,        // "General Tune-Up"
      description: String, // "Apply common safe optimizations"
      actions: Vec<PresetAction>,
  }
  struct PresetAction {
      module: String,      // "visual", "performance", "privacy"
      action_id: String,   // the tweak id within that module
      display_name: String,
  }
  ```
- Add a `run_preset` command that takes a preset ID, executes each action sequentially, records each in the undo log, returns a summary of what succeeded/failed
- The "General Tune-Up" preset should include:
  - Visual: disable transparency, disable animations
  - Performance: disable last access timestamp, disable 8.3 names, prefetch tuning
  - Privacy: disable advertising ID, disable telemetry (Green-tier ones only)
  - All Green-tier only - never include Yellow/Red in a preset
- Register both in `main.rs`

Frontend:
- Add mocks to `ui/src/lib/tauri.ts`
- Add a "Quick Actions" section to the Dashboard between the status bar and the Optimize section
- Show preset cards (start with just "General Tune-Up")
- Each card: name, description, count of actions, a "Run" button
- On click: confirmation dialog (even though all Green, batch operations deserve a summary of what will happen), then execute, show results (applied/failed count), link to History panel

**Complexity:** Medium. Needs preset definition + batch execution + result summary.

---

## Feature 4: "What Changed Since Last Visit" Diff

**What:** If the tool has been run on this machine before, show what's different now compared to the last session's snapshot.

**Why:** When a tech revisits a client machine, they need to quickly see what changed - new startup items, new bloatware, temp file growth, new event log errors. No other optimizer does this.

**Implementation:**

Backend:
- New crate `crates/mod-snapshot` (add to workspace Cargo.toml)
  - Define a `MachineSnapshot` struct capturing key metrics:
    ```rust
    struct MachineSnapshot {
        timestamp: String,
        hostname: String,
        startup_items: Vec<String>,       // names/paths
        installed_programs: Vec<String>,  // names
        bloatware_found: Vec<String>,     // package names
        service_states: HashMap<String, String>, // name -> start_type
        health_score: u32,
        disk_free_bytes: u64,
        temp_size_bytes: u64,
        critical_events: u32,
        warning_events: u32,
    }
    ```
  - `save_snapshot(snapshot)` - write to SQLite (same DB as undo log, new table `snapshots`)
  - `get_previous_snapshot(hostname)` - get the most recent prior snapshot for this machine
  - `diff_snapshots(old, new)` - return a `SnapshotDiff` with:
    - `new_startup_items: Vec<String>`
    - `removed_startup_items: Vec<String>`
    - `new_programs: Vec<String>`
    - `removed_programs: Vec<String>`
    - `new_bloatware: Vec<String>`
    - `health_score_change: i32`
    - `disk_free_change: i64`
    - `temp_size_change: i64`
    - `critical_event_change: i32`
    - `warning_event_change: i32`

- In `commands/mod.rs`:
  - Add `take_snapshot` - gathers current state from all diagnostic commands, saves to DB, returns the snapshot
  - Add `get_machine_diff` - takes current snapshot, compares to previous, returns the diff (or null if no previous snapshot exists)
  - Auto-snapshot: call `take_snapshot` during `run_all_diagnostics` (Feature 2) so snapshots accumulate naturally

Frontend:
- Add `ui/src/components/DiffPanel.tsx`
- Add `"diff"` to the `View` type in `App.tsx`
- Add to Sidebar under a "Session" or "Tools" section
- Add mocks to `ui/src/lib/tauri.ts`
- UI layout:
  - If no previous snapshot: "First visit to this machine. A baseline snapshot will be saved."
  - If previous snapshot exists, show a two-column diff:
    - Left: metric name (Startup Items, Installed Programs, Health Score, etc.)
    - Right: change indicator (green arrow up/down for improvements, red for regressions, neutral for no change)
    - Expandable rows for lists (e.g., click "3 new startup items" to see the names)
  - Show timestamp of previous snapshot ("Last scanned: 2 weeks ago")

**Complexity:** Medium-High. New crate + SQLite table + snapshot gathering + diff logic + new panel.

---

## Build Order

1. **Confirmation Dialogs** (Feature 1) - no dependencies, pure UI safety layer
2. **Run All Diagnostics** (Feature 2) - no dependencies, orchestrates existing commands
3. **Preset Action Groups** (Feature 3) - benefits from confirmation dialogs being in place
4. **What Changed Diff** (Feature 4) - benefits from batch diagnostics for auto-snapshotting

## File Checklist

| Feature | New Files | Modified Files |
|---------|-----------|----------------|
| 1 - Confirm Dialogs | `ui/src/components/ConfirmDialog.tsx`, `ConfirmDialog.css` | Every panel with actions, `ui/src/lib/tauri.ts` |
| 2 - Batch Scan | None | `commands/mod.rs`, `main.rs`, `Dashboard.tsx`, `Dashboard.css`, `tauri.ts` |
| 3 - Presets | None | `commands/mod.rs`, `main.rs`, `Dashboard.tsx`, `Dashboard.css`, `tauri.ts` |
| 4 - Diff | `crates/mod-snapshot/Cargo.toml`, `crates/mod-snapshot/src/lib.rs`, `ui/src/components/DiffPanel.tsx`, `DiffPanel.css` | `Cargo.toml` (workspace), `App.tsx`, `Sidebar.tsx`, `commands/mod.rs`, `main.rs`, `tauri.ts`, `optimizer-app/Cargo.toml` |

## Notes

- Use hyphens (-) everywhere, never em dashes or en dashes
- All commands currently return stubs/mocks - that's fine, build the wiring now
- Follow the existing pattern: Rust command in `commands/mod.rs`, register in `main.rs`, mock in `tauri.ts`, React component imports `invoke` from `../lib/tauri`
- The `PerformancePanel.tsx` is the best reference for the current UI pattern (tier badges, apply/undo, category grouping)
- Safety tier values are strings: `"Green"`, `"Yellow"`, `"Red"` (capital first letter)
