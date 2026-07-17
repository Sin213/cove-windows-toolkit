# Cove Windows Toolkit — full repository bug audit

Audit date: 2026-07-16
Audited commit: `362675b`
Scope: all Rust crates, Tauri command adapters and configuration, embedded PowerShell, React/TypeScript UI, release workflow, dependency locks, and documented development/release paths.

## Executive summary

This audit found multiple critical vulnerabilities caused by combining an always-elevated process with shell interpolation, renderer-controlled destructive commands, writable executable staging, and unqualified executable names. It also found data-loss workflows, many false-success/false-health states, broken clean-clone/release paths, localization and parsing defects, UI races, and effectively no regression-test coverage.

The findings below are confirmed from source inspection, safe local reproductions, or deterministic build/tool output unless explicitly placed in the “conditional concerns” section. “Every bug” cannot be proven in the mathematical sense by a finite audit—especially without destructive tests on many Windows versions, locales, hardware configurations, and policy states—but this document records every defect found in a repository-wide pass and separates confirmed defects from conditional risks.

| Severity | Count |
|---|---:|
| Critical | 10 |
| High | 24 |
| Medium | 115 |
| Low | 9 |
| **Total confirmed findings** | **158** |

### Severity model

- **Critical:** credible administrator-level code execution, arbitrary privileged deletion, or similarly catastrophic compromise.
- **High:** likely data loss, security boundary failure, severe false assurance, or a core workflow that is unusable.
- **Medium:** material incorrect behavior, incomplete operation, reliability failure, race, or misleading output.
- **Low:** limited-scope UI, documentation, maintainability, or edge-case correctness defect.

## Critical findings

### BUG-001 — Elevated executable-search-path hijacking

**Location:** `crates/optimizer-core/src/lib.rs:3-30`; representative callers throughout the modules; `crates/optimizer-app/windows-app-manifest.xml:20`.

`silent_cmd` and `powershell` launch bare names such as `powershell`, and callers similarly launch `cmd`, `sc`, `netsh`, `chkdsk`, `fsutil`, `powercfg`, `rstrui.exe`, and others without resolving a trusted Windows path. Windows executable search can select an attacker-planted executable in the application directory before the real system binary. Because the shipped application requests administrator elevation and the “portable” build commonly runs from a user-writable folder, placing a look-alike executable beside it can produce high-integrity code execution after the user accepts UAC.

**Fix:** resolve system tools from trusted absolute paths (and handle WOW64 redirection deliberately), reject non-system replacements, and do not elevate the whole UI process.

### BUG-002 — Elevated DLL load from user-writable LocalAppData

**Location:** `crates/mod-temps/src/lib.rs:84-113,116-201`; `crates/optimizer-app/windows-app-manifest.xml:20`.

The elevated application loads `%LOCALAPPDATA%\CoveToolkit\lhm\LibreHardwareMonitorLib.dll` through `Assembly.LoadFrom`. Extraction is skipped if that one filename already exists; there is no hash, signature, owner, ACL, version, or dependency-set validation. A same-account medium-integrity process can pre-place or replace the DLL and obtain high-integrity code execution when Temperatures or report export next loads it.

**Fix:** install executable content atomically into an administrator-only directory and verify an embedded hash/signature before every load.

### BUG-003 — Predictable privileged EXE/ZIP staging enables replacement races

**Location:** `crates/mod-temps/src/lib.rs:64-81,95-107`.

The elevated process writes fixed `%TEMP%\cove-pawnio-setup.exe` and `%TEMP%\cove-lhm-bundle.zip` paths, closes them, then later executes or extracts them. Another process for the same user can collide with or replace these predictable files between operations. The installer’s embedded signature does not help because the staged file is not reverified. The ZIP path feeds directly into BUG-002.

**Fix:** create a randomized private staging directory with restrictive ACLs and exclusive creation, retain/verify handles where possible, verify hashes or Authenticode after staging, and perform atomic installation.

### BUG-004 — Renderer can execute an arbitrary elevated uninstall command

**Location:** `crates/optimizer-app/src/commands/mod.rs:1003-1007`; `crates/mod-uninstall/src/lib.rs:49-80`.

The IPC command accepts raw `uninstall_string` and `quiet_uninstall_string` values from the renderer and sends the chosen string to `cmd /C`. It does not resolve the command from a backend-owned installed-program identifier. Any caller that reaches Tauri IPC can submit an arbitrary shell command, which runs in the administrator process.

**Fix:** expose an opaque backend-issued program ID, re-read and validate the corresponding uninstall registration server-side, parse executable and arguments without `cmd.exe`, and constrain executable paths/signatures as appropriate.

### BUG-005 — Leftover remover permits arbitrary recursive privileged deletion

**Location:** `crates/optimizer-app/src/commands/mod.rs:1015-1021`; `crates/mod-uninstall/src/lib.rs:139-268`.

The IPC command accepts arbitrary path-like strings and performs recursive filesystem/registry removal plus service/task deletion. Its denylist compares lowercased strings rather than canonical identities. Deterministic bypasses include `C:\Windows\.`, `C:/Windows`, and `\\?\C:\Windows`; dangerous descendants such as `C:\Windows\System32\drivers`, `C:\Users`, and `C:\Program Files` are not denied. Registry entries use `Remove-Item -Path`, so wildcard input such as `Registry::HKLM\SOFTWARE\*` expands. Many critical tasks and services are not protected. The function also kills processes whose executable paths begin with the supplied target and schedules locked paths for reboot deletion.

**Impact:** a compromised renderer or mistaken/overbroad scan result can erase operating-system, application, user, registry, service, or scheduled-task state as administrator.

**Fix:** never accept deletion targets from the renderer. Return opaque, signed/nonce-bound scan result IDs; canonicalize and reopen targets safely; permit only descendants of narrowly approved application roots; use literal registry APIs; and positively allowlist service/task identities.

### BUG-006 — Elevated PowerShell injection in disk-space scan

**Location:** `crates/optimizer-app/src/commands/mod.rs:1323-1328`; `crates/mod-diskhealth/src/lib.rs:165-190`.

The renderer-controlled drive string is inserted inside a single-quoted PowerShell program. For example, `C'; Set-Content "$env:TEMP\cove-proof.txt" pwned; #` terminates the literal and adds a command.

**Fix:** accept and canonicalize exactly one ASCII drive letter (or a backend-enumerated volume ID), and pass data without source-code interpolation.

### BUG-007 — Elevated `cmd.exe` injection in chkdsk

**Location:** `crates/optimizer-app/src/commands/mod.rs:1331-1334`; `crates/mod-diskhealth/src/lib.rs:239-303`.

`run_chkdsk` inserts the renderer-controlled drive directly into a `cmd /C` string. A value such as `C: & whoami > "%TEMP%\cove-proof.txt" & rem ` adds arbitrary commands before the generated `: /f` suffix.

**Fix:** select only backend-enumerated volumes, validate a one-letter volume syntax, invoke `chkdsk.exe` directly with argument boundaries, and provide confirmation through child stdin rather than a shell pipe.

### BUG-008 — Registry snapshot values become elevated PowerShell code during undo

**Location:** `crates/optimizer-app/src/commands/mod.rs:577-655,779-822`; `crates/mod-performance/src/lib.rs:99-112`; `crates/mod-visual/src/lib.rs:73-91`.

Pre-apply registry values are attacker-controlled machine/user state. Undo later passes the stored string to module functions that splice it unquoted into a PowerShell `-Value` expression. A pre-planted value such as `0; <command>; #` executes when the user applies and then undoes the tweak.

**Fix:** store typed values, validate the expected registry type and range, and use Win32 registry APIs or safely bound PowerShell parameters rather than generating source.

### BUG-009 — `open_url` is an elevated `cmd /C start` injection sink

**Location:** `crates/optimizer-app/src/commands/mod.rs:1303-1309`.

The IPC-supplied URL is passed as an argument after `cmd /C start`. A safe local reproduction with Rust’s `Command` API confirmed that a no-space metacharacter payload such as `https://example.invalid&ver` executes the command after `&`. The function also returns success even if spawning fails.

**Fix:** parse and allowlist `https:` (and only other explicitly required schemes), use `ShellExecuteW`/a URL opener without `cmd.exe`, and return the actual launch result.

## High-severity findings

### BUG-010 — Failed uninstall is treated as success and followed by live-data deletion

**Location:** `ui/src/components/UninstallPanel.tsx:86-100,117-145`; backend contract at `crates/mod-uninstall/src/lib.rs:31-35,49-80`.

The UI ignores `UninstallResult.success`, announces completion after any resolved IPC call, and scans even after a rejected call. Folder and Registry findings are preselected and can then be permanently removed while the application is still installed.

**Fix:** branch on the structured result, show its error/output, stop on failure, refresh installed state, and require a separately worded explicit override before scanning after failure.

### BUG-011 — “Scan for Leftovers Only” targets applications known to be installed

**Location:** `ui/src/components/UninstallPanel.tsx:102-145,236-238,293-295`; `crates/mod-uninstall/src/scan_leftovers.ps1:56-63,76-81`.

The action is offered on the installed-program list. The scanner deliberately adds an existing install location and the live uninstall registry key, the UI preselects them, and removal is enabled. This can destroy a working application and its uninstall registration without ever running its uninstaller.

**Fix:** remove the action for installed entries or require authoritative absence detection; never classify the active install directory/registration as a removable leftover.

### BUG-012 — Broad product-name matching can delete sibling products

**Location:** `crates/mod-uninstall/src/scan_leftovers.ps1:8-17,23-81`; `ui/src/components/UninstallPanel.tsx:117-145`.

For multiword product names the scanner uses the first word as a search token. An application such as “Adobe Acrobat” can therefore match an entire `Adobe` directory or vendor registry key containing sibling products. Those Folder/Registry results are preselected for recursive deletion.

**Fix:** use exact uninstall metadata, canonical install ownership, package/product identifiers, and conservative per-file evidence. Do not automatically select ambiguous vendor-level matches.

### BUG-013 — Async uninstall results can be reassociated with another selected program

**Location:** `ui/src/components/UninstallPanel.tsx:78-145,195-207`.

Rows remain clickable while uninstall/scan/cleanup is pending. Selecting B resets shared state, after which A’s delayed promise writes A’s scan into the common state displayed under B. The user can then delete A’s paths while believing they are B’s.

**Fix:** lock selection for the operation or tag requests/results with immutable program and generation IDs and discard stale responses.

### BUG-014 — Plain-HTTP, unbounded speed test can hang or fill disk

**Location:** `crates/mod-netdiag/src/lib.rs:63-101`.

The elevated process downloads `http://speedtest.tele2.net/10MB.zip` to predictable `%TEMP%\cove_speedtest.tmp`. It reads until EOF with no total byte cap, expected-length validation, or whole-operation deadline; the configured timeout is per I/O. A network attacker can drip data indefinitely or fill the system drive, and even a one-byte HTTP 200 response is accepted as a valid speed test.

**Fix:** use authenticated HTTPS, measure a capped stream without disk, enforce a monotonic overall deadline and expected size/status, and use secure randomized temporary storage only if needed.

### BUG-015 — Complete diagnostic failure is reported as “Overall OK”

**Location:** `crates/mod-health/src/lib.rs:10-37`; `crates/mod-eventlog/src/lib.rs:56-68,91-92`; `crates/mod-bsod/src/lib.rs:20-54`; `crates/mod-updates/src/lib.rs:41-55`; aggregation at `crates/optimizer-app/src/commands/mod.rs:1061-1086`.

Health query failure yields score 100, event failure yields zero events, dump failure yields an empty list, and Windows Update failure yields no pending updates. `run_all_diagnostics` maps all four failure shapes to `Ok`, so a machine on which every underlying command fails receives the strongest possible assurance.

**Fix:** return explicit `known/complete/error` state from every module and propagate Unknown/Failed into the aggregate; never infer health from absence of data.

### BUG-016 — Diagnostic health failures produce a perfect score and “All checks passed”

**Location:** `crates/mod-health/src/lib.rs:24,28-37,45-59,98-113`; `ui/src/components/Dashboard.tsx:259-270`.

Unreadable disk and RAM queries create informational findings but deduct no points, leaving score 100. The Dashboard treats the lack of Warning/Critical findings as “All checks passed.”

**Fix:** make the score nullable/incomplete, expose coverage/confidence, and render Unknown separately from healthy.

### BUG-017 — Windows Update reset always narrates success despite failed steps

**Location:** `crates/optimizer-app/src/commands/mod.rs:280-300`.

Service stops, directory renames, and service restarts use `-ErrorAction SilentlyContinue`; the script unconditionally prints that each step succeeded and normally exits zero even when none occurred. The backend therefore commits a false success/history entry.

**Fix:** use terminating errors, validate each service state and directory transition, return step-level results, and attempt rollback/recovery on partial failure.

### BUG-018 — Privacy tweak can report success when PowerShell never started

**Location:** `crates/optimizer-app/src/commands/mod.rs:669-695`.

The code only handles the `Ok(output)` branch. If process creation returns `Err`, execution falls through to an unconditional success response and history entry.

**Fix:** match both `Ok` and `Err`, commit history only after verified state change, and return the launch error.

### BUG-019 — Snapshot/history persistence silently fails and makes rollback untrustworthy

**Location:** `crates/optimizer-app/src/commands/mod.rs:699-822,1420-1484`.

Directory creation, serialization, and writes are ignored. Reads and undo are not consistently covered by the file lock; writes are non-atomic. Concurrent operations can lose entries. Undo calls can append inner history and then overwrite it with a stale outer copy. A change may be reported committed even though no recoverable snapshot/history was saved.

**Fix:** treat snapshot durability as a prerequisite to mutation, use atomic temp-write/fsync/rename, lock the full transaction (or use a database), propagate I/O errors, and test concurrent apply/undo.

### BUG-020 — Undo may claim success without restoring anything

**Location:** `crates/optimizer-app/src/commands/mod.rs:577-655,779-822`.

If a snapshot is absent, visual/performance undo reads the already-optimized current value and writes it back, then reports/logs an undo. Snapshots are never cleared and preserve the earliest value forever, so a later apply/undo after external changes can restore stale state instead of the state immediately preceding that apply.

**Fix:** require a valid operation-specific snapshot, version snapshots per committed change, consume them only after verified restoration, and fail visibly when no rollback record exists.

### BUG-021 — History advertises Undo for changes the backend cannot undo

**Location:** `ui/src/components/HistoryPanel.tsx:28-52,89-97`; `crates/optimizer-app/src/commands/mod.rs:848-899,1420-1475`.

The UI promises all changes can be undone and renders Undo for every committed entry. The backend only supports performance, visual, privacy, and startup; cleanup, power, and services are recorded but explicitly rejected. The UI ignores the structured failure, so clicking appears to do nothing.

**Fix:** store and return `can_undo` plus the exact rollback payload, render Undo only when supported, and surface all result messages.

### BUG-022 — Startup history undo flips current state instead of restoring prior state

**Location:** `crates/optimizer-app/src/commands/mod.rs:830-839,1463-1469`.

Startup history records no original enabled state. Undo re-queries the current item and writes the logical opposite. A no-op, duplicate entry, external change, or ambiguous duplicate name therefore produces the wrong result.

**Fix:** record the exact item identity/location and before-state in the history transaction and restore that value idempotently.

### BUG-023 — Fresh clones and CI cannot compile because an embedded binary is absent

**Location:** `crates/mod-temps/src/lib.rs:23-30`; `crates/mod-temps/resources/.gitignore`; `.github/workflows/release.yml:3-9,76-85`.

`include_bytes!` requires both `LibreHardwareMonitor.zip` and `PawnIO_setup.exe`, but both are git-ignored and absent from a clean checkout. CI downloads only LibreHardwareMonitor. The workflow comments acknowledge the problem, yet its build job remains runnable and is guaranteed to fail at the missing PawnIO file.

**Fix:** provide reproducible, pinned, hash-verified acquisition of both inputs (respecting licensing), or remove binary embedding. Add a clean-clone build job.

### BUG-024 — Dependency lock contains two current RustSec vulnerabilities

**Location:** `Cargo.lock:45-46,2737-2738`.

`cargo audit` reports `anyhow 1.0.102` affected by `RUSTSEC-2026-0190` (patched in 1.0.103) and `quick-xml 0.39.4` affected by `RUSTSEC-2026-0194` and `RUSTSEC-2026-0195` (patched in 0.41.0). `quick-xml` is transitive through `plist`/`tauri-utils`; reachability depends on which parsing paths receive attacker-controlled XML, but the vulnerable code is shipped in the dependency graph.

**Fix:** update the lock/dependency constraints to patched versions and run `cargo audit` in CI.

### BUG-025 — Temperature/report reads silently install a kernel driver

**Location:** `crates/mod-temps/src/lib.rs:32-81,276-284`; automatic report call at `crates/optimizer-app/src/commands/mod.rs:354`.

Opening a read-only temperature view—or exporting a diagnostic report—can stage and silently install PawnIO as a persistent kernel service. This violates the UI/documentation’s read-only expectation and occurs without specific informed consent or a dedicated install action.

**Fix:** make driver installation an explicit, separately confirmed administrative operation; diagnostics should report that the optional provider is missing rather than mutating the system.

### BUG-026 — Uninstall remover can schedule dangerous locked paths for boot deletion

**Location:** `crates/mod-uninstall/src/lib.rs:186-223`.

When immediate removal fails, the code recursively enumerates the supplied tree and calls `MoveFileEx(..., MOVEFILE_DELAY_UNTIL_REBOOT)` for files/directories without proving ownership or an approved root. Combined with the canonicalization failures in BUG-005, an apparently failed cleanup can become delayed system destruction at reboot.

**Fix:** remove the generic reboot-deletion fallback; permit it only for backend-owned, canonical, narrowly scoped application paths after explicit confirmation and auditable validation.

## Medium-severity findings — mutation, state, and UI workflows

### BUG-027 — Power timeout reports success after a partial AC-only change

**Location:** `crates/optimizer-app/src/commands/mod.rs:904-931`.

For display and sleep, the AC `powercfg` result controls the response, while the corresponding DC command result is discarded. A failed battery-setting change is therefore reported as complete. **Fix:** invoke `powercfg` directly, validate both exits and final queried values, and return partial failure details.

### BUG-028 — Presets return overall success even when every action fails

**Location:** `crates/optimizer-app/src/commands/mod.rs:1115-1146`.

Any recognized preset returns `"success": true`; only the counters disclose that actions failed. Consumers therefore display a completed preset even when `succeeded == 0`. **Fix:** define success as all required actions succeeding (or an explicit partial status) and surface per-action messages.

### BUG-029 — DNS change reports success when no eligible adapter exists

**Location:** `crates/optimizer-app/src/commands/mod.rs:195-218`.

The PowerShell pipeline may select zero `Up` adapters, execute no change, and still emit `OK`, which the backend treats as success. It also changes every Up adapter—including VPN/virtual interfaces—rather than the active route. **Fix:** select the intended default-route interface, require at least one verified change, and return per-interface results.

### BUG-030 — Bloatware removal hides failed deprovisioning

**Location:** `crates/mod-bloatware/src/lib.rs:119-142`.

Current packages are removed with terminating errors, but provisioned-package removal uses `SilentlyContinue`. The overall PowerShell exit can be zero and the result says removed even though the package remains provisioned for new users. **Fix:** make both phases terminating/checked and report current-user, all-user, and provisioned outcomes separately.

### BUG-031 — Bloatware inventory query failure makes every package look absent

**Location:** `crates/mod-bloatware/src/lib.rs:80-103`.

AppX/provisioning errors are silenced and JSON/process/parse failures collapse to an empty installed list. The UI then presents a definitive “not installed” inventory. **Fix:** return query state/errors and distinguish installed, absent, and unknown.

### BUG-032 — Unknown tweak modules return a fabricated success

**Location:** `crates/optimizer-app/src/commands/mod.rs:496-546`.

The generic apply dispatcher falls through to a success placeholder for an unrecognized module/action instead of rejecting it. This can create a history entry and success UI without changing the machine. **Fix:** make dispatch exhaustive and return a typed unknown-action error.

### BUG-033 — Report export and snapshot save ignore file-operation failures

**Location:** `crates/optimizer-app/src/commands/mod.rs:345-468,1175-1203`.

Directory creation, serialization, file writes, and report opening are ignored; both commands still return success. A read-only/full disk or bad path therefore produces “exported”/“saved” with no usable file. **Fix:** propagate each I/O/launch error, use atomic writes, and return the verified final path.

### BUG-034 — Blocking system operations run directly inside async Tauri commands

**Location:** representative commands `crates/optimizer-app/src/commands/mod.rs:904-1021,1331-1341`; contrast the `spawn_blocking` wrappers used elsewhere.

PowerShell, uninstallers, recursive deletion, chkdsk, bloatware removal, and other blocking work are executed directly in async handlers. Long operations can occupy Tauri/Tokio worker threads, delaying unrelated IPC and making the UI appear hung. **Fix:** consistently move blocking work to a bounded blocking pool and add cancellation/progress where operations can be long.

### BUG-035 — Activation can report the wrong Windows license

**Location:** `crates/optimizer-app/src/commands/mod.rs:1387-1407`.

The query/deserializer evaluates only the first matching licensing product. Systems can have multiple Windows licensing records; an unlicensed first row can mask a licensed record. **Fix:** evaluate all applicable Windows products and choose the active OS license using ApplicationID/SKU plus `LicenseStatus == 1`.

### BUG-036 — Startup items are identified and toggled by non-unique display name

**Location:** `crates/mod-startup/src/lib.rs:17-81,101-190`; `crates/optimizer-app/src/commands/mod.rs:830-839,1463-1469`.

The list deduplicates by name and toggle searches locations by name. Two items with the same name in HKCU/HKLM/startup folders collapse into one row; disabling one can leave another active while reporting success, and undo can target a different item. **Fix:** use a stable identity containing hive/view/path/value name or exact file identity.

### BUG-037 — Startup line protocol corrupts names or commands containing `|`

**Location:** `crates/mod-startup/src/lib.rs:17-81`.

PowerShell emits pipe-delimited records and Rust splits by `|`; valid registry names or command lines containing that character shift fields and break identity/state. **Fix:** serialize structured JSON.

### BUG-038 — Startup inventory omits common startup locations

**Location:** `crates/mod-startup/src/lib.rs:17-52`.

The implementation does not enumerate the all-users Startup folder and does not provide complete coverage of registry views/other standard startup sources. The panel consequently presents a partial list as the machine’s startup inventory. **Fix:** define and display coverage, enumerate both user/common folders and 32/64-bit registry views, or rename the feature to its actual scope.

### BUG-039 — Performance Apply/Undo UI marks resolved backend failures successful

**Location:** `ui/src/components/PerformancePanel.tsx:33-54`; result contract in `crates/optimizer-app/src/commands/mod.rs:630-666`.

The panel ignores `{success:false,message}` and flips local applied state after any resolved IPC call. A registry failure therefore shows Done/Undo as if it succeeded. **Fix:** type and branch on the response, display the message, and reload authoritative state.

### BUG-040 — DNS provider highlighting is incorrect and optimistic

**Location:** `ui/src/components/NetDiagPanel.tsx:66-71,111-130`; mock example `ui/src/lib/tauri.ts:622-632`.

Detection compares only the first DNS address, so a mixed pair is labeled as a provider; custom DNS leaves the initial “Automatic” option highlighted. Selection is updated before the backend result and is not rolled back on failure. **Fix:** compare the complete ordered/unordered pair as intended and update UI only after verified success/reload.

### BUG-041 — Power controls have stale-response races

**Location:** `ui/src/components/PowerPanel.tsx:55-99,116-147`.

Controls remain enabled while an IPC update is pending, and each closure captures its own previous state. Out-of-order A/B completion or failure can leave the UI disagreeing with the real plan/timeouts. **Fix:** serialize changes or use request generations and reload authoritative values.

### BUG-042 — Applied-state panels reset on navigation and contradict machine state

**Location:** `ui/src/components/PerformancePanel.tsx:19-24,83,109-130`; `VisualPanel.tsx:17-22,84,103-125`; `PrivacyPanel.tsx:31-40,97-133`; `ServicesPanel.tsx:29-34,90-122`.

All initialize `applied={}` on mount instead of deriving state from current versus target values or backend history. Navigating away/back removes Done/Undo and offers duplicate Apply even for an already-applied setting. **Fix:** make the backend’s authoritative current/before/undo state part of each response.

### BUG-043 — Snapshot UI ignores save failures and retains stale diff data

**Location:** `ui/src/components/DiffPanel.tsx:53-77,122-155`; backend `crates/optimizer-app/src/commands/mod.rs:1175-1203`.

Any resolved call becomes “Snapshot Saved” even when `success:false`. After a new snapshot, the displayed old diff/timestamp is not refreshed. The UI also promises that running diagnostics saves a baseline, but `run_all_diagnostics` never calls `take_snapshot`. **Fix:** check the result, refresh/clear diff, and either implement or remove the automation claim.

### BUG-044 — Dashboard crashes on structured backend failure

**Location:** `ui/src/components/Dashboard.tsx:283-310,387-407,435-444`; fallback at `crates/optimizer-app/src/commands/mod.rs:29-37,1086,1146`.

Dashboard stores a join-failure object and unconditionally calls `diagResult.modules.map`; `run_preset` failure similarly leaves counts undefined. There is no shape/success validation, so a normal backend error can crash the view. **Fix:** use discriminated response types, validate success before rendering, and add an error boundary.

### BUG-045 — Successful uninstall leaves a stale installed-program row

**Location:** `ui/src/components/UninstallPanel.tsx:64-69,166-172`.

The list loads once and reset only clears detail state. A successfully removed application remains listed and can be selected/uninstalled/scanned again. **Fix:** remove the verified item or reload inventory after completion.

### BUG-046 — Cleanup, Startup, and History silently swallow resolved failures

**Location:** `ui/src/components/CleanupPanel.tsx:64-81`; `StartupPanel.tsx:29-48`; `HistoryPanel.tsx:28-42`.

These panels either ignore `{success:false,message}` or do not render per-target failure results, leaving users with no explanation for permission, locked-resource, or unsupported-undo failures. **Fix:** render overall and per-item results and retain failed selections for retry.

### BUG-047 — Global CSS selector collisions corrupt unrelated panels

**Location:** all styles imported at `ui/src/components/CategoryPanel.tsx:5-27`; examples `SysInfoPanel.css:88-110` vs `Dashboard.css:198-210`, `SecurityPanel.css:255-310` vs `HealthPanel.css:62-78`, `DiskHealthPanel.css:92-106` vs `CleanupPanel.css:21-37`, `UninstallPanel.css:346-362` vs `CleanupPanel.css:46-62`, and `SecurityPanel.css:131-173` vs `SfcPanel.css:314-356`.

Unscoped generic classes such as `.card-title`, `.finding-*`, `.stat-value`, `.select-all-btn`, and `.scan-live` override one another based on import order, visibly restyling unrelated screens. **Fix:** scope every stylesheet under a unique component root or use CSS modules.

### BUG-048 — Destructive confirmation dialog is not an accessible/contained modal

**Location:** `ui/src/components/ConfirmDialog.tsx:24-47`.

The dialog is plain `div` markup without `role=dialog`, `aria-modal`, label association, focus placement/trap/restore, Escape behavior, or inert background. Keyboard focus remains behind the overlay and can activate unrelated/destructive controls. **Fix:** use the native `<dialog>` element or implement the complete WAI-ARIA modal pattern and inert background.

### BUG-049 — Browser-development mock backend is incomplete and contract-inaccurate

**Location:** `ui/src/lib/tauri.ts:5-9,215-414,622-632,799-871,1018-1042`; consumers including `BloatwarePanel.tsx:47-53`, `CleanupPanel.tsx:68-76`, `TempsPanel.tsx:13-17`, and `SecurityPanel.tsx:5-11`.

Several invoked commands have no mock (`get/remove_bloatware`, SFC scan/status, security scan/status, Windows Security launch). Unknown commands return `{}` cast to arbitrary `T`; Bloatware then calls `.filter` on `{}` and can crash the React root. Existing cleanup, temperature, Defender, privacy, and service shapes diverge from Rust contracts. **Fix:** derive typed mocks from shared schemas, cover every command, and reject unknown commands loudly.

### BUG-050 — Update history can render “Invalid Date” and contradictory zero days

**Location:** `crates/mod-updates/src/lib.rs:35-39,75-81,113-115`; `ui/src/components/UpdatesPanel.tsx:76-85`; `ui/src/lib/format.ts:11-25`.

The backend uses `Never`/`Unknown` strings while leaving `days_since_last_update` at zero. `timeAgo` never checks `Date.getTime()`, so the UI can show “Invalid Date” alongside “0 days.” **Fix:** model absent/unknown dates as nullable typed values and validate before formatting.

### BUG-051 — Disk Health hardcodes `C:` rather than the system volume

**Location:** `ui/src/components/DiskHealthPanel.tsx:122-137,239-245`.

Largest-file and chkdsk requests always use C even though the text says “system volume.” Windows installed on another volume is diagnosed/repaired incorrectly. **Fix:** return `%SystemDrive%`/enumerated volume identity from the backend and let the user select the intended volume.

## Medium-severity findings — diagnostics and reporting

### BUG-052 — Health KB-to-byte conversion can overflow

**Location:** `crates/mod-health/src/lib.rs:103-109`.

Externally supplied `u64` counters are multiplied by 1024 without checked arithmetic. Debug builds panic; release builds wrap and can produce a nonsensical health score. **Fix:** use checked/saturating conversion and mark overflowed data Unknown.

### BUG-053 — “Outdated drivers” is permanently hardcoded to zero

**Location:** `crates/mod-drivers/src/lib.rs:56-71`; advertised at `README.md:31`; exported by `crates/mod-report/src/lib.rs:57-61`.

No update/version comparison exists, yet every inventory/report claims zero outdated drivers. **Fix:** implement a defensible update-source comparison or remove the field and advertised capability.

### BUG-054 — Driver query failure is presented as a valid zero-driver audit

**Location:** `crates/mod-drivers/src/lib.rs:25-37,56-71`.

PowerShell/CIM/process/parse failure returns totals of zero rather than Unknown. **Fix:** return `Result` or explicit query/coverage state.

### BUG-055 — Unknown driver signature state is counted as unsigned

**Location:** `crates/mod-drivers/src/lib.rs:28,46-54`.

PowerShell’s false branch conflates `$false` with `$null`; unavailable signature data becomes an unsigned-driver warning. **Fix:** preserve signed/unsigned/unknown as separate states.

### BUG-056 — Driver inventory silently omits devices with a missing name/version

**Location:** `crates/mod-drivers/src/lib.rs:25-27,40-54`.

The query filters records missing either property, so `total` is not the actual inventory total and failure-prone devices disappear. **Fix:** retain the records and mark individual properties Unknown.

### BUG-057 — Event counts silently cap at 2,000 but are labeled totals

**Location:** `crates/mod-eventlog/src/lib.rs:44-60`.

Each severity query uses a 2,000-event limit and the returned vector length as the count. Busy systems therefore report exactly 2,000 rather than the true total with no truncation indicator. **Fix:** issue an independent count query or expose `truncated` and the cap.

### BUG-058 — “Recent events” are grouped by severity, not recency

**Location:** `crates/mod-eventlog/src/lib.rs:54-61,70-87`.

Critical records are appended before Errors and Warnings without a final timestamp sort. A six-day-old Critical can precede a one-minute-old Error in a list called recent. **Fix:** merge then sort descending by parsed event time.

### BUG-059 — Event-log time window is hidden from users

**Location:** `crates/mod-eventlog/src/lib.rs:44-57`; event UI count labels.

Queries cover seven days, but the response/UI labels simply state errors/warnings, suggesting all-log totals. **Fix:** expose and display `window_start`/`window_days`.

### BUG-060 — Event-log query failure looks like a clean log

**Location:** `crates/mod-eventlog/src/lib.rs:56-68,91-92`.

PowerShell catches, process errors, and parse errors collapse to zero events without an error state. This affects both the panel and overall diagnostics. **Fix:** preserve per-log/per-level errors and never equate unknown with zero.

### BUG-061 — Chkdsk exit codes are interpreted incorrectly

**Location:** `crates/mod-diskhealth/src/lib.rs:253-267,289-303`.

Any nonzero exit becomes `success=false`, although Microsoft documents code 1 as errors found and fixed and gives code 2 a defined cleanup/no-`/f` meaning. The message can simultaneously say completed and return failure. See [Microsoft chkdsk exit codes](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/chkdsk). **Fix:** model launch success separately from clean/fixed/unfixed status and interpret codes per mode.

### BUG-062 — Chkdsk confirmation and scheduling detection are locale-dependent

**Location:** `crates/mod-diskhealth/src/lib.rs:279-303`.

`echo Y` assumes the localized affirmative character, and output detection searches English phrases (`next time`, `scheduled`, `dismount`). Non-English systems fail or misreport; an immediate force-dismount can also be marked “scheduled for reboot.” OEM-code-page output is decoded as UTF-8. **Fix:** use native state/events and correct encoding instead of prose matching.

### BUG-063 — “Last chkdsk” can return an older event and miss online scans

**Location:** `crates/mod-diskhealth/src/lib.rs:352-363`.

The code queries Chkdsk events only if no Wininit/1001 exists, so any old boot-time event masks newer online results. It requests Chkdsk/26214 but omits the commonly emitted `/scan` event 26226. **Fix:** query all relevant providers/IDs together and select the newest timestamp.

### BUG-064 — Dirty-bit detection is English-only

**Location:** `crates/mod-diskhealth/src/lib.rs:344-350,384-386`.

The parser searches English `fsutil` output; on other Windows display languages it silently returns `dirty_bit=false`. **Fix:** use a native API or locale-independent result source and represent query failure.

### BUG-065 — Unknown physical-disk health is labeled Critical

**Location:** `crates/mod-diskhealth/src/lib.rs:138-157`.

Every status other than exact `Healthy`, including unsupported/`Unknown`, becomes Critical. **Fix:** map Healthy, Warning, Unhealthy, and Unknown separately.

### BUG-066 — TRIM state is modeled at the wrong scope and hides errors

**Location:** `crates/mod-diskhealth/src/lib.rs:112-127`.

Any `= 0` line from `fsutil behavior query DisableDeleteNotify` marks every SSD/NVMe as enabled even though output can differ for NTFS and ReFS. Query failure becomes false and the UI says “TRIM Off.” **Fix:** represent filesystem/volume-specific optional state.

### BUG-067 — Largest-file scan is unbounded and non-cancellable

**Location:** `crates/mod-diskhealth/src/lib.rs:174-186`.

`Get-ChildItem -Recurse | Sort-Object | Select -First 5` materializes and sorts the entire Users tree. Large profiles can consume substantial memory and run indefinitely, with no cancellation or coverage warning. **Fix:** maintain a bounded top-five while streaming, add cancellation/deadline, and report inaccessible paths.

### BUG-068 — Disk query/parse failure looks like no disks or a zero-size drive

**Location:** `crates/mod-diskhealth/src/lib.rs:83-130,199-226`.

Failed PowerShell, command, and parsing paths default to empty/zero data without a query state. **Fix:** return typed partial results plus errors/coverage.

### BUG-069 — Disk reliability-counter addition can overflow into “Good”

**Location:** `crates/mod-diskhealth/src/lib.rs:152-153`.

Two external `u64` error counters are added unchecked. Debug builds can panic; release wrapping can turn severe counts into a low/zero value. **Fix:** use `saturating_add` or checked arithmetic with Unknown on overflow.

### BUG-070 — Storage temperature of exactly zero is discarded

**Location:** `crates/mod-diskhealth/src/lib.rs:72`.

PowerShell truthiness treats numeric zero as false and emits no temperature. This is uncommon but valid in cold environments/sensor test conditions. **Fix:** test for `$null`, not truthiness.

### BUG-071 — Delimiter protocols corrupt legitimate diagnostic data

**Location:** `crates/mod-drivers/src/lib.rs:31,40-46`; `mod-diskhealth/src/lib.rs:77,86-94`; `mod-eventlog/src/lib.rs:59,72-86`; `mod-netdiag/src/lib.rs:121,125-135`.

Hand-built pipe-delimited PowerShell records are split positionally. Adapter names, providers, models, or messages containing `|` shift fields and create false identities/status. **Fix:** emit compressed JSON and deserialize typed objects.

### BUG-072 — Localized speed values parse as successful 0 Mbps

**Location:** `crates/mod-netdiag/src/lib.rs:83-101`.

PowerShell formats numbers with the current culture; a comma decimal such as `12,34` fails Rust’s `f64` parser and becomes `0.0` while status remains `ok`. **Fix:** emit invariant JSON numbers and fail/mark Unknown on parse error.

### BUG-073 — “Primary adapter” is simply the first Up adapter

**Location:** `crates/mod-netdiag/src/lib.rs:113-135,147-158`.

The first Up adapter may be VPN/vEthernet/non-routing, while connectivity testing independently picks a first gateway and can describe another interface. **Fix:** select the lowest-metric active default route and resolve all displayed/tested data through that interface.

### BUG-074 — IPv6-only networks appear to lack network configuration

**Location:** `crates/mod-netdiag/src/lib.rs:117-121,147-158`.

Only IPv4 address, gateway, and AddressFamily 2 DNS are queried. **Fix:** model and test both address families.

### BUG-075 — Captive portals can pass the Internet test

**Location:** `crates/mod-netdiag/src/lib.rs:170-181`.

`Invoke-WebRequest` follows redirects and accepts any final HTTP 200 without checking the expected Microsoft connectivity-test body. A captive login page is therefore “Internet connected.” **Fix:** validate the exact body/redirect policy or use the Windows Network List Manager state with explicit semantics.

### BUG-076 — ICMP filtering is mislabeled as gateway unreachable

**Location:** `crates/mod-netdiag/src/lib.rs:149-158`.

A reachable router that intentionally drops ping becomes a failed gateway test. **Fix:** label it “no ICMP reply” and corroborate with route/neighbor/TCP signals.

### BUG-077 — Wi-Fi parser breaks on localized labels and colon-containing SSIDs

**Location:** `crates/mod-netdiag/src/lib.rs:205-234`.

It searches the English `Channel` label, and `.split(':').nth(1)` truncates an SSID such as `Corp:Guest` to `Corp`. OEM-code-page `netsh` bytes are also treated as UTF-8, corrupting accented names. **Fix:** use the native WLAN API or locale/code-page-aware structured parsing and split only once.

### BUG-078 — Wi-Fi channel cannot identify 6 GHz band

**Location:** `crates/mod-netdiag/src/lib.rs:231-234`.

Channels above 14 are labeled 5 GHz and lower channels 2.4 GHz, but 6 GHz reuses/overlaps channel numbers. **Fix:** obtain actual center frequency/band from WLAN radio data.

### BUG-079 — Multiple WLAN interfaces can be merged into one fictional record

**Location:** `crates/mod-netdiag/src/lib.rs:214-229`.

The parser uses one accumulator across `netsh` output and can combine SSID, signal, and channel values from different interfaces. **Fix:** parse per-interface blocks or use WLAN interface GUIDs.

### BUG-080 — Failed connectivity tests display a 0 ms latency

**Location:** `crates/mod-netdiag/src/lib.rs:155-181,190-197`.

Failure records carry `Some(0)` rather than no latency, so the UI displays a plausible zero-millisecond measurement alongside failure. **Fix:** use `None` for absent timing.

### BUG-081 — Sysinfo command failure yields a valid-looking empty report

**Location:** `crates/mod-sysinfo/src/gather.ps1:1-16`; `crates/mod-sysinfo/src/lib.rs:117-140`.

PowerShell queries globally silence errors, process status/stderr is ignored, and deserialization failure returns `FullSystemInfo::default()`. Restricted/broken WMI can therefore produce a successful report with zero RAM/GPU/monitor data. **Fix:** collect per-section state/errors and make top-level parse/launch failures explicit.

### BUG-082 — Sysinfo CPU topology uses only the first socket

**Location:** `crates/mod-sysinfo/src/gather.ps1:5,206-213`.

Multi-socket machines report only the first processor’s cores/logical processors. **Fix:** retain per-socket records and sum appropriate totals.

### BUG-083 — ACPI thermal zone is mislabeled as CPU temperature

**Location:** `crates/mod-sysinfo/src/gather.ps1:18-25,213`; parallel fallback `crates/mod-temps/src/lib.rs:234-273`.

`MSAcpi_ThermalZoneTemperature` is often a motherboard/firmware zone, not CPU package temperature, and may be stale. **Fix:** label it accurately or use a hardware sensor API and enforce plausibility/known state.

### BUG-084 — Monitor resolutions are paired by unrelated array index

**Location:** `crates/mod-sysinfo/src/gather.ps1:90-113`.

WmiMonitorID enumeration and Win32_VideoController enumeration have no one-to-one ordering; multi-monitor systems can get blank/wrong resolutions or the adapter’s aggregate/current mode. **Fix:** use Windows display-configuration/EDID APIs that map targets to sources.

### BUG-085 — CPU architecture is reduced to address width

**Location:** `crates/mod-sysinfo/src/gather.ps1:194-213`.

ARM64 and x64 both become `64-bit`, so the field named architecture does not identify the architecture. **Fix:** map `Win32_Processor.Architecture` separately from OS address width.

### BUG-086 — Memory-slot count includes non-system-memory arrays

**Location:** `crates/mod-sysinfo/src/gather.ps1:190-192`.

`MemoryDevices` is summed for every physical-memory array; firmware can expose cache/video arrays and inflate DIMM slots. **Fix:** filter `Win32_PhysicalMemoryArray.Use == 3`.

### BUG-087 — Storage media type and NVMe detection use model-name guesses

**Location:** `crates/mod-sysinfo/src/gather.ps1:51-63`.

Devices are labeled SSD/NVMe only when English model text contains matching tokens. NVMe commonly appears as SCSI through Win32_DiskDrive and SSD models need not contain “SSD,” producing wrong media/interface data. **Fix:** use MSFT_PhysicalDisk/storage/device-bus properties.

### BUG-088 — One sysinfo schema mismatch discards every successful section

**Location:** `crates/mod-sysinfo/src/lib.rs:118-124`.

Deserialization is all-or-nothing; a single field shape/version drift returns a complete default report. **Fix:** deserialize sections independently or return a typed top-level error plus raw partial data.

### BUG-089 — GPU VRAM fallback can understate adapters over 4 GiB

**Location:** `crates/mod-sysinfo/src/gather.ps1:67-86`.

When the registry lookup misses, it falls back to the historically 32-bit `AdapterRAM` value, which can wrap/truncate large VRAM. **Fix:** use DXGI/display APIs or a verified 64-bit source and mark unavailable data Unknown.

### BUG-090 — Partial LHM data suppresses the missing-CPU explanation

**Location:** `crates/mod-temps/src/lib.rs:276-315`.

If any GPU/board reading exists, the function returns before adding `cpu_note`, even when CPU sensors are absent, PawnIO was just installed, or its service is broken. **Fix:** calculate CPU coverage/note before every return.

### BUG-091 — PawnIO “installed” check accepts a stopped/broken/wrong service

**Location:** `crates/mod-temps/src/lib.rs:32-39,60-81`.

`sc query PawnIO` success proves only service registration, not running state, binary path, signature, or compatible version. **Fix:** inspect service configuration/state/version/path and report reboot-required separately.

### BUG-092 — LHM extraction is never repaired or upgraded

**Location:** `crates/mod-temps/src/lib.rs:89-113`.

The existence of one DLL bypasses extraction forever. Interrupted extraction can leave missing dependencies, and application upgrades continue loading an old or vulnerable library. **Fix:** use versioned, hashed manifests and atomic directory replacement.

### BUG-093 — Subhardware sensors are updated but never enumerated

**Location:** `crates/mod-temps/src/lib.rs:137-159`.

The script updates subhardware but iterates only top-level hardware sensors, omitting common motherboard Super-I/O readings. **Fix:** recursively enumerate each `SubHardware.Sensors` collection.

### BUG-094 — Temperature collection has cross-call and cross-process races

**Location:** `crates/mod-temps/src/lib.rs:60-113,276-324`; periodic UI calls.

Concurrent panel refresh, export, or multiple app instances can stage/run the same installer, overwrite/read the same ZIP, and load a partially extracted directory. **Fix:** add process-wide and named cross-process locks plus atomic staging.

### BUG-095 — Apostrophes in profile paths break/inject temperature scripts

**Location:** `crates/mod-temps/src/lib.rs:99-103,116-120`.

Paths are inserted into single-quoted PowerShell strings without escaping. A legitimate profile such as `C:\Users\O'Brien` breaks the script; a crafted inherited environment path can add commands. **Fix:** pass encoded/bound parameters or correctly escape single quotes and validate paths.

### BUG-096 — Generic temperature thresholds misclassify hotspot/junction sensors

**Location:** `crates/mod-temps/src/lib.rs:149-157`.

The same CPU/GPU limits are assigned to every sensor in a category even though core, package, hotspot, memory-junction, VRM, and board sensors have different supported ranges. **Fix:** use sensor-specific metadata or avoid claiming thresholds when unknown.

### BUG-097 — Defender last-scan timestamp and type can refer to different scans

**Location:** `crates/mod-security/src/lib.rs:49-52`.

Timestamp always uses `LastQuickScanEndTime`, while type can be Full. A full-only history becomes `last_scan=Never`, `last_scan_type=Full`. **Fix:** compare both scan timestamps and return the matching later type/time.

### BUG-098 — Future Defender definition timestamp becomes known and fresh

**Location:** `crates/mod-security/src/lib.rs:49,61-67`.

Clock skew produces a negative age that fails `u32` parsing and defaults to zero while `known=true`. **Fix:** retain signed duration, detect future/skewed values, and report Unknown/error.

### BUG-099 — Hosts scan is hardcoded to C:\Windows and UTF-8

**Location:** `crates/mod-security/src/lib.rs:166-184`.

Windows installed elsewhere is skipped. One valid non-UTF-8 byte makes `read_to_string` fail and silently disables the whole check. **Fix:** use `%SystemRoot%`, decode BOM/active code page safely, and surface read coverage/errors.

### BUG-100 — Browser extension scan covers only default Chromium profiles

**Location:** `crates/mod-security/src/lib.rs:186-213`.

Only Chrome/Edge `Default\Extensions` directories are counted. Other profiles, Guest, and Firefox are invisible, yet the result reads as a general extension heuristic. **Fix:** enumerate supported browsers/profiles and display coverage.

### BUG-101 — Heuristic probe failures become “No suspicious indicators”

**Location:** `crates/mod-security/src/lib.rs:144-213`; runner integration.

Failed process, hosts, or extension probes are silently skipped. The scan runner still completes successfully and a zero-length result is presented as clean. **Fix:** return per-probe status/errors and mark incomplete scans Unknown.

### BUG-102 — Public security `run_scan` fabricates zero threats

**Location:** `crates/mod-security/src/lib.rs:93-117`.

The function only starts Defender but returns `threats_found=0`, and invalid scan types silently become Quick. It currently has no repository caller, but its public contract is wrong. **Fix:** reject invalid types and omit threat counts until result/status is queried.

### BUG-103 — BSOD scan ignores configured dump locations

**Location:** `crates/mod-bsod/src/lib.rs:18-33`.

Only default `%SystemRoot%` paths are scanned; configured `CrashControl\MinidumpDir`, `DumpFile`, and dedicated dump paths are ignored. **Fix:** read/expand CrashControl settings and deduplicate canonical files.

### BUG-104 — BSOD access failure is displayed as “No crash dumps found”

**Location:** `crates/mod-bsod/src/lib.rs:20-54`.

Enumeration/metadata errors are silenced and the response has no known/error state. **Fix:** return coverage and path-specific errors.

### BUG-105 — Empty BSOD state hardcodes the wrong scan path/scope

**Location:** `ui/src/components/BsodPanel.tsx:35-41`; backend scope at `crates/mod-bsod/src/lib.rs:18-33`.

The empty state says no files were found in `C:\Windows\Minidump`, even when `%SystemRoot%` is another drive and even though the backend also checks the full memory-dump path. **Fix:** return/display the actual scanned paths and coverage from the backend.

### BUG-106 — Exported temperatures are always formatted as 0°C

**Location:** `crates/mod-temps/src/lib.rs:3-9`; `crates/optimizer-app/src/commands/mod.rs:400-405`.

`temperature_c` serializes as an `f64`, but report construction calls `as_i64()`, which returns `None` for floating JSON numbers and defaults to zero. **Fix:** use `as_f64()` and intentional decimal formatting.

### BUG-107 — Defender Unknown becomes “Protection OFF / definitions 0 days” in reports

**Location:** `crates/mod-security/src/lib.rs:9-11,72-79`; `crates/optimizer-app/src/commands/mod.rs:436-440`.

Report integration ignores `known`, converting query failure/defaults into a definitive disabled/outdated claim. **Fix:** propagate and render Unknown.

### BUG-108 — Windows Update query failure becomes “System is up to date”

**Location:** `crates/mod-updates/src/lib.rs:41-55`; `crates/mod-report/src/lib.rs:71-76`; `ui/src/components/UpdatesPanel.tsx:94-96`.

WUA exceptions set the pending list empty; both UI and report treat empty as authoritative success. **Fix:** carry search success/error independently of the result list.

### BUG-109 — Windows Update `last_check` is actually `last_install`

**Location:** `crates/mod-updates/src/lib.rs:31-39,90-93`.

The field is directly cloned from `last_install`, and the history entry is not filtered to successful Installation operations, so uninstall/failure history can also be mislabeled as last installed update. **Fix:** retrieve a real detection/check timestamp and filter successful install operations/results.

### BUG-110 — Report content fails to escape ampersands

**Location:** `crates/mod-report/src/lib.rs:32-40`.

Escaping `<` and `>` without first escaping `&` corrupts literal evidence such as `&lt;tag&gt;` or `&copy;` when rendered. **Fix:** escape `&`, then `<`, `>`, quotes as appropriate, using a proven HTML encoder.

### BUG-111 — Public report title/headings permit raw HTML injection

**Location:** `crates/mod-report/src/lib.rs:2-6,24-25,37-40`.

`generate_html_report` inserts its public title and heading strings directly into markup. Current call sites pass constants, so this is latent rather than renderer-reachable today, but a caller-supplied `</title><script>…` executes in the exported page. **Fix:** encode every field and add a restrictive report CSP.

### BUG-112 — “Run All Diagnostics” does not run all diagnostic modules

**Location:** `crates/optimizer-app/src/commands/mod.rs:1061-1086`; diagnostics advertised in `README.md:27-37`.

The command covers only health, Event Log, BSOD, and Windows Update (plus activation metadata), omitting drivers, network, security, runtimes, disk health, temperature, and other diagnostic features. **Fix:** rename it to its actual scope or orchestrate all advertised diagnostics with explicit coverage/progress.

### BUG-113 — Dashboard health description claims unperformed CPU/SMART checks

**Location:** `ui/src/components/Dashboard.tsx:113-116,259-270`; `crates/mod-health/src/lib.rs:28-37`.

Dashboard says health covers Disk, RAM, CPU, and SMART, but the health module only scores disk free space and RAM availability. **Fix:** implement those checks or correct the description and confidence model.

## Additional security and mutation findings

### BUG-114 — Bloatware IPC accepts wildcard removal of all AppX packages (Critical)

**Location:** `crates/optimizer-app/src/commands/mod.rs:986-989`; `crates/mod-bloatware/src/lib.rs:119-125`.

The renderer supplies arbitrary package strings. `Get-AppxPackage -AllUsers -Name '*'` selects all AppX packages and pipes them to `Remove-AppxPackage -AllUsers`; the backend never requires membership in its own bloatware catalog. **Fix:** accept opaque catalog IDs and enforce exact server-side membership/package identity before removal.

### BUG-115 — Untrusted scan metadata injects protected descendants into leftovers (High)

**Location:** `crates/optimizer-app/src/commands/mod.rs:1009-1012`; `crates/mod-uninstall/src/scan_leftovers.ps1:56-82,114-133`.

IPC-controlled `install_location` and `registry_key` values are added directly to scan results. Protection is exact-string-only, so `C:\Windows\System32` is accepted even though `C:\Windows` is listed as protected. This makes destructive candidates look like backend-discovered leftovers before BUG-005’s remover handles them. **Fix:** re-resolve all metadata from a backend-owned installation record and validate canonical descendants before returning a candidate.

### BUG-116 — System Protection status uses an unrelated registry setting (High)

**Location:** `crates/mod-restore/src/lib.rs:24-55`.

The module treats nonzero `RPSessionInterval` as protection enabled and zero as disabled. Microsoft documents that value as the scheduled in-session checkpoint interval, with a default of zero—not the per-volume protection state. Enabled systems can therefore be told protection is off. See [Microsoft SystemRestoreConfig](https://learn.microsoft.com/en-us/windows/win32/sr/systemrestoreconfig). **Fix:** query actual per-volume System Restore/protection configuration and preserve Unknown on query failure.

### BUG-117 — Cleanup roots trust inherited environment variables (High)

**Location:** `crates/mod-cleanup/src/lib.rs:14-23,43-52,87-140`; elevated manifest `crates/optimizer-app/windows-app-manifest.xml:20`.

Targets are constructed from inherited `%TEMP%`, `%SystemRoot%`, and `%LocalAppData%` with no trusted-root/canonical validation. A process launching the app with a crafted environment can redirect a labeled cleanup target to an arbitrary tree; cleanup then deletes files at high integrity. `-Path` also interprets wildcard characters in those paths. **Fix:** obtain Windows/profile directories through trusted OS APIs, canonicalize/reopen them, require exact expected roots, and use literal filesystem APIs.

### BUG-118 — Release workflow embeds unpinned “latest” executable code (High)

**Location:** `.github/workflows/release.yml:76-85`; load path `crates/mod-temps/src/lib.rs:23,116-201`.

CI downloads LibreHardwareMonitor from a mutable `latest` URL without a version pin, checksum, or signature verification, then embeds and later loads its DLLs in an elevated process. Builds are neither reproducible nor protected against an upstream/release-asset substitution. **Fix:** pin a reviewed version and verify a repository-controlled SHA-256/Authenticode identity before build.

### BUG-119 — Local Tauri build hook resolves outside the repository (High)

**Location:** `crates/optimizer-app/tauri.conf.json:7-10`; documented command `README.md:78-87`.

The configured `beforeBuildCommand` is `pnpm --prefix ../../ui build`. In the workspace CLI context, a local `cargo tauri build` resolves it to the sibling `projects\ui`, which does not exist; this was reproduced locally. The release workflow works around it by blanking the hook, leaving the documented build broken. **Fix:** use the correct hook working directory/path and exercise the documented root command in CI.

### BUG-120 — Documented Tauri dev command does not start Vite (High)

**Location:** `crates/optimizer-app/tauri.conf.json:8-10`; `README.md:66-76`.

`devUrl` points to localhost:5173 but `beforeDevCommand` is empty, while documentation says only `cargo tauri dev` is needed. With no separately running Vite server, dev startup cannot load the UI. **Fix:** configure the frontend dev command or document and automate the required parallel process.

### BUG-121 — Tracked lockfile is stale relative to workspace version (High)

**Location:** tracked `Cargo.lock` package entries around `1851-2067,2383-2445`; workspace manifests at version 2.1.2.

At audited HEAD, every local workspace entry in the committed lockfile is 2.1.1 while manifests are 2.1.2. The pre-existing working-tree `Cargo.lock` modification consists of updating those entries, showing the committed/tagged state was not regenerated. A clean `--locked` build requires the stale lock to change and is not reproducible. **Fix:** regenerate and commit the lockfile as part of every workspace version bump and verify a pristine `cargo check --workspace --locked` in CI.

### BUG-122 — Cleanup claims success when deletion fails (Medium)

**Location:** `crates/mod-cleanup/src/lib.rs:119-140`.

Enumeration and `Remove-Item` errors are all silenced. For any existing path the script prints `OK|$freed`, so zero files removed because they are locked/inaccessible still becomes success. **Fix:** collect failed paths/errors, verify remaining targets, and return partial/failed status.

### BUG-123 — AppX security severities Moderate/Low become Optional (Medium)

**Location:** `crates/mod-updates/src/lib.rs:41-52`.

Only Critical and Important strings are preserved; every other MSRC severity—including valid Moderate and Low security ratings—is relabeled Optional. **Fix:** preserve the source rating enum and use Optional only for genuinely optional updates.

### BUG-124 — Installed-program deduplication hides distinct installations (Medium)

**Location:** `crates/mod-uninstall/src/list_programs.ps1:12-18`.

Entries are deduplicated solely by display name, collapsing per-user/machine, x86/x64, or different-version installs. The surviving row may contain the wrong uninstall command/location. **Fix:** key by registry path/product code plus architecture/context and display duplicates explicitly.

### BUG-125 — Deferred deletion ignores every `MoveFileEx` result (Medium)

**Location:** `crates/mod-uninstall/src/lib.rs:195-203,216-217`.

The Boolean return from each reboot-deletion request is discarded and `SCHEDULED` is printed regardless. The user is told locked leftovers will disappear after reboot even if none were scheduled. **Fix:** check every return and `GetLastError`, report partial failures, and verify after reboot where possible.

### BUG-126 — Service optimization changes start type but does not stop running services (Medium)

**Location:** `crates/mod-services/src/lib.rs:25-38,85-100`.

`Set-Service -StartupType` changes future startup behavior only. Currently running telemetry/Xbox/etc. services continue running, while descriptions claim effects such as “Stops telemetry data upload.” **Fix:** state the delayed semantics or explicitly stop selected services with separate result/confirmation and safe rollback.

### BUG-127 — Print Spooler is called Green without performing the promised printer check (Medium)

**Location:** `crates/mod-services/src/lib.rs:25-33`.

The item says “Set Manual only if no printer detected,” but no printer detection or eligibility gate exists; every system is offered the Green-tier action. **Fix:** implement printer/feature dependency checks or raise the tier and explain the unconditional risk.

### BUG-128 — Restore-point listing failures appear as no restore points (Medium)

**Location:** `crates/mod-restore/src/lib.rs:68-93`.

PowerShell launch, command, and JSON failures all return an empty vector, indistinguishable from a machine with no restore points. **Fix:** return a typed query result with error/known state.

### BUG-129 — Runtime support table marks EOL .NET 6 as current (Medium)

**Location:** `crates/mod-runtimes/src/lib.rs:336-348`.

The static matcher permanently treats major 6 as supported. By the audit date it is out of support, yet the UI reports it current; static major-only rules will continue drifting. **Fix:** consume maintained lifecycle data (or a regularly updated signed table) and include patch/channel dates.

### BUG-130 — Runtime probes turn query failure into “not installed” (Medium)

**Location:** `crates/mod-runtimes/src/lib.rs:50-143,147-187,218-230,258-283`.

PowerShell/registry/CLI errors generally return empty vectors or `Unknown` without an overall query state. Users cannot distinguish absence from failed detection. **Fix:** report coverage/error per runtime family.

### BUG-131 — Java inventory examines only each registry family’s CurrentVersion (Medium)

**Location:** `crates/mod-runtimes/src/lib.rs:237-280`.

The detector reads one `CurrentVersion` subkey instead of enumerating installed Java/JDK versions. Side-by-side versions—often the important outdated ones—are omitted. **Fix:** enumerate subkeys/installations and canonical homes, then deduplicate by vendor/version/architecture.

### BUG-132 — DirectX probe uses a predictable shared temp XML (Medium)

**Location:** `crates/mod-runtimes/src/lib.rs:190-230`.

Every call deletes and writes `%TEMP%\cove_dxdiag.xml`; concurrent calls/processes collide, the elevated write is exposed to same-user temp reparse races, and the final file is never removed. **Fix:** use an exclusive randomized private temp file/directory, validate it before parsing, and remove it reliably.

### BUG-133 — SFC, DISM, and combined repairs can run concurrently (Medium)

**Location:** `crates/optimizer-app/src/scan.rs:56-80`.

Concurrency is checked only under the requested key. Starting `sfc`, `dism`, and `full` creates three independent running entries, allowing overlapping DISM/SFC repairs against the same component store. **Fix:** enforce one global servicing-operation lock and make the combined operation own it for both phases.

### BUG-134 — Combined repair exposes only SFC’s final code/output (Medium)

**Location:** `crates/optimizer-app/src/scan.rs:99-105,315-331`.

`full` computes success from both tools but passes only SFC’s exit code and output tail into `finish`. A failed DISM followed by successful SFC shows an SFC exit code/tail that cannot explain the overall failure. **Fix:** store per-phase exit codes, summaries, and tails in the response.

### BUG-135 — SFC/DISM progress and summaries are locale-dependent (Medium)

**Location:** `crates/optimizer-app/src/scan.rs:260-288,334-362`.

The percent parser accepts only a dot; a localized `4,9%` is read as `9%`. Result summaries search English output phrases, so successful/fixed states on localized Windows fall back to generic messages. **Fix:** use exit/state sources where possible and normalize locale-specific decimal/output handling.

### BUG-136 — Servicing scans have no cancellation or deadline (Medium)

**Location:** `crates/optimizer-app/src/scan.rs:116-206`.

The worker blocks on `child.wait()` indefinitely and exposes no cancel command. A hung DISM/SFC/ConPTY leaves a permanent running operation until process exit. **Fix:** add cooperative cancel/kill, a generous explicit deadline, and durable recovery state.

### BUG-137 — Invalid security scan kinds silently run a Quick scan (Medium)

**Location:** `crates/optimizer-app/src/security_scan.rs:37-39,73-102,127-136`.

Any string other than `heuristic` is routed to the Defender slot, and anything other than exact `full` becomes `QuickScan`; the state retains the invalid kind. **Fix:** validate the enum before creating state or a worker.

### BUG-138 — Machine diff fabricates huge disk changes on query failure (Medium)

**Location:** `crates/optimizer-app/src/commands/mod.rs:1163-1171,1243-1264`.

Current disk-query/parse failure becomes zero, which is subtracted from a prior real free-space value and displayed as a massive loss. **Fix:** model disk space as optional and omit/mark the delta Unknown when either sample failed.

### BUG-139 — Machine diff’s bloatware field is permanently empty (Medium)

**Location:** `crates/optimizer-app/src/commands/mod.rs:1175-1193,1252-1263`.

Snapshots do not capture bloatware and `new_bloatware` is hardcoded to `[]`, so the advertised field can never report a change. **Fix:** snapshot stable package identities and compare them, or remove the field.

### BUG-140 — Machine diff compares ambiguous, case-sensitive display names (Medium)

**Location:** `crates/optimizer-app/src/commands/mod.rs:1188-1189,1229-1250`.

Startup/program differences use display-name strings only. Case/name changes look like remove+add, duplicate installations collapse semantically, and two unrelated items with the same name are indistinguishable. **Fix:** snapshot stable identities and normalized display metadata.

### BUG-141 — Shipped “portable” executable does not activate portable mode (Medium)

**Location:** `crates/optimizer-app/src/portable.rs:11-19`; `.github/workflows/release.yml:109-113`; claim at `README.md:11-14,137-140`.

Portable mode requires an adjacent `portable.marker` or pre-existing `cove-app-data` directory, but release packaging copies only the EXE. The single-file portable build therefore stores logs/history/snapshots in AppData and leaves machine state. **Fix:** compile a portable-mode flag into that artifact or intentionally create/package a marker with clear behavior.

### BUG-142 — Release version can differ across filename, Tauri metadata, UI, and Rust (Medium)

**Location:** `.github/workflows/release.yml:69-74,97-113`; `crates/optimizer-app/tauri.conf.json:4`; `ui/package.json`; UI version injection.

The workflow patches only Tauri JSON. The artifact filename uses workflow input, the title UI is built from the UI package version, and Rust workspace package versions remain unchanged. One release can visibly contain several versions. **Fix:** use one canonical version source and validate/patch every consumer before build.

### BUG-143 — Test harness cannot run because it requires UAC elevation (Medium)

**Location:** `crates/optimizer-app/build.rs`; `crates/optimizer-app/windows-app-manifest.xml:20`.

`cargo test --workspace --all-targets --locked` builds the app test harness with `requireAdministrator`; launching it in the automated shell failed with Windows error 740. This blocks normal workspace test execution/CI even before tests run. **Fix:** do not embed the elevation manifest in test binaries; isolate elevation in a production launcher/helper.

### BUG-144 — Network command failure still says “completed” (Medium)

**Location:** `crates/optimizer-app/src/commands/mod.rs:229-260`.

The response’s `success` follows the exit status, but `message` is always “completed” (and sometimes “restart required”) even for nonzero exits. UIs that emphasize the message give contradictory guidance. **Fix:** generate failure wording/output from status and stderr.

## Low-severity and engineering-quality findings

### BUG-145 — Tag pushes do not trigger the documented release workflow

**Location:** `.github/workflows/release.yml:3-14,131-133`; `README.md:126-135`.

The workflow has only `workflow_dispatch`, while documentation says a `v*` tag push triggers it. Ordinary branch dispatch also skips `publish-release` because that job requires a tag ref. **Fix:** add the documented tag trigger/publish behavior or update the documentation and supported manual procedure.

### BUG-146 — Checksum documentation names an artifact never produced

**Location:** `README.md:14,137-140`; `.github/workflows/release.yml:143-168`.

Documentation promises `checksums-sha256.txt`, while the workflow produces one `.sha256` sidecar per EXE. **Fix:** align generated assets and documentation.

### BUG-147 — There are no automated tests

**Location:** repository-wide.

Every Rust package test run reported zero tests; source search found no `#[test]`. The React package has no test script/suite. Critical shell escaping, deletion authorization, parser, rollback, and response-contract behavior therefore have no regression protection. **Fix:** add unit/property tests for pure parsing/validation, IPC contract tests, clean-clone build tests, and sandboxed Windows integration tests.

### BUG-148 — All three static quality gates fail

**Location:** repository-wide.

`cargo fmt --all -- --check` reports formatting diffs; strict Clippy fails on warnings in several crates; `pnpm run lint` reports six errors and one warning (including React state-in-effect and function-order defects). A passing compile therefore is not a clean quality build. **Fix:** repair existing violations and enforce the gates in CI.

### BUG-149 — Dependency audit reports nineteen additional unmaintained/unsound warnings

**Location:** `Cargo.lock` transitive graph.

Beyond BUG-024, `cargo audit` reported 19 warnings, including target-specific GTK/Linux and other unmaintained/unsound dependencies. Some are irrelevant to the Windows artifact, but the workspace has no target-aware audit policy, ownership, or documented exception list. **Fix:** update/remove reachable packages and maintain reviewed, expiring exceptions for truly unreachable target-specific warnings.

### BUG-150 — Elevated webview ships with no Content Security Policy

**Location:** `crates/optimizer-app/tauri.conf.json:24-27`.

`csp` is null in an always-elevated webview exposing powerful mutation IPC. No renderer injection was confirmed in current constant/local content, so this is defense-in-depth rather than a standalone exploit, but any future XSS/dependency compromise receives no CSP containment. **Fix:** define a restrictive CSP and minimize IPC capabilities/elevation.

### BUG-151 — UI lint/type mocks allow unknown commands to masquerade as any response

**Location:** `ui/src/lib/tauri.ts:1031-1042`.

The generic mock returns `{}` cast to `T`, defeating TypeScript’s contract checking and causing downstream runtime crashes (see BUG-049). **Fix:** use an exhaustive command-to-response map and a `never`/throw fallback.

### BUG-152 — Optimizer helper binary is a shipped workspace placeholder

**Location:** `crates/optimizer-helper/src/main.rs:1-7`.

The binary only prints that it is a stub despite comments describing a future privileged named-pipe server. Keeping it as a normal workspace package creates a misleading/accidentally publishable artifact and no actual privilege separation—the main UI remains elevated. **Fix:** remove it from production packaging until implemented, or complete a secured authenticated helper and de-elevate the UI.

### BUG-153 — Administrator detection depends on the Server service (Medium)

**Location:** `crates/mod-sfc/src/lib.rs:20-35`; consumers `ui/src/components/Sidebar.tsx:50-51` and `SfcPanel.tsx:51-78`.

The app uses `net session` as its elevation test. That command can fail when the Server/LanmanServer service is disabled or unavailable even for a fully elevated token, causing false “restart as Administrator” warnings and disabled-looking repair UI. **Fix:** query the process token elevation/integrity level through the Windows API.

### BUG-154 — Legacy public DISM runner can resolve the wrong path and misreport repairs (Low)

**Location:** `crates/mod-sfc/src/lib.rs:43-83,145-166`.

The public but currently unused runner launches bare `dism` (which can collide with the System32 `Dism` directory/search-path issue) and tests generic “restore operation completed successfully” before the more specific “component store has been repaired,” so repaired corruption can be summarized as “healthy, no repairs.” **Fix:** remove the dead API or use the trusted full executable path and test specific outcomes first.

### BUG-155 — Runtime “outdated” checks ignore patch level and several lifecycle rules (Medium)

**Location:** `crates/mod-runtimes/src/lib.rs:327-363`.

The logic treats every runtime on a supported .NET major as current regardless of an obsolete/vulnerable patch, every Java major 17 or newer as current (including short-lived EOL non-LTS releases), and most non-14 VC++ versions as current regardless of patch. It also marks every .NET Framework 4.x except 4.8.1 outdated even where 4.8 remains OS-supported. **Fix:** use maintained vendor lifecycle/minimum-patch data with vendor/channel/OS context and an Unknown state.

### BUG-156 — DirectX detector fabricates version 12 when XML lacks a version (Medium)

**Location:** `crates/mod-runtimes/src/lib.rs:206-230`.

If dxdiag XML parses but `DirectXVersion` is empty, the script assigns `12` rather than Unknown. **Fix:** preserve Unknown and expose why the field was unavailable.

### BUG-157 — Cleanup scan failures are displayed as zero-byte clean targets (Medium)

**Location:** `crates/mod-cleanup/src/lib.rs:55-84`.

Process, access, output, and numeric parse failures all return `(0,0)`, indistinguishable from an empty directory. **Fix:** return per-target measurement state/errors and avoid presenting failed scans as empty.

### BUG-158 — Native console output is broadly decoded with the wrong encoding (Medium)

**Location:** examples `crates/mod-power/src/lib.rs:34-68`, `crates/optimizer-app/src/commands/mod.rs:244-250`, and several `fsutil`/`chkdsk`/`netsh` call sites.

Many native Windows tools emit the active OEM code page, but the code uses `String::from_utf8_lossy`. Accented/localized plan names and diagnostic text become mojibake, and any parser depending on that text can fail. Specific chkdsk/netsh consequences are covered above. **Fix:** use native APIs/structured PowerShell where possible or decode using the process console code page.

## Conditional concerns and audit boundaries

- Exported reports and diagnostic responses can contain usernames, paths, SSIDs, MAC addresses, storage serials/models, process names, and Event Log message text. Collection is often feature-required, but the export UI should disclose the exact data and offer redaction before sharing.
- Hardware/driver behavior can expose additional edge cases not reproducible on the audit machine, especially sensor limits, storage reliability counters, WMI schemas, multi-GPU/monitor mapping, and vendor-specific runtime registrations.
- No destructive cleanup, uninstall, service, registry, AppX, chkdsk repair, DISM/SFC repair, or driver-install operation was executed against the host. Exploit construction was limited to safe command parsing/reproduction and read-only validation.
- `crates/mod-network/src/lib.rs` contains no executable implementation; network behavior lives in `mod-netdiag` and the command adapter.

## Verification results

| Check | Result | Notes |
|---|---:|---|
| `cargo check --workspace --all-targets --locked` | Pass | Passed with the pre-existing locally updated lockfile. |
| `pnpm.cmd run build` | Pass | TypeScript and Vite production build completed. |
| `pnpm.cmd audit --prod --audit-level low` | Pass | No known production npm advisories. |
| `cargo test --workspace --exclude optimizer-app --locked` | Pass, but ineffective | Every crate reported zero tests. |
| `cargo test --workspace --all-targets --locked` | Fail | App test harness could not launch: Windows error 740/elevation required. |
| `cargo tauri build --debug --no-bundle` | Fail | Reproduced broken `beforeBuildCommand` path resolving outside the repo. |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Fail | Existing Clippy warnings are promoted to errors. |
| `cargo fmt --all -- --check` | Fail | Repository has formatting drift. |
| `pnpm.cmd run lint` | Fail | Six errors and one warning. |
| `cargo audit` | Fail | Three advisory IDs across two locked packages, plus 19 warnings. |
| PowerShell parser over all three embedded `.ps1` files | Pass | No syntax errors. |
| `git diff --check` | Pass | No whitespace-error diagnostics in the pre-audit working tree. |

## Recommended remediation order

1. De-elevate the renderer/UI and introduce a narrowly authorized privileged helper; meanwhile eliminate every shell interpolation and bare executable lookup.
2. Disable uninstall/leftover/AppX destructive IPC until backend-owned opaque identities, canonical authorization, and safe literal deletion are implemented.
3. Move executable resources out of user-writable/temp locations and add pinned cryptographic verification.
4. Introduce a shared result model with `known`, `complete`, `success`, `partial`, and error details; stop treating empty/default data as healthy.
5. Make mutation history transactional and rollback payloads operation-specific before calling tweaks reversible.
6. Repair clean-clone build/release paths and dependency advisories, then establish CI gates and real tests for the critical validation/parsing/state logic.
