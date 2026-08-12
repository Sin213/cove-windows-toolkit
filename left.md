# Repository audit handoff

Paused: 2026-08-12
Resumed and completed: 2026-08-12

## Resume status (2026-08-12)

Items 1, 2, 4, 5, 6, and 7 below are **done**. Item 3 is an architecture
decision that is still open; its audit half is done and documented. Item 8
(tester validation on a disposable VM) is still outstanding by definition.

- **1 (done)** The legacy PawnIO/LHM block comment is deleted from
  `crates/mod-temps/src/lib.rs` (549 -> 207 lines). Only the read-only `windows`
  collector remains. The untracked `resources/*.zip|exe` binaries are now
  referenced by nothing.
- **2 (done)** All ten path-hardening files reviewed by diff. Known Folder
  allocation/free in `optimizer_core::program_files_directory` is correct,
  PowerShell single-quote escaping in the snapshot read is correct, system-drive
  and Windows-directory derivation all go through `[Environment]::SystemDirectory`,
  and the undo call graph takes no re-entrant lock and reconciles history once.
- **3 (audit half done, decision open)** Support logs, history/snapshot JSON,
  and exported reports all resolve through Known Folder lookups
  (`directories::ProjectDirs` / `UserDirs`) into the elevated token's own
  profile, so no environment variable or adjacent junction can redirect them.
  The de-elevated-UI + narrow-helper architecture is still not implemented and
  remains the recommended next project.
- **4 (done)** Added `scripts/check-cargo-audit-warnings.ps1` and
  `scripts/audit-approved-warnings.txt` (17 approved advisory IDs), wired into
  CI after `cargo audit`, and rewrote the `SECURITY.md` policy section to match.
  Verified it passes on the current graph and fails when an ID is removed.
- **5 (done)** `bug.md` now opens with a notice that the July report is historic
  and ends with an "August 2026 follow-up audit" section: 65 confirmed addressed
  root causes (16/8/13/6/22), the verification table below, residual risks, the
  intentionally disabled features, and the finite-audit statement.
- **6 (done)** All gates rerun and passing: fmt, clippy `-D warnings`,
  `cargo test --workspace --lib` (47 passed), pnpm install/audit/lint/build,
  `cargo audit` (0 vulnerabilities, 17 warnings), the new warning gate,
  PowerShell parse of all 3 tracked `.ps1` files, `cargo metadata` (26 MIT
  members at 2.3.2), 8/8 Action pins validated against the GitHub commit API,
  and `git diff --check` clean.
- **7 (done)** `release\Cove-Windows-Toolkit-2.3.2-full-audit-Portable.exe`
  13,713,920 bytes (13.08 MB),
  SHA-256 `d6e15de510ba789779cb38f66d14cb095e081f690c3f5a11731f45d4a0b19577`,
  sidecar written, Authenticode `NotSigned` (expected). No pre-existing release
  artifact was overwritten.

Still uncommitted; `.claude/settings.local.json` remains untouched and must stay
out of any commit.

The original handoff follows unchanged for reference.

This file records the exact state of the unfinished full-repository audit so it
can be resumed without repeating the work. The release candidate is **not yet
finished**: no final tester executable was built from the current tree, the
current `bug.md` has not been refreshed, and the last full gate run predates a
few final path-hardening edits.

## Workspace state

- Branch: `agent/cleanup-support-logs`
- HEAD when paused: `d41759a` (`Fix pnpm cache path in CI`)
- Draft PR from the earlier cleanup/log work: #3
- The audit changes are uncommitted and span roughly 82 tracked paths.
- New repository files: `LICENSE` and `rust-toolchain.toml`.
- `.claude/settings.local.json` is a pre-existing user-local modification. It is
  unrelated to this audit and must not be edited, reverted, staged, or committed.
- Existing tester executables and checksum sidecars under `release/` must not be
  overwritten. Use a new filename for the eventual audit build.
- Nothing from this audit has been committed or pushed.

## Work already completed

### Privilege and destructive-operation hardening

- Replaced the cleanup PowerShell fail-fast pipeline with native Windows,
  handle-relative traversal and deletion. Reparse points are not followed,
  locked children are skipped without aborting the target, missing optional
  folders are idempotent, and nested folders are deleted post-order.
- Added cleanup regression coverage for missing, empty, locked, linked, swapped,
  special-character, nested, and unknown targets.
- Restricted elevated uninstall execution to freshly revalidated HKLM MSI
  product-code registrations and a trusted System32 `msiexec.exe`. HKCU and
  arbitrary registered executables are refused.
- Removed heuristic/shared-folder leftover discovery. Registered install
  locations may be reviewed, but automatic leftover deletion is deliberately
  disabled because ownership cannot yet be proven race-free.
- Disabled elevated startup-folder file moves. Registry Run toggles are limited
  to approved roots, reject collisions, and roll back a partial destination copy.
- Disabled adjacent `portable.marker` / `cove-app-data` state mode. The no-install
  executable now stores state in per-user AppData so an adjacent junction cannot
  redirect elevated writes.
- Removed the active temperature path that silently installed PawnIO during a
  read-only diagnostic. Temperature collection now uses read-only providers.
- Trusted inbox executable resolution now uses the Windows directory/System32.
  Program Files discovery for optional vendor tools uses the Known Folder API,
  not an inherited `ProgramFiles` variable. Windows Security URI launching uses
  `ShellExecuteW`.

### Rollback, history, and data integrity

- The first pre-change snapshot is preserved until undo; repeated Apply no longer
  overwrites the original value.
- Apply/undo/preset mutations are serialized so concurrent requests cannot race
  snapshot and registry state.
- Registry state is read immediately and checked before a snapshot/mutation.
  Query failure is no longer mistaken for an absent value.
- Corrupt, unreadable, or wrongly typed rollback JSON fails closed and cannot
  cause Undo to delete a registry value.
- Failed applies discard a newly created unused snapshot without erasing other
  rollback records.
- Only the latest snapshot-backed history row for an action is undoable. Direct
  panel Undo and History Undo reconcile all matching rows.
- Corrupt history is reported instead of displayed as empty or overwritten.
- Program inventory failures no longer produce a false “all programs removed”
  machine diff.

### Frontend reliability and contracts

- Added response validation for Cleanup, Security, Diff, History, Startup, and
  Uninstaller envelopes and worker-failure fallbacks.
- Fixed false success/completion states in Cleanup and Uninstaller, including
  retrying a post-uninstall location scan without running the uninstaller again.
- Added local in-flight guards and stale-generation rejection to mutation and
  polling workflows. Temperature, SFC, and Security polling now avoids overlaps,
  StrictMode loss, post-unmount writes, and stale response replacement.
- Visual/Performance undo availability now follows real rollback capability.
- Visual, Performance, Privacy, Services, and Dashboard preset actions are
  guarded against duplicate/concurrent mutations.
- Restore status/history failures are independent; restore descriptions are
  backend-validated and capped at 120 characters.
- External open/copy/download/update failures are surfaced instead of ignored.
- Browser mocks match the production MSI/startup/history/window contracts.
- Title-bar actions use the shared Tauri wrapper, so browser development no
  longer produces unhandled Tauri invoke rejections.

### Correctness and release engineering

- Fixed exact AppX package matching, hosts-file whitespace parsing, current
  runtime patch thresholds, trusted DISM resolution, and several misleading
  scan/default states.
- CI now targets the actual `master` branch and is reusable by the release
  workflow. Release builds require the quality job first.
- Rust, Node, pnpm, and Tauri CLI versions are pinned; Cargo and pnpm builds use
  their lockfiles.
- External GitHub Actions are pinned to verified commit SHAs. In particular:
  - `pnpm/action-setup@b906affcce14559ad1aafd4ab0e942779e9f58b1`
  - `Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6`
- Release write permission is scoped only to the publishing job.
- Frontend auditing is a CI gate; the known brace-expansion, nanoid, and postcss
  advisories were removed from the lockfile.
- Added an MIT license and package license metadata.
- Excluded the unfinished `optimizer-helper` stub from the workspace and marked
  it `publish = false`.
- Fixed the Tauri hook working directory (`pnpm --dir ../ui ...`) and clarified
  that the standalone EXE is no-install but uses per-user AppData.

## Work still required

### 1. Clean up the last source edit

`crates/mod-temps/src/lib.rs` still contains the old PawnIO/LHM implementation
inside one large block comment. It compiles and cannot execute, but it should be
deleted cleanly instead of leaving hundreds of lines of obsolete installer code
in the source. Keep only the active read-only `windows` collector.

### 2. Review the final path-hardening integration

The following files were changed after the last broad audit checkpoint and need
one focused diff review plus final tests:

- `crates/optimizer-core/src/lib.rs`
- `crates/mod-bsod/src/lib.rs`
- `crates/mod-diskhealth/src/lib.rs`
- `crates/mod-health/src/lib.rs`
- `crates/mod-restore/src/lib.rs`
- `crates/mod-runtimes/src/lib.rs`
- `crates/mod-security/src/lib.rs`
- `crates/mod-temps/src/lib.rs`
- `crates/optimizer-app/src/commands/mod.rs`
- `crates/optimizer-app/src/security_scan.rs`

Specifically verify Windows Known Folder cleanup/allocation, PowerShell quoting,
system-drive derivation, BSOD environment expansion, Windows Update reset paths,
and optional NVIDIA/dotnet executable discovery.

### 3. Decide the remaining elevated-state architecture

The app still runs the entire Tauri UI as Administrator. This leaves an inherent
large privilege boundary even after individual operations were hardened. The
long-term ironclad design is:

1. Run the UI/webview as the normal user.
2. Implement a narrow authenticated privileged helper for specific approved
   operations.
3. Pass typed operation IDs, not arbitrary commands or paths.
4. Keep per-user UI state and logs in the normal-user process.

Until that architecture exists, audit all elevated writes to user-controlled
locations—especially support logs, history/snapshot JSON, and exported reports—
for directory-junction/reparse redirection. The excluded `optimizer-helper` is
only a placeholder and must not be re-added to production until it is genuinely
implemented and reviewed.

Automatic leftover deletion should remain disabled unless scan-time identity is
bound to handle-relative, no-reparse deletion. Do not restore the old heuristic
or `remove_dir_all` implementation.

### 4. Align the dependency-warning policy with CI

`SECURITY.md` says every new `cargo audit` warning blocks release, but plain
`cargo audit` exits nonzero for vulnerabilities, not necessarily for a newly
introduced maintenance warning. Either:

- add an explicit approved-warning/advisory comparison gate, or
- change the policy text to match the actual CI behavior.

There are currently no published Cargo vulnerabilities, but 17 documented
maintenance warnings remain in the resolved graph.

### 5. Finish `bug.md`

The existing `bug.md` is the July 2026 audit of commit `362675b` and contains
stale verification failures. Do not present it as the state of this tree.

Write a new August 2026 follow-up section or replace the file with a current
report that includes:

- audited branch/commit and scope;
- confirmed root causes, severity, fix, and regression coverage;
- an exact found/fixed count without double-counting symptoms;
- verification command results;
- explicit residual risks and intentionally disabled features;
- a statement that a finite audit cannot prove the absence of every bug.

The release-engineering subset has already been independently counted as **21
confirmed addressed root causes**: CI/release correctness 5, supply chain 7,
reproducibility/toolchain 4, manifest/legal 3, and documentation/policy 2. The
overall repository count is not finalized; derive it from the complete diff and
audit notes rather than publishing a guess or adding it to the historic 158.

### 6. Run the final gates after all edits stop

Use the installed complete `stable` toolchain explicitly. It is Rust 1.96.0 and
works. Direct `cargo` currently triggers recovery of a separate partially
installed `1.96.0` rustup toolchain and can fail with a `cargo-fmt.exe` conflict.
That is a local rustup state issue, not a repository failure.

```powershell
rustup run stable cargo fmt --all -- --check
rustup run stable cargo check --workspace --all-targets --locked
rustup run stable cargo clippy --workspace --all-targets --locked -- -D warnings
rustup run stable cargo test --workspace --lib --locked

pnpm.cmd --dir ui install --frozen-lockfile --offline
pnpm.cmd --dir ui audit --audit-level low
pnpm.cmd --dir ui run lint
pnpm.cmd --dir ui run build

$env:CARGO_HOME = (Resolve-Path -LiteralPath 'target').Path + '\audit-cargo-home'
target\audit-tools\bin\cargo-audit.exe audit

git diff --check
```

Also run:

- the PowerShell parser over every tracked `*.ps1` file;
- `cargo metadata --locked --no-deps --format-version 1` and confirm 26 MIT
  workspace members at version 2.3.2;
- GitHub commit-API validation for every 40-character Action pin;
- a final `git status --short`, carefully excluding the user-owned
  `.claude/settings.local.json` from any later commit.

Checkpoint results before pausing were promising but are not a substitute for
the final rerun: workspace/all-target compilation passed, frontend lint/build
passed, cleanup/startup/uninstall tests passed, a prior workspace library run
reported 50 passing tests, pnpm audit reported zero advisories, and cargo audit
reported zero vulnerabilities plus the 17 documented warnings.

The `optimizer-app` unit-test binary embeds `requireAdministrator`, so a normal
noninteractive test launch fails with Windows error 740. CI intentionally runs
workspace library tests while Clippy/check still compile every target.

### 7. Build the tester EXE only after every gate passes

```powershell
pnpm.cmd --dir ui run build

Push-Location crates/optimizer-app
rustup run stable cargo tauri build --no-bundle --ci --config '{"build":{"beforeBuildCommand":""}}' -- --locked
Pop-Location

$artifact = 'release\Cove-Windows-Toolkit-2.3.2-full-audit-Portable.exe'
Copy-Item -LiteralPath 'target\release\optimizer-app.exe' -Destination $artifact
Get-FileHash -LiteralPath $artifact -Algorithm SHA256
Get-AuthenticodeSignature -LiteralPath $artifact
```

Record the exact size and SHA-256 in the final handoff. The current project does
not Authenticode-sign local builds, so `NotSigned`/SmartScreen “Unknown Publisher”
is expected. Do not call the build fully side-by-side portable: it is a
single-file no-install executable with per-user AppData state.

### 8. Tester-only validation still needed

No destructive repair action was run on this development machine. The tester
should cover, on a disposable VM or restore-point-protected machine:

- cleanup with locked temp files, nested folders, and missing WER folders;
- direct and History undo after repeated Apply and a preset;
- HKCU/non-MSI uninstall refusal and a legitimate HKLM MSI uninstall;
- startup registry collision refusal and startup-folder rows being disabled;
- SFC/DISM polling across tab changes and app remounts;
- Defender quick/full/heuristic start guards;
- Windows Update reset, restore point creation, chkdsk scheduling, and bloatware
  removal only in a disposable environment;
- Logs copy/save/open-folder privacy and bounded output;
- no-install EXE behavior with no adjacent marker/data directory;
- Windows 10/11, non-English Windows, and paths containing apostrophes/non-ASCII
  characters where practical.

## Do not do during resume

- Do not restore arbitrary elevated uninstall commands.
- Do not re-enable automatic leftover deletion.
- Do not re-enable automatic PawnIO/kernel-driver installation.
- Do not use bare executable names for optional third-party programs.
- Do not overwrite corrupt rollback/history data with empty defaults.
- Do not use `git reset --hard`, discard unrelated user changes, or stage
  `.claude/settings.local.json`.
- Do not commit, push, tag, or publish until the final gates and tester EXE are
  complete and the user explicitly requests publication.
