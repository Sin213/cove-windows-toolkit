# Dependency audit policy

The shipped artifact is Windows-only. CI fails on every RustSec vulnerability and
runs `cargo audit` against the committed lockfile. Informational warnings are
reviewed separately because Cargo resolves Tauri's Linux graph into the shared
lockfile even though those GTK/GLib packages are not compiled into the Windows
artifact.

Current reviewed informational exceptions are:

- GTK3/GLib warnings that exist only in Tauri's non-Windows WebKit/GTK graph.
- The unmaintained `unic-*` crates reached on Windows through
  `tauri-utils -> urlpattern`. These have no published vulnerability, but remain
  a temporary maintenance exception.
- `proc-macro-error`, which is build-time only.

They are not ignored by ID: audit output remains visible in CI. The exact
approved advisory IDs are tracked in `scripts/audit-approved-warnings.txt`
(17 entries today). Review these exceptions on every Tauri upgrade and no later
than 2026-11-10.

How the gate is actually enforced, since plain `cargo audit` exits nonzero only
for published vulnerabilities:

- `cargo audit` fails CI on any RustSec vulnerability.
- `scripts/check-cargo-audit-warnings.ps1` parses `cargo audit --json` and fails
  CI on any unmaintained/unsound warning whose advisory ID is not on the
  approved list. It also reports approved IDs that have disappeared, so the list
  can be pruned.

Introducing a new warning therefore requires reviewing it and adding it to both
the approved list and this file in the same change.

The Windows dependency graph must also pass:

```powershell
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --lib --locked
cargo audit
pwsh -NoProfile -File scripts/check-cargo-audit-warnings.ps1
pnpm --dir ui audit --audit-level low
```
