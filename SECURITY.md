# Dependency audit policy

The shipped artifact is Windows-only. CI fails on every RustSec vulnerability and
runs `cargo audit` against the committed lockfile. Informational warnings are
reviewed separately because Cargo resolves Tauri's Linux graph into the shared
lockfile even though those GTK/GLib packages are not compiled into the Windows
artifact.

Current informational exceptions are the GTK3/GLib and `unic-*` advisories
reported only through Tauri's non-Windows WebKit/GTK dependency graph, plus
`proc-macro-error`, which is build-time only. They are not ignored by ID: audit
output remains visible in CI. Review these exceptions on every Tauri upgrade and
no later than 2026-11-10. A warning that becomes reachable from the Windows
target, or any vulnerability, blocks release.

The Windows dependency graph must also pass:

```powershell
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo audit
```
