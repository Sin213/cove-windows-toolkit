# Project Core Technologies

## Languages and Runtimes

- Rust workspace, edition 2024, pinned by `rust-toolchain.toml` to Rust 1.96.0 with Clippy and rustfmt.
- TypeScript and JavaScript frontend using Node.js 24.16.0 and pnpm 11.5.2.
- Windows PowerShell queries are used by the application for Windows diagnostics and operations.

## Frameworks and Libraries

- Tauri v2 desktop shell and Rust backend.
- React 19 with React DOM, TypeScript, and Vite 8.
- Rust workspace dependencies include serde, serde_json, chrono, thiserror, tokio, tracing, and uuid.
- Frontend uses `@tauri-apps/api` and ESLint tooling.

## Build, Test, and Development Tools

- Cargo workspace commands and Tauri CLI 2.11.2 for development and production builds.
- Frontend scripts are provided by `ui/package.json` for Vite development, TypeScript/Vite builds, linting, and preview.
- GitHub Actions workflows are present under `.github/workflows/` for CI and releases.

## External Services and Infrastructure

- GitHub Releases and GitHub Actions are documented as the release distribution and automation path.
- No runtime hosted service is documented; the application runs locally on Windows.

## Important Technical Constraints

- Supported platform is 64-bit Windows 10/11, and the application runs elevated for system diagnostics and repairs.
- Actions use safety tiers; Yellow and Red actions require confirmation.
- Support-log display, copy, and save paths include privacy redaction according to the README.
- The Rust workspace explicitly excludes `crates/optimizer-helper`.
