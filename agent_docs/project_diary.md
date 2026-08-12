# Project Diary

Record only durable decisions, discarded approaches, and reusable lessons.

## Decisions and Lessons

- The repository is organized as a modular Rust workspace: shared types and the Tauri application are separated from feature-specific Windows modules.
- The documented safety model distinguishes Green, Yellow, and Red actions; Yellow and Red operations require confirmation.
- Support logs remain local by default and are redacted before display, copying, or saving.
- Release checksums are generated in CI for the final executable bytes; local `release/` artifacts are not authoritative for published-download verification.
