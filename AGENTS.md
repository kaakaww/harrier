# Repository Guidelines

## Project Structure & Module Organization
- Workspace crates: `crates/harrier-cli` (binary), `crates/harrier-core` (HAR parsing/analysis), `crates/harrier-proxy` (MITM capture), `crates/harrier-browser` (Chrome/CDP), `crates/harrier-detectors` (auth/security heuristics).
- Shared resources: `tests/fixtures/` (canned HARs), `samples/` (larger references), `docs/` (user guides), `scripts/` (release/automation); `target/` is build output (never commit).
- Keep CLI flags and command wiring in `harrier-cli`; push reusable logic into `harrier-core` or the relevant feature crate.

## Build, Test, and Development Commands
- Fast paths: `make build` (debug), `make release-build`, `make test`, `make lint`, `make install`.
- Direct cargo: `cargo run -- stats tests/fixtures/sample.har` to exercise the binary; `cargo test --all` for the full suite; `cargo fmt -- --check` and `cargo clippy --all-targets --all-features -- -D warnings` match CI.
- Release: `make release` or `./scripts/release.sh` drives version bumping and tagging; push the tag to trigger GitHub Actions artifacts.

## Coding Style & Naming Conventions
- Rust 2024 edition; 4-space indentation.
- Formatting/linting enforced by `cargo fmt` and clippy with warnings denied. Avoid `unwrap()`/`expect()` in user-facing paths—prefer `anyhow::Result` for CLI flows and typed errors via `thiserror` in libraries.
- Logging uses `tracing`; prefer structured fields. Keep new command/flag names consistent with existing `harrier <command> --flag` patterns.

## Testing Guidelines
- Default: `cargo test --all` before opening a PR; run `make lint` if you touched public interfaces.
- Targeted runs: `cargo test -p harrier-core entry_filters` (package-specific) or `cargo test stats::` (module-prefix) for quicker feedback.
- Integration inputs live in `tests/fixtures/`; add small, redacted HARs when expanding behavior and document any special cases in test names.

## Commit & Pull Request Guidelines
- Follow the existing concise, imperative commit style (e.g., `Add design doc`, `Replace --scan with --hawkscan guidance output`). Squash WIP commits before review.
- PRs should include a short summary, commands run (`make test`, `make lint`), any manual capture steps, and screenshots/output snippets when CLI UX changes.
- Link related issues/roadmap items where applicable; avoid committing `target/` contents or unsanitized HAR data.

## Security & Data Handling
- HAR files may contain credentials/tokens; scrub or redact before committing. Prefer synthetic or sanitized samples in `tests/fixtures/` and `samples/`.
- Proxy/browser crates generate CA material under `~/.harrier/`; never commit those artifacts. Document new config/env vars in `docs/` and `README.md`.
