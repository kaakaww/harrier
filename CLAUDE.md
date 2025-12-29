# Harrier - Repository Guidelines

## Project Overview

Harrier is a command-line interface tool for working with HTTP Archive (HAR) files. It provides utilities to collect, analyze, and modify HAR files, making it easier to work with HTTP traffic data for security testing and analysis.

**Sponsor:** StackHawk
**Purpose:** Help StackHawk customers work with HAR files in the context of scanning applications with HawkScan.

**Tech Stack:**
- Language: Rust
- Edition: 2024
- Type: Command-line tool

**Project Goals:**
1. **Collection:** Capture and generate HAR files from various sources
2. **Analysis:** Parse, inspect, and extract information from HAR files
3. **Modification:** Transform, filter, and modify HAR file contents
4. **Integration:** Work seamlessly with StackHawk's HawkScan for security testing workflows

## HAR File Context

HTTP Archive (HAR) files are JSON-formatted archives of HTTP transactions. They contain:
- Request/response headers and bodies
- Timing information
- Cookie data
- Cache information
- SSL/TLS details

Common use cases:
- Performance analysis
- Security testing and vulnerability scanning
- Debugging web applications
- Traffic replay and testing

## Project Structure & Module Organization

- **Workspace crates:** `crates/harrier-cli` (binary), `crates/harrier-core` (HAR parsing/analysis), `crates/harrier-proxy` (MITM capture), `crates/harrier-browser` (Chrome/CDP), `crates/harrier-detectors` (auth/security heuristics).
- **Shared resources:** `tests/fixtures/` (canned HARs), `samples/` (larger references), `docs/` (user guides), `scripts/` (release/automation); `target/` is build output (never commit).
- Keep CLI flags and command wiring in `harrier-cli`; push reusable logic into `harrier-core` or the relevant feature crate.

## Build, Test & Development

**Make commands (fast paths):**
- `make build` - debug build
- `make release-build` - release build
- `make test` - run all tests
- `make lint` - run clippy and fmt checks
- `make install` - install locally

**Direct cargo:**
- `cargo run -- stats tests/fixtures/sample.har` - exercise the binary
- `cargo test --all` - full test suite
- `cargo fmt -- --check` and `cargo clippy --all-targets --all-features -- -D warnings` - match CI

**Release:**
- `make release` or `./scripts/release.sh` drives version bumping and tagging
- Push the tag to trigger GitHub Actions artifacts

## Coding Style & Conventions

- Rust 2024 edition; 4-space indentation
- Formatting/linting enforced by `cargo fmt` and clippy with warnings denied
- Avoid `unwrap()`/`expect()` in user-facing paths—prefer `anyhow::Result` for CLI flows and typed errors via `thiserror` in libraries
- Logging uses `tracing`; prefer structured fields
- Keep new command/flag names consistent with existing `harrier <command> --flag` patterns

## Testing Guidelines

- Default: `cargo test --all` before opening a PR; run `make lint` if you touched public interfaces
- Targeted runs: `cargo test -p harrier-core entry_filters` (package-specific) or `cargo test stats::` (module-prefix) for quicker feedback
- Integration inputs live in `tests/fixtures/`; add small, redacted HARs when expanding behavior and document any special cases in test names

## Commit & PR Guidelines

- Follow the existing concise, imperative commit style (e.g., `Add design doc`, `Replace --scan with --hawkscan guidance output`)
- Squash WIP commits before review
- PRs should include a short summary, commands run (`make test`, `make lint`), any manual capture steps, and screenshots/output snippets when CLI UX changes
- Link related issues/roadmap items where applicable
- Avoid committing `target/` contents or unsanitized HAR data

## Security & Data Handling

- HAR files may contain credentials/tokens; scrub or redact before committing
- Prefer synthetic or sanitized samples in `tests/fixtures/` and `samples/`
- Proxy/browser crates generate CA material under `~/.harrier/`; never commit those artifacts
- Document new config/env vars in `docs/` and `README.md`

## Related Resources

- **StackHawk:** Application security testing platform
- **HawkScan:** StackHawk's dynamic application security testing (DAST) scanner
- **HAR Spec:** https://w3c.github.io/web-performance/specs/HAR/Overview.html
- **Chrome DevTools:** Built-in HAR export functionality

---

## Roadmap

### Phase 1: Foundation (Completed)
- [x] Workspace structure with 5 crates
- [x] Custom HAR data types matching W3C HAR 1.2 spec
- [x] HAR file reader and writer
- [x] Basic CLI with subcommands
- [x] Core analysis engine (summary and performance)
- [x] App type detection (REST, GraphQL, SOAP, gRPC, WebSocket, MCP, SPA)
- [x] Auth pattern detection (Basic, Bearer, JWT, OAuth, API Keys, Cookies)

### Phase 2: Core Analysis Features (Partially Complete)
- [x] Implement `stats` command - display HAR statistics, performance metrics, and host analysis
- [x] Implement `filter` command - filter by host (exact/glob), status, method, content-type with AND logic
- [x] Add comprehensive tests with real HAR file fixtures (65 tests passing)
- [x] Update README with usage examples
- [ ] Implement `security` command - **DEFERRED** (detectors exist, CLI stub only)
- [ ] Implement `discover` command - **DEFERRED** (detectors exist, CLI stub only)

**Decision:** Security and discover commands deferred to prioritize Phase 4 (HAR collection via proxy), which is more critical for HawkScan workflows. The detection infrastructure in `harrier-detectors` is complete and can be wired to CLI commands post-Phase 4 MVP.

### Phase 3: Advanced Analysis (Deferred)
- [ ] Sensitive data detection (PII, credentials, tokens)
- [ ] API schema inference
- [ ] OpenAPI spec generation from HAR files
- [ ] Performance bottleneck identification
- [ ] Security issue reporting with severity levels

**Note:** Phase 3 deferred in favor of Phase 4 priority. Will revisit after proxy MVP.

### Phase 4: HAR Collection via Proxy (Completed)
- [x] HTTP/HTTPS MITM proxy implementation using `hudsucker`
- [x] TLS certificate generation and management with `rcgen`
- [x] HAR capture from intercepted traffic (buffer-and-write approach for MVP)
- [x] Proxy configuration and setup documentation
- [x] CA certificate installation guide (macOS/Linux/Windows)

**Status:** MVP complete. Basic HTTP/HTTPS proxy captures all traffic to HAR file on shutdown. Users can configure browsers to use the proxy, and comprehensive setup documentation is available in [docs/proxy-setup.md](docs/proxy-setup.md).

**Post-MVP Enhancements (Future):**
- Live filtering during capture
- Real-time analysis/streaming
- HAR file rotation for long-running captures
- Web UI for traffic inspection

### Phase 5: Browser Integration (MVP Complete)
- [x] Chrome binary detection (macOS/Linux/Windows)
- [x] Chrome launcher with DevTools Protocol
- [x] Profile management (temporary and persistent)
- [x] HAR generation from browser traffic
- [x] CLI command structure with filtering and StackHawk integration
- [ ] **Network event capture via CDP** - **STUBBED** (WebSocket connection, Network domain events)
- [ ] Headless mode support
- [ ] Screenshot and trace capture

**Status:** MVP complete. The `harrier chrome` command launches Chrome in headed mode, allows user interaction, and captures traffic on browser close. The infrastructure is in place with a stubbed CDP session that will be fully implemented post-MVP.

**Post-MVP Enhancements (Future):**
- Full CDP integration (WebSocket connection to Chrome)
- Network domain event listeners (requestWillBeSent, responseReceived, loadingFinished)
- Request/response body capture via CDP
- Headless mode (`--headless` flag)
- Screenshot capture
- Performance trace capture
- Live filtering during capture
- Real-time traffic display

### Phase 6: Polish & Distribution (Future)
- [ ] Binary releases for major platforms
- [ ] Installation via package managers (brew, cargo, etc.)
- [ ] Comprehensive documentation
- [ ] Example HAR files and tutorials
- [ ] Performance optimization for large files
- [ ] Progress indicators and better UX

## Current Focus

**Phase 5 MVP Complete - Next Steps**

With the Chrome integration MVP complete, the next priorities are:

1. **Complete CDP Integration** - Implement full WebSocket connection to Chrome DevTools Protocol for real network traffic capture
2. **Wire existing detectors to CLI** - The `harrier-detectors` crate has comprehensive auth and app-type detection that needs CLI integration
3. **Complete Phase 2** - Finish `security` and `discover` commands (backend infrastructure exists, just needs CLI wiring)
4. **Phase 6 consideration** - Begin planning for binary releases and distribution

## Wishlist

- Generate OAS from HAR
- Generate `stackhawk.yml[s]` from HAR
- Link current repo to StackHawk app
- Better API/SPA detection
