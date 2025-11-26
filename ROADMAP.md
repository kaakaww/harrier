# Harrier Roadmap

## Overview

Harrier is a CLI tool for collecting, analyzing, and modifying HTTP Archive (HAR) files, with a focus on security testing workflows for StackHawk customers.

## Phases

### ✅ Phase 1: Foundation (Completed)
- [x] Workspace structure with 5 crates
- [x] Custom HAR data types matching W3C HAR 1.2 spec
- [x] HAR file reader and writer
- [x] Basic CLI with subcommands
- [x] Core analysis engine (summary and performance)
- [x] App type detection (REST, GraphQL, SOAP, gRPC, WebSocket, MCP, SPA)
- [x] Auth pattern detection (Basic, Bearer, JWT, OAuth, API Keys, Cookies)

### 🟡 Phase 2: Core Analysis Features (Partially Complete)
- [x] Implement `stats` command - display HAR statistics, performance metrics, and host analysis
- [x] Implement `filter` command - filter by host (exact/glob), status, method, content-type with AND logic
- [x] Add comprehensive tests with real HAR file fixtures (65 tests passing)
- [x] Update README with usage examples
- [ ] Implement `security` command - **DEFERRED** (detectors exist, CLI stub only)
- [ ] Implement `discover` command - **DEFERRED** (detectors exist, CLI stub only)

**Decision:** Security and discover commands are deferred to prioritize Phase 4 (HAR collection via proxy), which is more critical for HawkScan workflows. The detection infrastructure in `harrier-detectors` is complete and can be wired to CLI commands post-Phase 4 MVP.

### 📋 Phase 3: Advanced Analysis (Deferred)
- [ ] Sensitive data detection (PII, credentials, tokens)
- [ ] API schema inference
- [ ] OpenAPI spec generation from HAR files
- [ ] Performance bottleneck identification
- [ ] Security issue reporting with severity levels

**Note:** Phase 3 deferred in favor of Phase 4 priority. Will revisit after proxy MVP.

### ✅ Phase 4: HAR Collection via Proxy (Completed)
- [x] HTTP/HTTPS MITM proxy implementation using `hudsucker`
- [x] TLS certificate generation and management with `rcgen`
- [x] HAR capture from intercepted traffic (buffer-and-write approach for MVP)
- [x] Proxy configuration and setup documentation
- [x] CA certificate installation guide (macOS/Linux/Windows)

**Status:** MVP complete! Basic HTTP/HTTPS proxy captures all traffic to HAR file on shutdown. Users can configure browsers to use the proxy, and comprehensive setup documentation is available in [docs/proxy-setup.md](docs/proxy-setup.md).

**Post-MVP Enhancements (Future):**
- Live filtering during capture
- Real-time analysis/streaming
- HAR file rotation for long-running captures
- Web UI for traffic inspection

### 🟡 Phase 5: Browser Integration (MVP Complete)
- [x] Chrome binary detection (macOS/Linux/Windows)
- [x] Chrome launcher with DevTools Protocol
- [x] Profile management (temporary and persistent)
- [x] HAR generation from browser traffic
- [x] CLI command structure with filtering and StackHawk integration
- [ ] **Network event capture via CDP** - **STUBBED** (WebSocket connection, Network domain events)
- [ ] Headless mode support
- [ ] Screenshot and trace capture

**Status:** MVP complete! The `harrier chrome` command launches Chrome in headed mode, allows user interaction, and captures traffic on browser close. The infrastructure is in place with a stubbed CDP session that will be fully implemented post-MVP.

**Completed in Phase 5 MVP:**
- ✅ Cross-platform Chrome binary detection with `ChromeFinder`
- ✅ Profile management with temporary/persistent profiles (RAII cleanup)
- ✅ Chrome process lifecycle with `ChromeLauncher`
- ✅ CDP debugging port configuration
- ✅ Network capture data structures (`NetworkRequest`, `NetworkResponse`, `NetworkCapture`)
- ✅ HAR conversion logic (W3C HAR 1.2 compliant)
- ✅ CLI command with `--output`, `--hosts`, `--scan`, `--chrome-path`, `--url`, `--profile`
- ✅ Host filtering integration with existing `harrier-core` filter
- ✅ StackHawk scan integration with `--scan` flag
- ✅ Signal handling (Ctrl+C with user confirmation)
- ✅ Comprehensive documentation in README.md

**Post-MVP Enhancements (Future):**
- Full CDP integration (WebSocket connection to Chrome)
- Network domain event listeners (requestWillBeSent, responseReceived, loadingFinished)
- Request/response body capture via CDP
- Headless mode (`--headless` flag)
- Screenshot capture
- Performance trace capture
- Live filtering during capture
- Real-time traffic display

### 📋 Phase 6: Polish & Distribution (Future)
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

**Recent Accomplishments:**

**Phase 5 (Chrome Integration):**
- ✅ Cross-platform Chrome binary detection
- ✅ Chrome launcher with CDP debugging port
- ✅ Profile management (temporary/persistent)
- ✅ HAR conversion infrastructure
- ✅ CLI command with filtering and StackHawk integration
- ✅ Signal handling and graceful shutdown

**Phase 4 (Proxy):**
- ✅ Full HTTP/HTTPS MITM proxy with TLS interception
- ✅ Automatic CA certificate generation and management
- ✅ HAR capture on proxy shutdown
- ✅ Comprehensive setup documentation with platform-specific instructions
- ✅ Integration with existing `filter` and `stats` commands for post-processing

## Notes

- **Priority shift:** Phase 4 (proxy) prioritized over Phase 2 completion and Phase 3 based on HawkScan workflow needs
- **Technical debt accepted:** Security and discover commands deferred with plan to backfill post-proxy MVP
- **Phase 5** (browser integration) remains future work, likely after Phase 4 MVP stabilizes
- Focus on StackHawk customer use cases: traffic capture, security testing, API discovery
- Keep CLI fast and composable with other Unix tools

## Wishlist

- Generate OAS from HAR
- Generate `stackhawk.yml[s]` from HAR
- Link current repo to StackHawk app
- Better API/SPA detection