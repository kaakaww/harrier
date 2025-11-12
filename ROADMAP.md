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

### 🚧 Phase 4: HAR Collection via Proxy (Current - MVP In Progress)
- [ ] HTTP/HTTPS MITM proxy implementation using `hudsucker`
- [ ] TLS certificate generation and management with `rcgen`
- [ ] HAR capture from intercepted traffic (buffer-and-write approach for MVP)
- [ ] Proxy configuration and setup documentation
- [ ] CA certificate installation guide (macOS/Linux/Windows)

**MVP Scope:** Basic HTTP/HTTPS proxy that captures all traffic to HAR file on shutdown. Live filtering and real-time analysis deferred to post-MVP iterations.

### 📋 Phase 5: Browser Integration (Planned)
- [ ] Chrome launcher with DevTools Protocol
- [ ] Network event capture via CDP
- [ ] HAR generation from browser traffic
- [ ] Headless browser automation
- [ ] Screenshot and trace capture

### 📋 Phase 6: Polish & Distribution (Future)
- [ ] Binary releases for major platforms
- [ ] Installation via package managers (brew, cargo, etc.)
- [ ] Comprehensive documentation
- [ ] Example HAR files and tutorials
- [ ] Performance optimization for large files
- [ ] Progress indicators and better UX

## Current Focus

**Phase 4 MVP - HAR Collection via Proxy**

Building basic HTTP/HTTPS MITM proxy to capture traffic for HawkScan workflows. This is prioritized over completing Phase 2 (security/discover commands) and Phase 3 (advanced analysis) because:

1. **Primary use case:** Proxy collection is more critical than additional analysis features
2. **Current capabilities sufficient:** Existing `stats` and `filter` commands meet immediate analysis needs
3. **Foundation ready:** All dependencies (hudsucker, rustls, rcgen) already integrated

**MVP Goal:** Intercept HTTP/HTTPS traffic, generate valid HAR file on shutdown, enable post-processing with existing filter command.

**Post-MVP:** Wire security/discover commands (infrastructure exists), add live filtering, streaming HAR writer.

## Notes

- **Priority shift:** Phase 4 (proxy) prioritized over Phase 2 completion and Phase 3 based on HawkScan workflow needs
- **Technical debt accepted:** Security and discover commands deferred with plan to backfill post-proxy MVP
- **Phase 5** (browser integration) remains future work, likely after Phase 4 MVP stabilizes
- Focus on StackHawk customer use cases: traffic capture, security testing, API discovery
- Keep CLI fast and composable with other Unix tools
