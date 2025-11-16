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

**Phase 4 Complete - Next Steps**

With the proxy MVP complete, the next priorities are:

1. **Wire existing detectors to CLI** - The `harrier-detectors` crate has comprehensive auth and app-type detection that needs CLI integration
2. **Complete Phase 2** - Finish `security` and `discover` commands (backend infrastructure exists, just needs CLI wiring)
3. **Phase 5 consideration** - Evaluate browser integration vs. further proxy enhancements

**Completed in Phase 4:**
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
