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

### 🚧 Phase 2: Core Analysis Features (Current)
- [x] Implement `stats` command - display HAR statistics, performance metrics, and host analysis
- [x] Implement `filter` command - filter by domain, status, method, content-type
- [x] Implement `security` command - auth and sensitive data scanning
- [x] Implement `discover` command - API endpoint discovery and app type classification
- [ ] Add comprehensive tests with real HAR file fixtures
- [ ] Update README with usage examples

### 📋 Phase 3: Advanced Analysis (Planned)
- [ ] Sensitive data detection (PII, credentials, tokens)
- [ ] API schema inference
- [ ] OpenAPI spec generation from HAR files
- [ ] Performance bottleneck identification
- [ ] Security issue reporting with severity levels

### 📋 Phase 4: HAR Collection via Proxy (Planned)
- [ ] HTTP/HTTPS MITM proxy implementation
- [ ] TLS certificate generation and management
- [ ] Real-time HAR generation from intercepted traffic
- [ ] Traffic filtering and selective capture
- [ ] Proxy configuration and setup documentation

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

**Phase 2:** Building out the core analysis commands so users can actually use Harrier to examine HAR files. The `stats` command is complete with basic statistics, performance metrics, and host analysis.

## Notes

- Phases 4 and 5 are lower priority - validate Phase 2-3 features with users first
- Focus on StackHawk customer use cases: security testing, API discovery, authentication analysis
- Keep CLI fast and composable with other Unix tools
