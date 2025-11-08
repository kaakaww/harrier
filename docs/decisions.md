# Technical Decisions

This document tracks key technical decisions made during development and the reasoning behind them.

## 2025-01-08: Initial Setup

### Workspace Structure
**Decision:** Use a Cargo workspace with 5 separate crates instead of a monolithic structure.

**Reasoning:**
- Separates concerns cleanly (CLI, core, proxy, browser, detectors)
- Allows independent testing of each component
- Proxy and browser can be optional features later
- Makes it easier for contributors to understand specific areas

**Crates:**
- `harrier-cli` - Binary with CLI interface
- `harrier-core` - HAR parsing, reading, writing
- `harrier-detectors` - Pattern detection (app types, auth methods)
- `harrier-proxy` - MITM proxy (Phase 4)
- `harrier-browser` - Chrome DevTools Protocol integration (Phase 5)

### Custom HAR Types vs har Crate
**Decision:** Define our own HAR data structures instead of using the `har` crate from crates.io.

**Reasoning:**
- The `har` crate (v0.8) uses an enum `Spec` to distinguish v1.2 vs v1.3
- This makes working with the data awkward - constant pattern matching required
- The crate also has nested enums for `Entries::List` and `Request::Full` that complicate access
- Most HAR files in the wild are v1.2, so we can focus on that
- Defining our own types gives us full control and simpler API
- We're using serde directly for JSON parsing anyway

**Trade-offs:**
- We maintain our own types (but they're stable - HAR 1.2 hasn't changed since 2012)
- We lose potential future HAR 1.3 support (but can add later if needed)
- Simpler code and better developer experience outweigh these concerns

### Clap for CLI
**Decision:** Use `clap` v4 with derive macros for CLI parsing.

**Reasoning:**
- Industry standard for Rust CLI apps
- Derive API is clean and type-safe
- Automatic help generation
- Subcommand support fits our design (analyze, filter, security, etc.)

### Analysis Engine Design
**Decision:** Use trait-based analyzers with a common `Analyzer` trait.

**Reasoning:**
- Makes it easy to add new types of analysis
- Each analyzer is independent and testable
- Follows Rust patterns and good separation of concerns
- Users can compose different analyzers as needed

### Security Focus
**Decision:** Build in security-focused features from the start (auth detection, sensitive data scanning).

**Reasoning:**
- Primary use case is StackHawk customers doing security testing
- Differentiates from generic HAR tools
- Security patterns are valuable for API discovery too

## Future Decisions

This section will grow as we make more architectural choices. Keep it simple - just record what we chose and why.
