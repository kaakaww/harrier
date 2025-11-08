# Harrier - HAR File CLI Tool

## Project Overview

Harrier is a command-line interface tool for working with HTTP Archive (HAR) files. It provides utilities to collect, analyze, and modify HAR files, making it easier to work with HTTP traffic data for security testing and analysis.

**Sponsor:** StackHawk
**Purpose:** Help StackHawk customers work with HAR files in the context of scanning applications with HawkScan.

## Tech Stack

- **Language:** Rust
- **Edition:** 2024
- **Type:** Command-line tool

## Project Goals

Harrier aims to provide a comprehensive toolkit for HAR file manipulation:

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

These files are commonly used for:
- Performance analysis
- Security testing and vulnerability scanning
- Debugging web applications
- Traffic replay and testing

## Development Guidelines

### Code Style
- Follow standard Rust formatting (`cargo fmt`)
- Use `cargo clippy` for linting
- Write idiomatic Rust code
- Prefer type safety and error handling with `Result<T, E>`

### Testing
- Write unit tests for core functionality
- Include integration tests for CLI commands
- Test with real-world HAR file examples

### Security Considerations
- Be cautious with sensitive data in HAR files (tokens, credentials, PII)
- Provide options to sanitize/redact sensitive information
- Validate HAR file structure before processing

### Dependencies
- Prefer well-maintained, popular crates
- Consider binary size for CLI distribution
- Use `serde` for JSON serialization/deserialization

## Common Tasks

When working with Claude Code, you might:
- Implement new HAR file parsing features
- Add CLI subcommands for different operations
- Improve error handling and user feedback
- Add filters or transformations for HAR data
- Integrate with StackHawk APIs or workflows

## Project Structure

```
harrier/
├── src/           # Source code
│   └── main.rs    # CLI entry point
├── Cargo.toml     # Rust package manifest
├── CLAUDE.md      # This file - project context for Claude Code
└── LICENSE        # Open source license
```

## Related Tools & Resources

- **StackHawk:** Application security testing platform
- **HawkScan:** StackHawk's dynamic application security testing (DAST) scanner
- **HAR Spec:** https://w3c.github.io/web-performance/specs/HAR/Overview.html
- **Chrome DevTools:** Built-in HAR export functionality

## Getting Started

```bash
# Build the project
cargo build

# Run in development
cargo run -- [command] [args]

# Run tests
cargo test

# Install locally
cargo install --path .
```

## Notes for Claude Code

- HAR files can be large; consider streaming or chunked processing for big files
- CLI UX is important; provide helpful error messages and usage examples
- Consider both single-file and batch operations
- Think about piping and composability with other Unix tools
