# Harrier

A command-line tool for collecting, analyzing, and modifying HTTP Archive (HAR) files.

## Overview

Harrier is designed to make working with HAR files easier, especially in the context of security testing with [StackHawk](https://www.stackhawk.com/) and HawkScan. HAR files capture HTTP traffic data and are useful for debugging, analysis, and testing.

## Project Goals

Harrier aims to provide a comprehensive toolkit for HAR file operations:

- **Collect** - Generate HAR files from various sources
- **Analyze** - Parse, inspect, and extract insights from HAR files
- **Modify** - Transform, filter, and sanitize HAR file contents
- **Integrate** - Work seamlessly with automation and testing workflows

## Initial Features (Planned)

- Parse and validate HAR files
- Extract specific requests/responses
- Filter by URL patterns, hostnames, or content types
- Sanitize sensitive data (tokens, credentials, PII)
- Generate summary statistics and metadata

## Installation

```bash
# From source
cargo install --path .

# Or run directly
cargo run -- [command] [args]
```

## Usage

```bash
# Validate a HAR file
harrier validate file.har

# Extract specific URLs
harrier filter file.har --url-pattern "*/api/*"

# Sanitize sensitive data
harrier sanitize file.har --output clean.har

# View summary statistics
harrier stats file.har
```

## Development

```bash
# Build
cargo build --release

# Run tests
cargo test

# Run linter
cargo clippy

# Format code
cargo fmt
```

## About HAR Files

HTTP Archive (HAR) is a JSON-based format for logging web browser interactions with web servers. HAR files contain:
- HTTP request/response headers and bodies
- Timing information
- Cookie and cache data
- SSL/TLS connection details

Learn more: [HAR Specification](https://w3c.github.io/web-performance/specs/HAR/Overview.html)

## Sponsor

This project is sponsored by [StackHawk](https://www.stackhawk.com/), purveyors of fine API discovery, test, and intelligence solutions.

## License

MIT - See [LICENSE](LICENSE) for details.
