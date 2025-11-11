# Harrier

A command-line tool for analyzing, filtering, and working with HTTP Archive (HAR) files.

## Overview

Harrier makes working with HAR files easier, especially for security testing with [StackHawk](https://www.stackhawk.com/) and HawkScan. It provides fast analysis, flexible filtering, and security insights for HTTP traffic captured in HAR format.

## Features

- **Stats** - Analyze HAR files with traffic statistics, performance metrics, and host analysis
- **Filter** - Extract specific traffic by host, status code, method, or content type
- **Security** - Detect authentication patterns and scan for sensitive data
- **Discover** - Identify API types (REST, GraphQL, gRPC, WebSocket, etc.) and endpoints

## Installation

```bash
# From source
cargo install --path .

# Or run directly
cargo run -- [command] [args]
```

## Usage

### Stats Command

Analyze HAR file contents and generate traffic statistics:

```bash
# Basic statistics
harrier stats traffic.har

# With detailed timing information
harrier stats traffic.har --timings

# Show all hosts with request counts
harrier stats traffic.har --hosts

# Show authentication analysis
harrier stats traffic.har --auth

# All details
harrier stats traffic.har --verbose
```

### Filter Command

Extract specific traffic from HAR files:

```bash
# Filter to a single host
harrier filter traffic.har --hosts api.example.com -o filtered.har

# Filter with glob patterns
harrier filter traffic.har --hosts "*.example.com" -o filtered.har

# Multiple hosts (repeatable or comma-separated)
harrier filter traffic.har --hosts api.com --hosts cdn.com -o filtered.har
harrier filter traffic.har --hosts "api.com,cdn.com" -o filtered.har

# Filter by status codes
harrier filter traffic.har --status 2xx -o success.har
harrier filter traffic.har --status 404 -o notfound.har

# Combined filters (AND logic)
harrier filter traffic.har --hosts api.com --status 2xx --method POST

# Output to stdout for piping
harrier filter traffic.har --hosts api.com | jq '.log.entries | length'
```

### Security Command

Analyze authentication and security patterns:

```bash
# Full security analysis
harrier security traffic.har

# Check authentication patterns only
harrier security traffic.har --check-auth

# Scan for sensitive data
harrier security traffic.har --find-sensitive

# Show only insecure requests
harrier security traffic.har --insecure-only
```

### Discover Command

Identify API types and discover endpoints:

```bash
# Discover all APIs and app types
harrier discover traffic.har

# Show only API endpoints
harrier discover traffic.har --endpoints-only
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
