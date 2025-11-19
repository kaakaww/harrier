# Harrier

A command-line tool for analyzing, filtering, and working with HTTP Archive (HAR) files.

## Overview

Harrier makes working with HAR files easier, especially for security testing with [StackHawk](https://www.stackhawk.com/) and HawkScan. It provides fast analysis, flexible filtering, and security insights for HTTP traffic captured in HAR format.

## Features

- **Stats** - Analyze HAR files with traffic statistics, performance metrics, and host analysis
- **Filter** - Extract specific traffic by host, status code, method, or content type
- **Proxy** - Capture HTTP/HTTPS traffic in real-time with MITM proxy
- **Chrome** - Launch Chrome and capture network traffic via Chrome DevTools Protocol
- **Security** _(Coming Soon)_ - Detect authentication patterns and scan for sensitive data
- **Discover** _(Coming Soon)_ - Identify API types (REST, GraphQL, gRPC, WebSocket, etc.) and endpoints

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

### Proxy Command

Capture HTTP/HTTPS traffic in real-time using a Man-in-the-Middle (MITM) proxy:

```bash
# Start proxy on default port 8080
harrier proxy

# Specify custom port and output file
harrier proxy --port 3128 --output my-traffic.har

# Use custom CA certificate
harrier proxy --cert /path/to/ca.crt --key /path/to/ca.key
```

**How it works:**

1. Start the proxy with `harrier proxy`
2. The first time you run it, a CA certificate will be generated at `~/.harrier/ca.crt`
3. **Install the CA certificate** in your system's trust store (see [Proxy Setup Guide](docs/proxy-setup.md))
4. Configure your browser or application to use the proxy (e.g., `localhost:8080`)
5. Browse normally - all HTTP/HTTPS traffic will be captured
6. Press `Ctrl+C` to stop the proxy and write the HAR file

**Important:** You must install the CA certificate for HTTPS interception to work. Without it, browsers will show certificate errors. See the [Proxy Setup Guide](docs/proxy-setup.md) for detailed installation instructions for macOS, Linux, and Windows.

**Post-capture analysis:**

```bash
# View captured traffic statistics
harrier stats captured.har

# Filter to specific hosts
harrier filter captured.har --hosts api.example.com -o filtered.har
```

### Chrome Command

Launch Chrome in headed mode and capture network traffic directly via Chrome DevTools Protocol (CDP):

```bash
# Basic usage - launches Chrome and captures all traffic
harrier chrome

# Specify output file
harrier chrome --output my-session.har

# Filter to specific hosts (supports globs)
harrier chrome --hosts "api.example.com"
harrier chrome --hosts "*.example.com,*.cdn.com"

# Start at a specific URL
harrier chrome --url "https://app.example.com"

# Use a persistent profile for saved sessions/cookies
harrier chrome --profile my-app-testing

# Override Chrome location if not auto-detected
harrier chrome --chrome-path "/path/to/chrome"

# Run StackHawk scan after capture
harrier chrome --scan

# Combined example
harrier chrome --url "https://app.example.com" \
               --hosts "*.example.com" \
               --profile testing \
               --output app-traffic.har \
               --scan
```

**How it works:**

1. Harrier automatically detects your Chrome installation (macOS, Linux, Windows)
2. Chrome launches in headed mode so you can interact normally
3. Network traffic is captured via Chrome DevTools Protocol (CDP)
4. Browse, interact with web apps, or test workflows
5. When ready, press 's' to stop capture (Chrome continues), 'k' to kill Chrome and save, or close Chrome naturally
6. Harrier saves the HAR file with all captured requests, responses, headers, and response bodies
7. Response bodies larger than 15MB are automatically truncated for HawkScan compatibility
8. Optionally filter traffic to specific hosts
9. Optionally run StackHawk scan on the captured traffic

**Interactive capture control:**

When capturing traffic, you have three options:
- **'s' key**: Stop capturing and save HAR (Chrome remains open)
- **'k' key**: Kill Chrome and save HAR with captured traffic
- **Close Chrome**: Naturally close Chrome to stop and save

**Profile management:**

- Default: Uses a temporary profile (cleaned up automatically)
- `--profile <name>`: Uses persistent profile at `~/.harrier/profiles/<name>`
- Persistent profiles retain cookies, sessions, and browser state between captures

**Response body capture:**

- All response bodies are captured and included in HAR files
- Bodies larger than 15MB are truncated to meet HawkScan's 16MB limit
- Both text and binary content supported (base64 encoding for binary)
- Truncation metadata is preserved in the HAR file

**Integration with StackHawk:**

```bash
# Capture authenticated traffic, filter to API, and scan
harrier chrome --url "https://app.example.com/login" \
               --hosts "api.example.com" \
               --profile authenticated \
               --output api-traffic.har \
               --scan
```

**Status:** ✅ Fully functional MVP - Chrome integration with complete network capture and response body support is complete and tested on macOS.

## Coming Soon

The following features are planned but not yet implemented:

### Security Command
Analyze authentication and security patterns:
- Detect authentication methods (Basic, Bearer, JWT, OAuth, API Keys, Cookies)
- Scan for sensitive data exposure
- Identify insecure requests (HTTP, weak auth, etc.)

### Discover Command
Identify API types and discover endpoints:
- Detect API types (REST, GraphQL, gRPC, WebSocket, SOAP, etc.)
- Extract and list all endpoints
- Generate OpenAPI specifications from traffic

_Backend infrastructure for these features exists in the `harrier-detectors` crate and will be wired to CLI commands in a future release._

## Development

### Building and Testing

```bash
# Build (debug mode)
make build
cargo build

# Build (release mode)
make release-build
cargo build --release

# Run all tests
make test
cargo test --all

# Run linting (clippy + rustfmt)
make lint
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt -- --check

# Format code
cargo fmt

# Clean build artifacts
make clean
cargo clean

# Install locally
make install
cargo install --path .
```

### Releasing

Harrier uses an interactive release wizard to simplify the release process:

```bash
# Run the release wizard
make release
```

The wizard will:
1. Detect the current version
2. Prompt for release type (major/minor/patch/custom)
3. Show commits since last release
4. Run pre-release checks (tests, git status, etc.)
5. Update version in `Cargo.toml`
6. Create a git commit and tag
7. Show push instructions

After the wizard completes, push to trigger the release:

```bash
git push origin main
git push origin v1.0.0  # Replace with your version
```

This automatically triggers a GitHub Actions workflow that:
- Builds binaries for 6 platforms (macOS Intel/ARM, Windows x64/ARM, Linux x64/ARM)
- Creates a GitHub Release with all binaries attached
- Generates release notes from commits

### CI/CD

The project uses GitHub Actions for continuous integration and release automation:

**CI Workflow** (`.github/workflows/ci.yml`):
- **Lint** - Code formatting and clippy checks (ubuntu)
- **Test (Linux)** - Full test suite on Linux (ubuntu)
- **Test (macOS)** - Platform-specific tests only (macos)
- **Test (Windows)** - Platform-specific tests only (windows)

All jobs run in parallel for speed, with automatic cancellation on failure to save costs.

**Release Workflow** (`.github/workflows/release.yml`):
- Triggered by git tags matching `v*.*.*`
- Builds release binaries for 6 platforms in parallel
- Publishes to GitHub Releases with auto-generated notes

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
