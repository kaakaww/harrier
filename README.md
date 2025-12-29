# Harrier

[![Release](https://img.shields.io/github/v/release/kaakaww/harrier)](https://github.com/kaakaww/harrier/releases)

A CLI tool for analyzing, filtering, and capturing HTTP Archive (HAR) files.

## Overview

Harrier is a command-line interface tool for working with HTTP Archive (HAR) files. It provides utilities to collect, analyze, and modify HAR files. The goal of the project is to make it easier to work with HTTP traffic data for analysis and security testing.

## Installation

Download the latest release for your platform from [Releases](https://github.com/kaakaww/harrier/releases). Or, install from source with Cargo:

```bash
# From source
cargo install --path .
```

## Prerequisites

- **Chrome or Chromium** - Required for `harrier capture` browser mode. Harrier auto-detects Chrome in standard locations. Use `--chrome-path` to specify a custom location.

## Quick Start

```bash
# Display help
harrier --help

# Quick summary of any HAR file
harrier app.har

# Capture traffic from Chrome
harrier capture --url https://example.com

# Full analysis
harrier analyze app.har --all

# Generate HawkScan config
harrier export app.har --hawkscan
```

## Commands

### `harrier <FILE>` - Quick Summary

Show a quick overview of any HAR file:

```bash
harrier traffic.har
```

### `harrier analyze` - Analyze HAR Files

Analyze HAR files for security, authentication, and architecture:

```bash
# Summary (default)
harrier analyze app.har

# Focus on specific areas
harrier analyze app.har --focus map       # Architecture/hosts
harrier analyze app.har --focus auth      # Authentication patterns

# Multiple focus areas
harrier analyze app.har --focus map --focus auth

# Everything
harrier analyze app.har --all

# Scope to a specific host
harrier analyze app.har --host api.example.com

# Output formats
harrier analyze app.har --format json
harrier analyze app.har --format table
```

#### Authentication Analysis (`--focus auth`)

Deep analysis of authentication and authorization:

```bash
harrier analyze app.har --focus auth
```

Detects:
- **Auth Providers**: Microsoft Entra, Auth0, Okta, Google, AWS Cognito, Firebase, Keycloak
- **OAuth Flows**: Authorization code, token exchange, refresh patterns
- **Credentials**: Traces cookies and headers back to their origin endpoints
- **JWT Details**: Algorithm, issuer, audience, claims (email, roles, scope)
- **Security Issues**: Missing cookie attributes (HttpOnly, Secure, SameSite)

Example output:
```
Authentication
  Provider:     Microsoft Entra
                login.microsoftonline.com (3rd party)
  Method:       OAuth 2.0 Authorization Code

Authorization
  Session Cookies:
    auth-token           HttpOnly, Secure
      ⚠ Missing SameSite attribute

  Credential Sources:
    Cookie auth-token [JWT]  (45 requests)
      ← POST 200 (Set-Cookie header)  https://api.example.com/login
```

### `harrier capture` - Capture Traffic

Capture HTTP/HTTPS traffic via Chrome (default) or MITM proxy:

```bash
# Browser mode (default) - launches Chrome with DevTools Protocol
harrier capture
harrier capture --url https://example.com
harrier capture --output session.har

# Use a named profile (retains logins, cookies, extensions)
harrier capture --profile my-app

# Use temporary profile (auto-deleted after)
harrier capture --temp

# Proxy mode - start MITM proxy for mobile apps or any HTTP client
harrier capture --proxy
harrier capture --proxy --port 9090

# Filter captured traffic to specific hosts
harrier capture --host api.example.com
harrier capture --host "*.example.com,*.cdn.com"

# Show HawkScan guidance after capture
harrier capture --hawkscan
```

**Browser mode** is best for SPAs and sites requiring login. **Proxy mode** is best for mobile apps and any HTTP client.

#### Proxy Mode CA Certificate

For HTTPS interception in proxy mode, Harrier generates a CA certificate at `~/.harrier/ca/`. To trust this certificate:

- **macOS**: `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.harrier/ca/harrier-ca.crt`
- **Windows**: Import `harrier-ca.crt` via Certificate Manager (certmgr.msc)
- **Linux**: Copy to `/usr/local/share/ca-certificates/` and run `sudo update-ca-certificates`

See [docs/proxy-setup.md](docs/proxy-setup.md) for detailed instructions.

### `harrier export` - Generate Configs

Export HAR analysis to various formats:

```bash
# Generate HawkScan configuration
harrier export app.har --hawkscan

# Scope to specific host
harrier export app.har --hawkscan --host api.example.com

# Include all hosts (even non-scannable ones)
harrier export app.har --hawkscan --all-hosts

# Write to file
harrier export app.har --hawkscan -o stackhawk.yml
```

### `harrier filter` - Filter HAR Entries

Extract specific traffic from HAR files:

```bash
# Filter by host (exact or glob)
harrier filter traffic.har --host api.example.com
harrier filter traffic.har --host "*.example.com"

# Multiple hosts
harrier filter traffic.har --host api.com --host cdn.com
harrier filter traffic.har --host "api.com,cdn.com"

# Filter by status code
harrier filter traffic.har --status 2xx
harrier filter traffic.har --status 404
harrier filter traffic.har --status 500-599

# Filter by method
harrier filter traffic.har --method POST

# Combined filters (AND logic)
harrier filter traffic.har --host api.com --status 2xx --method POST

# Output formats
harrier filter traffic.har --host api.com                    # Pretty summary (default)
harrier filter traffic.har --host api.com --format json      # Full HAR JSON
harrier filter traffic.har --host api.com --format table     # CSV table
harrier filter traffic.har --host api.com -o filtered.har    # Write to file

# Read from stdin (for piping)
cat traffic.har | harrier filter - --host api.com
```

### `harrier profile` - Manage Chrome Profiles

```bash
harrier profile list                    # List all profiles
harrier profile info my-app             # Show profile details
harrier profile delete old-profile      # Delete a profile
harrier profile clean                   # Clear cache from all profiles
harrier profile clean --profile my-app  # Clear cache from specific profile
```

### `harrier completion` - Shell Completions

```bash
# Bash
echo 'source <(harrier completion --shell bash)' >> ~/.bashrc

# Zsh
echo 'source <(harrier completion --shell zsh)' >> ~/.zshrc

# Fish
harrier completion --shell fish > ~/.config/fish/completions/harrier.fish

# PowerShell
harrier completion --shell powershell >> $PROFILE
```

## Output Formats

All analysis commands support `--format`:

| Format | Description |
|--------|-------------|
| `pretty` | Human-readable colored output (default) |
| `json` | Machine-readable JSON |
| `table` | CSV format for spreadsheets |

## Integration with HawkScan

```bash
# Capture authenticated traffic and generate config
harrier capture --url https://app.example.com \
                --profile authenticated \
                --host api.example.com \
                --output api-traffic.har

# Generate HawkScan configuration
harrier export api-traffic.har --hawkscan -o stackhawk.yml

# Run scan
hawk scan
```

## Development

```bash
make build          # Build (debug)
make release-build  # Build (release)
make test           # Run all tests
make lint           # Run clippy + rustfmt
make install        # Install locally
```

## About HAR Files

HTTP Archive (HAR) is a JSON format for logging HTTP transactions. HAR files contain requests, responses, headers, cookies, and timing data.

Learn more: [HAR Specification](https://w3c.github.io/web-performance/specs/HAR/Overview.html)

## License

MIT - See [LICENSE](LICENSE) for details.

---

Made with ❤️ by [StackHawk](https://www.stackhawk.com/).
