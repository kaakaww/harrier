# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

Updated Intel Mac builds to use macos-15-intel GitHub Actions runner

## [1.0.0] - 2025-12-28

### Added
- **Enhanced Auth Analysis** (`--focus auth`):
  - Third-party provider detection (Microsoft Entra, Auth0, Okta, Google, AWS Cognito, Firebase, Keycloak, OneLogin, Ping Identity, Salesforce)
  - OAuth flow detection from URL patterns and JWT claims
  - Credential tracing: tracks cookies and auth headers back to their origin endpoints
  - JWT details: algorithm, issuer, audience, expiration, and all claims
  - Session cookie security analysis with warnings for missing HttpOnly/Secure/SameSite
- **CLI Redesign**: Consolidated 8 commands into 6 workflow-oriented commands
  - New `analyze` command with `--focus` flags (map, auth) and `--all`
  - New `capture` command combining browser (default) and proxy (`--proxy`) modes
  - New `export` command for generating configs (`--hawkscan`)
- **Target URL Metadata**: `--url` value stored in HAR as `_harrier` metadata
  - Ensures accurate primary host detection in analysis
  - Handles URLs with or without scheme (`app.example.com` works)
  - User guidance hints when `--url` not specified
- **Shell Completions**: Tab completion support for Bash, Zsh, Fish, and PowerShell
  - New `harrier completion --shell <SHELL>` command generates completion scripts
  - Intelligent value hints for file paths, URLs, hostnames, and command-specific values
- **Profile Management**: New `harrier profile` command with `list`, `info`, `delete`, and `clean` subcommands
- **Persistent Default Profile**: Default profile now persists at `~/.harrier/profiles/default`
  - Retains logins, extensions, cookies, and settings between runs
  - Cache cleared on every startup via CDP
- **`--temp` Flag**: New flag for `capture` command to use temporary profiles
- **CDP-based Cache Clearing**: Browser cache cleared on every Chrome launch via CDP
- **CDP-based Navigation**: URLs navigated via CDP after cache clear for reliable capture

### Changed
- **BREAKING**: Commands consolidated - scripts will need updates:
  | Old Command | New Command |
  |-------------|-------------|
  | `harrier stats <FILE>` | `harrier analyze <FILE>` or `--focus stats` |
  | `harrier discover <FILE>` | `harrier analyze <FILE> --focus api` |
  | `harrier auth <FILE>` | `harrier analyze <FILE> --focus auth` |
  | `harrier map <FILE>` | `harrier analyze <FILE> --focus map` |
  | `harrier chrome` | `harrier capture` |
  | `harrier proxy` | `harrier capture --proxy` |
  | `harrier config <FILE>` | `harrier export <FILE> --hawkscan` |
- **Simplified Help Text**: Single-line-per-option format for all commands
- **Strict `--format` Handling**: Invalid format values now error instead of silently defaulting
- **Chrome Launcher**: Always launches to `about:blank`, navigation happens via CDP
- **Profile Storage**: All profiles stored in `~/.harrier/profiles/` directory

### Fixed
- **IP-based Captures**: `get_root_domain()` now returns IPs as-is instead of truncating
- **Primary Host Detection**: Filters out `chrome-extension://`, `data:`, and localhost URLs
- **Duplicate HAR Parsing**: Stats now reads file once and shares across analyses
- Chrome launch reliability on resource-constrained systems with longer timeout
- First page load now always captured in HAR (cache cleared before navigation)

## [0.2.0] - 2025-01-XX

### Added
- Initial HAR file analysis and filtering capabilities
- Chrome DevTools Protocol integration for traffic capture
- MITM proxy for HTTP/HTTPS traffic capture
- Authentication pattern detection
- Host-based filtering with glob support
- Statistics and analysis commands

[Unreleased]: https://github.com/azconger/harrier/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/azconger/harrier/releases/tag/v0.2.0
