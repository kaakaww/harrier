# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Shell Completions**: Tab completion support for Bash, Zsh, Fish, and PowerShell
  - New `harrier completion --shell <SHELL>` command generates completion scripts
  - Comprehensive help in `completion --help` shows installation for all shells
  - Intelligent value hints for file paths, URLs, hostnames, and command-specific values
  - Simple, `gh`-style interface for ease of use
- **Profile Management**: New `harrier profile` command with `list`, `info`, `delete`, and `clean` subcommands
- **Profile Commands**:
  - `profile list` - List all Chrome profiles with sizes
  - `profile info <name>` - Show detailed profile information
  - `profile delete <name>` - Delete a profile (with confirmation)
  - `profile clean` - Clear cache from profiles while preserving cookies/extensions
- **Persistent Default Profile**: Default profile now persists at `~/.harrier/profiles/default`
  - Retains logins, extensions, cookies, and settings between runs
  - Cache cleared on every startup via CDP
- **`--temp` Flag**: New flag for `chrome` command to use temporary profiles
  - Temporary profiles auto-delete after Chrome closes
  - Takes precedence over `--profile` flag with warning message
- **First-Run Experience**: Informative message when default profile is created
- **Profile Size Warnings**: Warnings when profiles exceed 1GB in `profile list`
- **CDP-based Cache Clearing**: Browser cache cleared on every Chrome launch via CDP
- **CDP-based Navigation**: URLs navigated via CDP after cache clear for reliable capture
- **Longer CDP Connection Timeout**: Increased from 5 to 20 retry attempts (2.5s → 10s total)

### Changed
- **BREAKING**: Default `chrome` command behavior changed from temporary to persistent profile
  - Previous behavior: `harrier chrome` used temporary profile (auto-deleted)
  - New behavior: `harrier chrome` uses persistent `default` profile
  - **Migration**: Use `harrier chrome --temp` for old temporary profile behavior
- **Chrome Launcher**: Always launches to `about:blank`, navigation happens via CDP
- **Profile Storage**: All profiles stored in `~/.harrier/profiles/` directory

### Fixed
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
