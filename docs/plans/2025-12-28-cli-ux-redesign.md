# CLI UX Redesign: Workflow-Oriented Commands

**Date:** 2025-12-28
**Status:** Implemented

## Summary

Consolidated 8 commands into 6 workflow-oriented commands with a clean break (no deprecation period).

## New Command Structure

```
harrier <FILE>              Quick summary (unchanged)
harrier analyze <FILE>      Unified analysis (replaces map, auth)
harrier capture             Unified capture (replaces proxy, chrome) - browser default
harrier filter <FILE>       HAR filtering (enhanced)
harrier export <FILE>       Output generation (replaces config)
harrier profile             Chrome profile management (unchanged)
harrier completion          Shell completions (unchanged)
```

## Command Migration

| Old Command | New Command |
|-------------|-------------|
| `harrier map <FILE>` | `harrier analyze <FILE> --focus map` |
| `harrier auth <FILE>` | `harrier analyze <FILE> --focus auth` |
| `harrier config <FILE>` | `harrier export <FILE> --hawkscan` |
| `harrier chrome` | `harrier capture` (browser is default) |
| `harrier proxy` | `harrier capture --proxy` |

## Command Details

### `harrier analyze <FILE>`

Unified analysis command with focus areas:

```bash
harrier analyze app.har                    # Summary (default)
harrier analyze app.har --focus map        # Architecture/hosts
harrier analyze app.har --focus auth       # Authentication
harrier analyze app.har --focus security   # Security findings
harrier analyze app.har --all              # Everything
harrier analyze app.har --host api.example.com  # Scoped to host
```

**Focus enum values:** `map`, `auth`, `security`

### `harrier capture`

Unified traffic capture with browser as default:

```bash
harrier capture                            # Browser mode (default)
harrier capture --url https://example.com  # With starting URL
harrier capture --proxy                    # MITM proxy mode
harrier capture --proxy --port 9090        # Custom port
harrier capture -o traffic.har             # Custom output file
harrier capture --hawkscan                 # Show HawkScan guidance after
```

**Browser-specific flags:** `--url`, `--profile`, `--temp`, `--chrome-path`
**Proxy-specific flags:** `--port`, `--cert`, `--key`
**Shared flags:** `-o/--output`, `--hosts`, `--hawkscan`

### `harrier export <FILE>`

Output generation (currently HawkScan, extensible):

```bash
harrier export app.har --hawkscan          # Generate stackhawk.yml snippet
harrier export app.har --hawkscan --host api.example.com
harrier export app.har --hawkscan --all-hosts
harrier export app.har --hawkscan -o config.yml
```

**Future formats:** `--openapi`, `--postman`, `--curl`

## Files Modified

### Created
- `crates/harrier-cli/src/commands/analyze.rs`
- `crates/harrier-cli/src/commands/capture.rs`
- `crates/harrier-cli/src/commands/export.rs`

### Modified
- `crates/harrier-cli/src/main.rs` - New command enum
- `crates/harrier-cli/src/commands/mod.rs` - Module exports
- `crates/harrier-cli/src/commands/summary.rs` - Updated "Next Steps"
- `crates/harrier-cli/tests/chrome_command.rs` - Updated to test `capture`

### Deleted
- `crates/harrier-cli/src/commands/auth.rs`
- `crates/harrier-cli/src/commands/chrome.rs`
- `crates/harrier-cli/src/commands/config.rs`
- `crates/harrier-cli/src/commands/map.rs`
- `crates/harrier-cli/src/commands/proxy.rs`

## Design Decisions

1. **Browser as default capture mode** - Most common use case for StackHawk customers
2. **Summary as default analyze mode** - Quick overview, use `--focus` or `--all` for depth
3. **Clean break** - No deprecation warnings, old commands removed immediately
4. **Extensible export** - `--hawkscan` flag allows future formats (`--openapi`, etc.)

## Future Enhancements (Not in Scope)

- Filter stdin support (`harrier filter - --hosts api`)
- Filter `--format` fix (currently always outputs JSON)
- Plumbing layer (`harrier har`, `harrier detect`, `harrier emit`)
- Configuration file (`.harrier.yaml`)
- Interactive TUI mode
