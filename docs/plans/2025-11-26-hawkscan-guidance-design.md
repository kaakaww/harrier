# HawkScan Guidance Feature Design

**Date:** 2025-01-26
**Status:** Approved
**Branch:** feature/hawkscan-enhancements

## Overview

Replace the `--scan` flag on the `chrome` command with `--hawkscan`, which prints configuration guidance instead of invoking the `hawk` CLI directly.

## Motivation

The original `--scan` flag attempted to invoke `hawk scan` as a subprocess, which introduced complexity:
- Environment variable management
- Working directory handling
- Error code passthrough
- Dependency on `hawk` binary being installed

A simpler approach: print the YAML configuration snippet users need to incorporate the captured HAR file into their `stackhawk.yml`. This is more transparent, requires no external dependencies, and works with any workflow.

## CLI Changes

### Before
```bash
harrier chrome --scan --output recording.har
```
- Invoked `hawk scan recording.har` as subprocess
- Required `hawk` CLI to be installed
- Captured and printed hawk's output

### After
```bash
harrier chrome --hawkscan --output recording.har
```
- Prints configuration guidance after HAR is saved
- No external dependencies
- User runs `hawk scan` separately

## Output Format

When `--hawkscan` is specified, after saving the HAR file:

```
✅ HAR file written to: recording.har

📋 To use this HAR with HawkScan, add the following to your stackhawk.yml:

hawk:
  spider:
    har:
      file:
        paths:
          - recording.har

Then run: hawk scan
```

The path in the YAML snippet matches the `--output` path (relative or absolute).

## Implementation

### Files to Modify

1. **`crates/harrier-cli/src/main.rs`**
   - Rename `scan` field to `hawkscan`
   - Update help text to `"Print HawkScan configuration guidance after capture"`

2. **`crates/harrier-cli/src/commands/chrome.rs`**
   - Rename `scan` parameter to `hawkscan` in `execute()` signature
   - Replace `run_hawk_scan()` with `print_hawkscan_guidance()`
   - Remove `which` crate check for `hawk` binary
   - Remove `stackhawk.yml` existence check

3. **`crates/harrier-cli/tests/chrome_command.rs`**
   - Update test to check for `--hawkscan` instead of `--scan`

### Code Removed

- `run_hawk_scan()` function (~30 lines)
- `which::which("hawk")` check
- `stackhawk.yml` existence warning

## Behavior Notes

- `--hawkscan` works independently of `--hosts` filter
- `--hawkscan` works with any `--output` path
- No validation of `stackhawk.yml` existence
- No invocation of external processes

## Future Considerations

Features explicitly deferred:
- Filtering HAR by domains in `stackhawk.yml`
- Auto-injecting HAR config into `stackhawk.yml`
- Direct `hawk` CLI invocation with passthrough args

These can be revisited if user demand warrants the complexity.
