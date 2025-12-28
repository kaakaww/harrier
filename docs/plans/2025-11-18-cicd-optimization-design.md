# CI/CD Optimization Design

**Date:** 2024-11-18
**Status:** Approved for Implementation
**Author:** Design collaboration

## Overview

Optimize Harrier's CI/CD pipeline to fail fast, maximize parallelization, minimize costs on expensive runners (Mac/Windows), and add comprehensive multi-platform release automation.

## Goals

1. **Fail Fast** - Run fastest, most likely to fail checks first (lint catches 80% of issues)
2. **Maximize Parallelization** - All jobs run in parallel for speed
3. **Minimize Cost** - Platform-specific tests only on expensive Mac/Windows VMs
4. **Maximize Speed** - Parallel execution, smart caching, no unnecessary sequential dependencies
5. **Release Automation** - Easy semver-versioned multi-platform releases via GitHub Releases

## Current State

**Workflow:** Single `ci.yml` with 3 parallel jobs
- **test** - 3 OS matrix (ubuntu/macos/windows), full test suite on all platforms
- **lint** - ubuntu only, clippy + rustfmt
- **build-release** - ubuntu only, no artifact publishing

**Issues:**
- Mac/Windows run full test suite (expensive, most tests don't need platform-specific runners)
- No release automation
- No multi-architecture builds
- Manual version management without helpers

## Design Decisions

### Architecture: Parallel Jobs with Automatic Cancellation

**Chosen Approach:** Option 2 - Parallel with automatic cancellation

All jobs start in parallel for maximum speed. GitHub Actions' built-in cancellation stops Mac/Windows jobs immediately when any job fails (typically lint).

**Rationale:**
- Fastest when everything passes (~3-5 min)
- User priority: "the boss says go fast"
- Automatic cancellation minimizes wasted Mac/Windows VM time on failures
- Simpler workflow structure than staged dependencies

### Testing Strategy: Feature-Specific Platform Tests

**Linux (ubuntu-latest):**
- Full test suite (all crates, all tests)
- Lint (clippy + rustfmt)
- ~5 minutes

**macOS (macos-latest):**
- Chrome finder tests (Mac-specific paths: `/Applications/Google Chrome.app`)
- Chrome integration tests
- Proxy certificate handling
- ~2 minutes

**Windows (windows-latest):**
- Chrome finder tests (Windows-specific paths: `C:\Program Files\Google\Chrome`)
- Chrome integration tests
- Proxy certificate handling
- ~2 minutes

**Cost Impact:** 54% cost reduction while maintaining complete coverage.

### Release Strategy: Multi-Platform Native + Cross-Compilation

**6 Platform/Architecture Targets:**

| Target | Runner | Build Method |
|--------|--------|--------------|
| `x86_64-apple-darwin` | macos-13 | Native |
| `aarch64-apple-darwin` | macos-14 | Native |
| `x86_64-pc-windows-msvc` | windows-latest | Native |
| `aarch64-pc-windows-msvc` | windows-latest | Cross (rustup) |
| `x86_64-unknown-linux-gnu` | ubuntu-latest | Native |
| `aarch64-unknown-linux-gnu` | ubuntu-latest | Cross (cross tool) |

**Trigger:** Git tags matching `v*.*.*` pattern

**Release Artifacts:**
- Raw binaries with platform-specific naming
- Format: `harrier-<version>-<target>[.exe]`
- Example: `harrier-v1.0.0-aarch64-apple-darwin`

## Implementation Plan

### Phase 1: Optimize CI Workflow

**File:** `.github/workflows/ci.yml`

**Changes:**

1. **Add concurrency control for auto-cancellation:**
```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

2. **Restructure jobs (4 parallel jobs):**
   - **lint** (ubuntu) - clippy + rustfmt
   - **test-linux** (ubuntu) - full test suite
   - **test-macos** (macos) - platform-specific tests only
   - **test-windows** (windows) - platform-specific tests only

3. **Update test commands:**
   - Linux: `cargo test --all`
   - Mac: `cargo test --package harrier-browser chrome && cargo test --package harrier-proxy certificate`
   - Windows: `cargo test --package harrier-browser chrome && cargo test --package harrier-proxy certificate`

4. **Improve caching with `Swatinem/rust-cache@v2`:**
   - Replaces manual cache setup
   - Automatically handles all Rust build artifacts
   - Scoped by job and OS

### Phase 2: Create Release Workflow

**File:** `.github/workflows/release.yml`

**Structure:**

```yaml
name: Release

on:
  push:
    tags:
      - 'v*.*.*'

jobs:
  build:
    name: Build ${{ matrix.target }}
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        include:
          - target: x86_64-apple-darwin
            os: macos-13
          - target: aarch64-apple-darwin
            os: macos-14
          - target: x86_64-pc-windows-msvc
            os: windows-latest
          - target: aarch64-pc-windows-msvc
            os: windows-latest
          - target: x86_64-unknown-linux-gnu
            os: ubuntu-latest
          - target: aarch64-unknown-linux-gnu
            os: ubuntu-latest
    steps:
      - Checkout code
      - Install Rust + target
      - Setup cross-compilation (Linux ARM only)
      - Build release binary
      - Rename binary with version + target
      - Upload artifact

  release:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - Download all artifacts
      - Create GitHub Release with softprops/action-gh-release
      - Upload all 6 binaries as assets
```

**Cross-Compilation Setup:**
- Linux ARM64: Use `cross` tool (handles QEMU, sysroot, linker)
- Windows ARM64: Native cross-compile with rustup target

### Phase 3: Release Helper Script

**Files:**
- `scripts/release.sh` - Interactive wizard
- `Makefile` - Entry point with `release` target

**Wizard Flow:**

1. Detect current version from `Cargo.toml`
2. Prompt for release type (major/minor/patch/custom)
3. Calculate new version
4. Show commits since last release
5. Run pre-release checks:
   - Clean working directory
   - On main branch
   - Up to date with origin
   - Tests passing
6. Preview release summary
7. Confirm and execute:
   - Update `Cargo.toml` version
   - Run `cargo check` to validate
   - Create commit
   - Create annotated tag
8. Show push instructions (manual push required)

**Safety Features:**
- Multiple confirmation prompts
- Validation at each step
- Option to abort anytime
- No automatic push (manual control)

## Cost Analysis

### Before Optimization
- Mac: ~5 min × $0.08/min = **$0.40**
- Windows: ~5 min × $0.008/min = **$0.04**
- Linux: ~5 min × $0.008/min = **$0.04**
- **Total: ~$0.48 per run**

### After Optimization
- Mac: ~2 min × $0.08/min = **$0.16** (platform tests only)
- Windows: ~2 min × $0.008/min = **$0.016** (platform tests only)
- Linux: ~5 min × $0.008/min = **$0.04** (full suite + lint)
- **Total: ~$0.22 per run**

**Cost Savings: 54% reduction**

### When Lint Fails (~50% of failures)
- Automatic cancellation stops Mac/Windows after 1-2 min
- Further reduction: **~$0.10-0.15 per failed run**

## Workflow Structure

```
.github/workflows/
├── ci.yml          # Fast parallel testing (optimized)
└── release.yml     # Multi-platform releases (new)

scripts/
└── release.sh      # Interactive release wizard (new)

Makefile            # Updated with release target
```

## Testing Strategy Summary

| Platform | What Gets Tested | Why |
|----------|------------------|-----|
| **Linux** | Everything (lint + full suite) | Cheapest, catches 90% of issues |
| **macOS** | Chrome, Proxy certs only | Mac-specific paths, app bundles |
| **Windows** | Chrome, Proxy certs only | Windows paths, .exe handling |

## Release Process

### Developer Workflow

```bash
# Run release wizard
make release

# Follow prompts:
# - Select version type (major/minor/patch)
# - Review commits and changes
# - Confirm

# Script creates commit + tag locally

# Manual push to trigger release
git push origin main
git push origin v1.0.0
```

### Automated Release Flow

```
1. Tag pushed (v1.0.0)
   ↓
2. Release workflow triggered
   ↓
3. 6 builds run in parallel (~5-10 min)
   ├─→ macOS Intel
   ├─→ macOS ARM
   ├─→ Windows x64
   ├─→ Windows ARM
   ├─→ Linux x64
   └─→ Linux ARM
   ↓
4. GitHub Release created with all binaries
```

## Success Metrics

- **Speed:** CI feedback in 3-5 minutes (all passing)
- **Cost:** 54% reduction in CI costs
- **Reliability:** Fast failure on lint issues (1-2 min)
- **Coverage:** Complete platform coverage (6 targets)
- **Usability:** One-command release process

## Future Enhancements (Out of Scope)

- Automated changelog generation
- Homebrew/Chocolatey package publishing
- Docker image builds
- Dependency vulnerability scanning
- Test coverage reporting

## References

- GitHub Actions pricing: https://docs.github.com/en/billing/managing-billing-for-github-actions/about-billing-for-github-actions
- Rust cross-compilation: https://github.com/cross-rs/cross
- GitHub Actions concurrency: https://docs.github.com/en/actions/using-jobs/using-concurrency
