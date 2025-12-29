#!/usr/bin/env bash
#
# Release wizard for Harrier
# Creates a version bump commit with changelog and git tag for automated releases
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Symbols
CHECK="✓"
CROSS="✗"

# Print colored messages
info() { echo -e "${CYAN}$1${NC}"; }
success() { echo -e "${GREEN}${CHECK}${NC} $1"; }
error() { echo -e "${RED}${CROSS}${NC} $1"; exit 1; }
warn() { echo -e "${YELLOW}⚠${NC}  $1"; }

# Extract changelog content for a version (same logic as make changelog)
extract_changelog() {
    local version="$1"
    if [[ "$version" == "Unreleased" ]]; then
        awk '/^## \[Unreleased\]/{found=1; next} /^## \[/{if(found) exit} /^\[.*\]:/{next} found{print}' CHANGELOG.md
    else
        awk -v ver="$version" '/^## \[/{if(found) exit; if($0 ~ "\\["ver"\\]") found=1; next} /^\[.*\]:/{next} found{print}' CHANGELOG.md
    fi
}

# Check if unreleased section has content
unreleased_has_content() {
    local content
    content=$(extract_changelog "Unreleased")
    # Remove blank lines and check if anything remains
    [[ -n $(echo "$content" | grep -v '^[[:space:]]*$') ]]
}

# Promote changelog from Unreleased to version
promote_changelog() {
    local version="$1"
    local date
    date=$(date +%Y-%m-%d)
    local prev_version

    # Insert new version header after [Unreleased]
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s/^## \[Unreleased\]$/## [Unreleased]\\
\\
## [${version}] - ${date}/" CHANGELOG.md
    else
        sed -i "s/^## \[Unreleased\]$/## [Unreleased]\n\n## [${version}] - ${date}/" CHANGELOG.md
    fi

    # Update footer links
    prev_version=$(grep -o '\[.*\]: https://github.com/kaakaww/harrier/releases/tag/v.*' CHANGELOG.md | head -1 | sed 's/.*tag\/v//' || echo "")

    if [[ -n "$prev_version" ]]; then
        # Update Unreleased link to compare against new version
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sed -i '' "s|\[Unreleased\]: \(.*\)/compare/v.*\.\.\.HEAD|[Unreleased]: \1/compare/v${version}...HEAD|" CHANGELOG.md
        else
            sed -i "s|\[Unreleased\]: \(.*\)/compare/v.*\.\.\.HEAD|[Unreleased]: \1/compare/v${version}...HEAD|" CHANGELOG.md
        fi

        # Add new version link before existing version links
        local new_link="[${version}]: https://github.com/kaakaww/harrier/compare/v${prev_version}...v${version}"
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sed -i '' "/^\[Unreleased\]:.*HEAD$/a\\
${new_link}" CHANGELOG.md
        else
            sed -i "/^\[Unreleased\]:.*HEAD$/a ${new_link}" CHANGELOG.md
        fi
    fi
}

# ============================================================================
# Main Script
# ============================================================================

echo ""
echo -e "${BOLD}${BLUE}🚀 Harrier Release Wizard${NC}"
echo ""

# 1. Environment validation
[[ -f "Cargo.toml" ]] || error "Not in project root (no Cargo.toml found)"
grep -q '\[workspace\]' Cargo.toml || error "Not a workspace project"
[[ -f "CHANGELOG.md" ]] || error "No CHANGELOG.md found"

CURRENT_VERSION=$(grep -m1 '^version = ' Cargo.toml | sed 's/version = "\(.*\)"/\1/')
echo -e "${BOLD}Current version:${NC} ${GREEN}${CURRENT_VERSION}${NC}"
echo ""

# 2. Changelog pre-check
if ! grep -q "^## \[Unreleased\]" CHANGELOG.md; then
    echo -e "${RED}${CROSS}${NC} No [Unreleased] section found in CHANGELOG.md"
    echo ""
    echo "Add this to the top of your changelog (after the header):"
    echo ""
    echo -e "  ${CYAN}## [Unreleased]${NC}"
    echo ""
    echo -e "  ${CYAN}### Added${NC}"
    echo -e "  ${CYAN}- Your changes here${NC}"
    echo ""
    exit 1
fi

if ! unreleased_has_content; then
    echo -e "${RED}${CROSS}${NC} [Unreleased] section in CHANGELOG.md is empty"
    echo ""
    echo "Before releasing, add your changes to CHANGELOG.md under [Unreleased]:"
    echo ""
    echo -e "  ${CYAN}### Added${NC}"
    echo -e "  ${CYAN}- New feature X${NC}"
    echo ""
    echo -e "  ${CYAN}### Fixed${NC}"
    echo -e "  ${CYAN}- Bug Y${NC}"
    echo ""
    exit 1
fi
success "Changelog has unreleased content"

# 3. Version selection
# Parse current version
IFS='.' read -r major minor patch <<< "${CURRENT_VERSION%-*}"

echo ""
echo "What type of release?"
echo "  1) Patch (${major}.${minor}.$((patch + 1)))"
echo "  2) Minor (${major}.$((minor + 1)).0)"
echo "  3) Major ($((major + 1)).0.0)"
echo "  4) Custom"
echo ""
read -rp "Choice [1-4]: " choice
case "$choice" in
    1) NEW_VERSION="${major}.${minor}.$((patch + 1))" ;;
    2) NEW_VERSION="${major}.$((minor + 1)).0" ;;
    3) NEW_VERSION="$((major + 1)).0.0" ;;
    4) read -rp "Enter version (e.g., 1.0.0-rc1): " NEW_VERSION ;;
    *) error "Invalid choice" ;;
esac

[[ -n "$NEW_VERSION" ]] || error "No version specified"

# Check version doesn't already exist
if grep -q "^## \[${NEW_VERSION}\]" CHANGELOG.md; then
    error "Version ${NEW_VERSION} already exists in CHANGELOG.md"
fi

echo ""
echo -e "${BOLD}New version:${NC} ${GREEN}${NEW_VERSION}${NC}"

# 4. Context display
echo ""
info "Recent commits:"
echo ""
git log --oneline --no-merges -10
echo ""

info "Changelog to be released:"
echo ""
extract_changelog "Unreleased" | head -20
echo ""

# 5. Pre-flight checks
info "Running pre-flight checks..."
echo ""

# Working directory clean
if [[ -n $(git status --porcelain) ]]; then
    error "Working directory has uncommitted changes. Commit or stash them first."
fi
success "Working directory clean"

# On main branch
BRANCH=$(git branch --show-current)
if [[ "$BRANCH" != "main" ]]; then
    warn "Not on main branch (on: $BRANCH)"
    read -rp "Continue anyway? [y/N]: " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || exit 0
else
    success "On main branch"
fi

# Format check
if cargo fmt --check --quiet 2>/dev/null; then
    success "Code formatting OK"
else
    error "Code formatting issues. Run 'cargo fmt' first."
fi

# Clippy
info "Running clippy..."
if cargo clippy --all-targets --all-features --quiet -- -D warnings 2>/dev/null; then
    success "Clippy passed"
else
    warn "Clippy warnings found"
    read -rp "Continue anyway? [y/N]: " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || exit 0
fi

# Tests
info "Running tests..."
if cargo test --all --quiet 2>/dev/null; then
    success "Tests passed"
else
    warn "Some tests failed"
    read -rp "Continue anyway? [y/N]: " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || exit 0
fi

# 6. Final confirmation
echo ""
echo -e "${BOLD}Ready to release:${NC}"
echo -e "  Version:   ${CURRENT_VERSION} → ${GREEN}${NEW_VERSION}${NC}"
echo -e "  Tag:       ${CYAN}v${NEW_VERSION}${NC}"
echo -e "  Changelog: [Unreleased] → [${NEW_VERSION}]"
echo ""
read -rp "Continue? [y/N]: " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { echo "Cancelled."; exit 0; }

# 7. Execute release
echo ""

# Update Cargo.toml version
info "Updating Cargo.toml..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    sed -i '' "s/^version = \"${CURRENT_VERSION}\"/version = \"${NEW_VERSION}\"/" Cargo.toml
else
    sed -i "s/^version = \"${CURRENT_VERSION}\"/version = \"${NEW_VERSION}\"/" Cargo.toml
fi

# Verify cargo accepts it
cargo check --quiet 2>/dev/null || error "Cargo check failed after version update"
success "Updated Cargo.toml"

# Promote changelog
info "Updating CHANGELOG.md..."
promote_changelog "$NEW_VERSION"
success "Updated CHANGELOG.md"

# Commit and tag
info "Creating commit and tag..."
git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "chore: release v${NEW_VERSION}"
git tag -a "v${NEW_VERSION}" -m "Release v${NEW_VERSION}"
success "Created commit and tag"

# 8. Done
echo ""
echo -e "${GREEN}${BOLD}${CHECK} Release v${NEW_VERSION} prepared!${NC}"
echo ""
echo "Next step:"
echo -e "  ${CYAN}git push --follow-tags origin main${NC}"
echo ""
echo "This will trigger the release workflow:"
echo -e "  ${BLUE}https://github.com/kaakaww/harrier/actions${NC}"
echo ""
