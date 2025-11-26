#!/usr/bin/env bash
#
# Release wizard for Harrier
# Creates a version bump commit and git tag for automated releases
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

# Check we're in the right directory
[[ -f "Cargo.toml" ]] || error "Not in project root (no Cargo.toml found)"
grep -q '\[workspace\]' Cargo.toml || error "Not a workspace project"

# Get current version
CURRENT_VERSION=$(grep -m1 '^version = ' Cargo.toml | sed 's/version = "\(.*\)"/\1/')

echo ""
echo -e "${BOLD}${BLUE}🚀 Harrier Release Wizard${NC}"
echo ""
echo -e "${BOLD}Current version:${NC} ${GREEN}${CURRENT_VERSION}${NC}"
echo ""

# Ask for version bump type
echo "What type of release?"
echo "  1) Major (1.0.0)"
echo "  2) Minor (0.2.0)"
echo "  3) Patch (0.1.1)"
echo "  4) Custom"
echo ""
read -rp "Choice [1-4]: " choice

# Calculate new version
IFS='.' read -r major minor patch <<< "${CURRENT_VERSION%-*}"
case "$choice" in
    1) NEW_VERSION="$((major + 1)).0.0" ;;
    2) NEW_VERSION="${major}.$((minor + 1)).0" ;;
    3) NEW_VERSION="${major}.${minor}.$((patch + 1))" ;;
    4) read -rp "Enter version (e.g., 1.0.0-rc1): " NEW_VERSION ;;
    *) error "Invalid choice" ;;
esac

[[ -n "$NEW_VERSION" ]] || error "No version specified"

echo ""
echo -e "${BOLD}New version:${NC} ${GREEN}${NEW_VERSION}${NC}"
echo ""

# Show recent commits
info "Recent commits:"
echo ""
git log --oneline --no-merges -10
echo ""

# Pre-flight checks
info "Running pre-flight checks..."

# Check git status
[[ -z $(git status --porcelain) ]] || error "Working directory has uncommitted changes"
success "Working directory clean"

# Check we're on main
BRANCH=$(git branch --show-current)
if [[ "$BRANCH" != "main" ]]; then
    warn "Not on main branch (on: $BRANCH)"
    read -rp "Continue anyway? [y/N]: " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || exit 0
else
    success "On main branch"
fi

# Check tests
info "Running tests..."
if cargo test --quiet --all 2>&1 > /dev/null; then
    success "Tests passing"
else
    warn "Tests failed"
    read -rp "Continue anyway? [y/N]: " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || exit 0
fi

# Final confirmation
echo ""
echo -e "${BOLD}Ready to release:${NC}"
echo -e "  Version: ${CURRENT_VERSION} → ${GREEN}${NEW_VERSION}${NC}"
echo -e "  Tag:     ${CYAN}v${NEW_VERSION}${NC}"
echo ""
read -rp "Continue? [y/N]: " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { echo "Cancelled."; exit 0; }

# Update version
info "Updating Cargo.toml..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    sed -i '' "s/^version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" Cargo.toml
else
    sed -i "s/^version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" Cargo.toml
fi

# Verify it worked
cargo check --quiet || error "Cargo check failed after version update"
success "Updated version"

# Commit and tag
git add Cargo.toml Cargo.lock
git commit -m "Bump version to ${NEW_VERSION}"
git tag -a "v${NEW_VERSION}" -m "Release v${NEW_VERSION}"
success "Created commit and tag"

echo ""
echo -e "${GREEN}${BOLD}✓ Release prepared!${NC}"
echo ""
echo "Next steps:"
echo -e "  ${CYAN}git push origin main${NC}"
echo -e "  ${CYAN}git push origin v${NEW_VERSION}${NC}"
echo ""
echo "This will trigger the release workflow and publish binaries."
echo ""
