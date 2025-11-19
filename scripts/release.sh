#!/usr/bin/env bash
#
# Release wizard for Harrier
#
# Interactive script to prepare and tag a new release.
# Run with: make release

set -e

# Handle Ctrl+C gracefully
trap 'echo -e "\n\nRelease cancelled by user."; exit 130' INT TERM

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Unicode symbols
CHECK="✓"
CROSS="✗"
ROCKET="🚀"
MEMO="📝"
WARNING="⚠️"
PACKAGE="📦"

# Helper functions
print_header() {
    echo -e "\n${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${BLUE}$1${NC}"
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

print_success() {
    echo -e "${GREEN}${CHECK}${NC} $1"
}

print_error() {
    echo -e "${RED}${CROSS}${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}${WARNING}${NC}  $1"
}

print_info() {
    echo -e "${CYAN}$1${NC}"
}

confirm() {
    local prompt="$1"
    local default="${2:-n}"

    if [ "$default" = "y" ]; then
        prompt="$prompt [Y/n]: "
    else
        prompt="$prompt [y/N]: "
    fi

    read -p "$(echo -e ${prompt})" response
    response=${response:-$default}

    [[ "$response" =~ ^[Yy]$ ]]
}

# Get current version from Cargo.toml
get_current_version() {
    grep -m1 '^version = ' Cargo.toml | sed 's/version = "\(.*\)"/\1/'
}

# Validate semver format
validate_semver() {
    local version="$1"
    if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?$ ]]; then
        return 1
    fi
    return 0
}

# Calculate next version
calculate_next_version() {
    local current="$1"
    local bump_type="$2"

    # Parse current version
    IFS='.' read -r major minor patch <<< "$current"
    patch="${patch%%-*}"  # Remove any pre-release suffix

    case "$bump_type" in
        major)
            echo "$((major + 1)).0.0"
            ;;
        minor)
            echo "${major}.$((minor + 1)).0"
            ;;
        patch)
            echo "${major}.${minor}.$((patch + 1))"
            ;;
    esac
}

# Main script
main() {
    echo -e "\n${ROCKET} ${BOLD}${CYAN}Harrier Release Wizard${NC}"
    print_header ""

    # Check if we're in the right directory
    if [ ! -f "Cargo.toml" ] || ! grep -q '\[workspace\]' Cargo.toml; then
        print_error "Not in Harrier project root directory"
        exit 1
    fi

    # Get current version
    CURRENT_VERSION=$(get_current_version)
    echo -e "${BOLD}Current version:${NC} ${GREEN}${CURRENT_VERSION}${NC}\n"

    # Ask for release type
    echo "What type of release?"
    echo "  ${BOLD}1)${NC} Major (breaking changes)"
    echo "  ${BOLD}2)${NC} Minor (new features, backward compatible)"
    echo "  ${BOLD}3)${NC} Patch (bug fixes only)"
    echo "  ${BOLD}4)${NC} Custom version"
    echo ""

    read -p "Selection [1-4]: " release_type

    case "$release_type" in
        1)
            NEW_VERSION=$(calculate_next_version "$CURRENT_VERSION" "major")
            ;;
        2)
            NEW_VERSION=$(calculate_next_version "$CURRENT_VERSION" "minor")
            ;;
        3)
            NEW_VERSION=$(calculate_next_version "$CURRENT_VERSION" "patch")
            ;;
        4)
            read -p "Enter custom version (e.g., 1.0.0-rc1): " NEW_VERSION
            if ! validate_semver "$NEW_VERSION"; then
                print_error "Invalid semver format"
                exit 1
            fi
            ;;
        *)
            print_error "Invalid selection"
            exit 1
            ;;
    esac

    echo -e "\n${BOLD}New version will be:${NC} ${GREEN}${NEW_VERSION}${NC}\n"

    # Show commits since last tag
    print_header "${MEMO} Commits since last release"

    LAST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
    if [ -n "$LAST_TAG" ]; then
        echo -e "${BOLD}Changes since ${LAST_TAG}:${NC}\n"
        git log --oneline --decorate --no-merges "${LAST_TAG}..HEAD" | head -20
        COMMIT_COUNT=$(git rev-list --count "${LAST_TAG}..HEAD")
        if [ "$COMMIT_COUNT" -gt 20 ]; then
            echo "... and $((COMMIT_COUNT - 20)) more commits"
        fi
    else
        print_warning "No previous tags found"
        echo -e "\n${BOLD}Recent commits:${NC}\n"
        git log --oneline --decorate --no-merges HEAD | head -10
    fi

    # Pre-release checks
    echo ""
    print_header "${PACKAGE} Pre-release checks"

    # Check git status
    if ! git diff-index --quiet HEAD --; then
        print_error "Working directory has uncommitted changes"
        git status --short
        exit 1
    fi
    print_success "Working directory is clean"

    # Check branch
    CURRENT_BRANCH=$(git branch --show-current)
    if [ "$CURRENT_BRANCH" != "main" ]; then
        print_warning "Not on main branch (currently on: $CURRENT_BRANCH)"
        if ! confirm "Continue anyway?"; then
            exit 0
        fi
    else
        print_success "On main branch"
    fi

    # Check if up to date with remote
    git fetch --quiet
    LOCAL=$(git rev-parse @)
    REMOTE=$(git rev-parse @{u} 2>/dev/null || echo "")

    if [ -n "$REMOTE" ]; then
        if [ "$LOCAL" != "$REMOTE" ]; then
            print_warning "Local branch is not up to date with origin/main"
            if ! confirm "Continue anyway?"; then
                exit 0
            fi
        else
            print_success "Up to date with origin/main"
        fi
    else
        print_warning "No upstream branch configured"
    fi

    # Run tests
    echo ""
    print_info "Running tests..."
    if cargo test --quiet --all 2>&1 | grep -q "test result:"; then
        print_success "All tests passing"
    else
        print_error "Tests failed"
        if ! confirm "Continue anyway?"; then
            exit 0
        fi
    fi

    # Show release summary
    echo ""
    print_header "📋 Release Summary"

    echo -e "  ${BOLD}Version:${NC}  ${CURRENT_VERSION} → ${GREEN}${NEW_VERSION}${NC}"
    echo -e "  ${BOLD}Tag:${NC}      ${CYAN}v${NEW_VERSION}${NC}"
    if [ -n "$LAST_TAG" ]; then
        echo -e "  ${BOLD}Commits:${NC}  ${COMMIT_COUNT} commits since ${LAST_TAG}"
    fi

    echo -e "\n${BOLD}The script will:${NC}"
    echo "  1. Update version in Cargo.toml"
    echo "  2. Run cargo check to validate"
    echo "  3. Commit changes"
    echo "  4. Create annotated git tag v${NEW_VERSION}"
    echo "  5. Show next steps (push instructions)"

    echo ""
    if ! confirm "Continue?"; then
        echo -e "\n${YELLOW}Release cancelled${NC}"
        exit 0
    fi

    # Update Cargo.toml version
    echo ""
    print_info "Updating Cargo.toml version..."

    # Use sed to update version in Cargo.toml (works on both macOS and Linux)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s/^version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" Cargo.toml
    else
        # Linux
        sed -i "s/^version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" Cargo.toml
    fi

    print_success "Updated Cargo.toml version"

    # Validate with cargo check
    print_info "Running cargo check..."
    if cargo check --quiet; then
        print_success "Cargo check passed"
    else
        print_error "Cargo check failed"
        print_warning "Reverting changes..."
        git checkout Cargo.toml
        exit 1
    fi

    # Create commit
    print_info "Creating commit..."
    git add Cargo.toml Cargo.lock
    git commit -m "Bump version to ${NEW_VERSION}"
    print_success "Created commit"

    # Create tag
    print_info "Creating git tag..."
    git tag -a "v${NEW_VERSION}" -m "Release v${NEW_VERSION}"
    print_success "Created tag: v${NEW_VERSION}"

    # Success!
    echo ""
    print_header "${GREEN}${CHECK} Release prepared locally!${NC}"

    echo -e "${BOLD}Next steps:${NC}\n"
    echo -e "  ${CYAN}git push origin main${NC}"
    echo -e "  ${CYAN}git push origin v${NEW_VERSION}${NC}\n"
    echo "This will trigger the release workflow and publish binaries."
    echo ""
}

# Run main function
main "$@"
