# Harrier Makefile
# Build automation for the Harrier CLI

.PHONY: help build release-build test lint fmt check-fmt pre-commit clean install release
.PHONY: changelog changelog-preview

# Default target
.DEFAULT_GOAL := help

# Variables
BINARY_NAME := harrier
VERSION := $(shell grep '^version' Cargo.toml | head -n1 | cut -d'"' -f2)

# Colors for output
CYAN := \033[0;36m
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m

## help: Show this help message
help:
	@echo "$(CYAN)Harrier Build System$(NC)"
	@echo ""
	@echo "$(GREEN)Available targets:$(NC)"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'

## build: Build the project in debug mode
build:
	@echo "$(CYAN)Building debug binary...$(NC)"
	cargo build

## release-build: Build the project in release mode
release-build:
	@echo "$(CYAN)Building release binary...$(NC)"
	cargo build --release

## test: Run all tests
test:
	@echo "$(CYAN)Running tests...$(NC)"
	cargo test --all

## lint: Run clippy lints
lint:
	@echo "$(CYAN)Running clippy...$(NC)"
	cargo clippy --all-targets --all-features -- -D warnings

## fmt: Format code
fmt:
	@echo "$(CYAN)Formatting code...$(NC)"
	cargo fmt

## check-fmt: Check code formatting without modifying
check-fmt:
	@echo "$(CYAN)Checking code formatting...$(NC)"
	cargo fmt -- --check

## pre-commit: Run all checks before committing (format, lint, test)
pre-commit:
	@echo "$(CYAN)╔════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(CYAN)║           Running Pre-Commit Checks                    ║$(NC)"
	@echo "$(CYAN)╚════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "$(YELLOW)[1/4] Formatting code...$(NC)"
	@cargo fmt
	@echo "$(GREEN)✓ Code formatted$(NC)"
	@echo ""
	@echo "$(YELLOW)[2/4] Checking format...$(NC)"
	@cargo fmt -- --check && echo "$(GREEN)✓ Format check passed$(NC)" || (echo "$(RED)✗ Format check failed$(NC)" && exit 1)
	@echo ""
	@echo "$(YELLOW)[3/4] Running clippy...$(NC)"
	@cargo clippy --all-targets --all-features -- -D warnings && echo "$(GREEN)✓ Clippy passed$(NC)" || (echo "$(RED)✗ Clippy failed$(NC)" && exit 1)
	@echo ""
	@echo "$(YELLOW)[4/4] Running tests...$(NC)"
	@cargo test --all && echo "$(GREEN)✓ Tests passed$(NC)" || (echo "$(RED)✗ Tests failed$(NC)" && exit 1)
	@echo ""
	@echo "$(GREEN)╔════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(GREEN)║          All pre-commit checks passed! ✓               ║$(NC)"
	@echo "$(GREEN)╚════════════════════════════════════════════════════════╝$(NC)"

## clean: Clean build artifacts
clean:
	@echo "$(CYAN)Cleaning build artifacts...$(NC)"
	cargo clean

## install: Install harrier locally
install: release-build
	@echo "$(CYAN)Installing $(BINARY_NAME)...$(NC)"
	cargo install --path crates/harrier-cli

## release: Run interactive release wizard
release:
	@echo "$(YELLOW)Tip: For better Ctrl+C handling, run directly: ./scripts/release.sh$(NC)"
	@./scripts/release.sh

## changelog: Extract changelog for a version (usage: make changelog or make changelog V=0.3.0)
changelog:
	@V=$${V:-$(VERSION)}; \
	if [ "$$V" = "Unreleased" ]; then \
		awk '/^## \[Unreleased\]/{found=1; next} /^## \[/{if(found) exit} /^\[.*\]:/{next} found{print}' CHANGELOG.md; \
	else \
		awk -v ver="$$V" '/^## \[/{if(found) exit; if($$0 ~ "\\["ver"\\]") found=1; next} /^\[.*\]:/{next} found{print}' CHANGELOG.md; \
	fi

## changelog-preview: Show changelog for current version with header
changelog-preview:
	@echo "$(CYAN)╔════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(CYAN)║       Changelog for v$(VERSION)$(NC)"
	@echo "$(CYAN)╚════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@$(MAKE) -s changelog
	@echo ""
