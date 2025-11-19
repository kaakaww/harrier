.PHONY: help build test lint release clean install

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the project in debug mode
	cargo build

release-build: ## Build the project in release mode
	cargo build --release

test: ## Run all tests
	cargo test --all

lint: ## Run clippy and rustfmt checks
	cargo fmt -- --check
	cargo clippy --all-targets --all-features -- -D warnings

clean: ## Clean build artifacts
	cargo clean

install: ## Install harrier locally
	cargo install --path .

release: ## Run interactive release wizard
	@./scripts/release.sh
