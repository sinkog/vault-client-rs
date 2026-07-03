# vault-client-rs build orchestration. Every quality gate runs inside the
# pinned `rust-builder` container (see docker-compose.yml) so local runs match
# CI byte-for-byte. The `vault` dev service is started alongside it for the
# integration tests.
#
# Common flow:  make check      # fmt + clippy + deny + tests (the merge gate)
#               make coverage    # line coverage report (cargo-llvm-cov)
#               make shell       # drop into the builder container

DC       := docker compose
EXEC     := $(DC) exec -T rust-builder
# Clippy/rustc treat warnings as errors, matching CI's RUSTFLAGS.
DENY_WARN := -D warnings
# Line-coverage floor for `make coverage-check` (override: make coverage-check RUST_COV_MIN=85).
RUST_COV_MIN ?= 90
# Files excluded from coverage: the `blocking` feature is a purely mechanical
# sync-over-async mirror of the async API, and sys/mod.rs is trait-delegation
# boilerplate (`self.x().await`) that exists only for mockability. Neither
# carries logic worth asserting; measuring them only rewards rote tests.
COV_IGNORE ?= (blocking/mod\.rs|client/blocking_client\.rs|api/sys/mod\.rs)

.PHONY: help up down build shell clean tools-install \
        fmt fmt-check lint test coverage coverage-check deny check release

help: ## Show available make targets
	@grep -hE '^[a-zA-Z0-9_.-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# --- Container lifecycle ------------------------------------------------------

up: ## Start the rust-builder + vault containers in the background
	$(DC) up -d rust-builder vault

down: ## Stop and remove the containers (cache volumes are kept)
	$(DC) down

build: ## Pull the pinned images
	$(DC) pull

shell: up ## Open an interactive shell in the rust-builder container
	$(DC) exec rust-builder sh

clean: ## Remove containers and the cargo/target cache volumes
	$(DC) down -v

# --- One-time tool install (cached in the cargo-home volume) -------------------

tools-install: up ## Install cargo-nextest, cargo-deny, cargo-llvm-cov into the cache volume
	$(EXEC) cargo install --locked cargo-nextest cargo-deny cargo-llvm-cov

# --- Quality gates ------------------------------------------------------------

fmt: up ## Apply rustfmt across the workspace
	$(EXEC) cargo fmt --all

fmt-check: up ## Fail if formatting differs
	$(EXEC) cargo fmt --all --check

lint: up ## Run clippy as a hard gate (-D warnings)
	$(EXEC) cargo clippy --all-features --all-targets --workspace -- $(DENY_WARN)

test: up ## Run the full test suite (nextest) against the dev Vault
	$(EXEC) cargo nextest run --all-features --workspace --no-fail-fast

coverage: up ## Line-coverage report (cargo-llvm-cov; excludes boilerplate)
	$(EXEC) cargo llvm-cov nextest --all-features --workspace --ignore-filename-regex '$(COV_IGNORE)'

coverage-check: up ## Fail if line coverage < RUST_COV_MIN% (excludes boilerplate)
	$(EXEC) cargo llvm-cov nextest --all-features --workspace --ignore-filename-regex '$(COV_IGNORE)' --fail-under-lines $(RUST_COV_MIN)

deny: up ## Supply-chain gate (cargo-deny: advisories/licenses/bans/sources)
	$(EXEC) cargo deny check

check: fmt-check lint deny test ## Full merge gate: fmt + clippy + supply-chain + tests

# --- Release ------------------------------------------------------------------

release: up ## Build reproducible release artifacts (--locked)
	$(EXEC) cargo build --release --locked --workspace
