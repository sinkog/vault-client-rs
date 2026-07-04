# Instructions for AI Agents

## What is This Codebase?

A modern Rust client for [Vault](https://www.hashicorp.com/en/products/vault) targeting
Rust `1.94+`.

Design notes and proposals live in `~/Development/md/vault-client-rs/` (numbered
documents plus `vault_client_rs_ergonomics.md`). Read the relevant one before
making non-trivial changes.

## Build System

All the standard Cargo commands apply but with two important details: add `--all-features` so that
all feature-gated code (`blocking`, `auto-renew`) is included, and `--workspace` so that the
test utilities crate is covered too.

 * `cargo build --workspace --all-features` to build
 * `cargo nextest run --workspace --all-features` to run tests
 * `cargo clippy --workspace --all-features --all-targets` to lint (`--all-targets` lints test code, which CI does too)
 * `cargo fmt` to reformat

Publishing happens in CI on tag push (see Releases); never run `cargo publish` by hand.

Always run `cargo check --workspace --all-features` before making changes to verify the codebase compiles cleanly.
If compilation fails, investigate and fix compilation errors before proceeding with any modifications.


## Repository Layout

This is a Cargo workspace with the following crates:

 * `crates/vault-client-rs/`: the main library crate
 * `crates/vault-client-rs-test/`: test utilities (mock server helpers, response builders)

## Key Files

 * `src/lib.rs`: crate root, module declarations and public re-exports
 * `src/client/async_client.rs`: `VaultClient`, `ClientBuilder`, `TokenState`, retry logic
 * `src/client/blocking_client.rs`: synchronous wrapper around the async client, feature-gated on `blocking`
 * `src/api/traits.rs`: operation traits for all handlers (enables mocking)
 * `src/api/auth/`: auth method handlers (approle, aws, azure, cert, gcp, github, kubernetes, kerberos, ldap, oidc, radius, token, userpass)
 * `src/api/sys/`: system handlers (health, seal, lease, mounts, auth, policy, audit, wrapping, plugins, raft, rekey, quotas, namespaces)
 * `src/api/kv2.rs`: KV v2 handler with convenience methods
 * `src/api/*.rs`: secret engine handlers (kv1, transit, pki, database, ssh, cubbyhole, aws, azure, gcp, consul, nomad, rabbitmq, terraform, totp, identity)
 * `src/types/error.rs`: `VaultError` enum with retryability metadata
 * `src/types/secret.rs`: `MountPath`, `SecretPath` validated newtypes
 * `src/types/redaction.rs`: configurable log redaction (`Full`/`Partial`/`None`)
 * `src/types/*.rs`: request/response types per engine
 * `src/circuit_breaker.rs`: circuit breaker state machine
 * `src/renewal.rs`: token renewal daemon and lease watchers (feature-gated on `auto-renew`)
 * `src/blocking/mod.rs`: blocking handler wrappers (feature-gated on `blocking`)

## Test Suite Layout

Tests are consolidated into three test binaries (plus the test utilities crate) for faster compilation:

 * `tests/mock/`: tests that use `wiremock` (HTTP-level mocking)
 * `tests/unit/`: unit and property-based tests (the latter use `proptest`)
 * `tests/integration/`: integration tests that require a locally running Vault node

Each directory has a `main.rs` crate root that declares all modules.

Never put tests inline in an implementation module under `#[cfg(test)]`. Every
test lives in one of the three directories above, wired through its `main.rs` for much
faster builds (linking specifically).

A `pub(crate)` type that an external test cannot name is exercised through the
public API, not by adding an in-crate test module.

Write tests that exercise behavior. Do not add tests to chase a coverage number.
Focus on meaningful coverage improvements.

Use `cargo nextest run --profile default --workspace --all-features '--' --exact [test module name]` to run
all tests in a specific module.

### Property-based Tests

Property-based tests are written using [proptest](https://docs.rs/proptest/latest/proptest/) and
use a naming convention: they begin with `prop_`.

To run the property-based tests specifically, use `cargo nextest run --workspace --all-features 'prop_'`.

## Rust Code Style

 * Use top-level `use` statements; never a function-local `use`
 * Prefer a plain `use` import; on a genuine name clash, alias with `use ... as ...`; reach
   for a fully-qualified path only when nothing else disambiguates
 * Prefer the type system (generics, traits, newtypes) over macros for reducing duplication.
   Some duplication is acceptable when the alternative is forced indirection
 * Tests live under `tests/{mock,unit,integration}/`, never inline under `#[cfg(test)]` in an
   implementation module

End every task with these, all clean:

 * `cargo fmt`
 * `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-features --all-targets`
 * `RUSTFLAGS="-D warnings" cargo nextest run --workspace --all-features`

## Domain Primitives Are Newtypes

Never let a `String` carry a value with a specific domain meaning, e.g. a mount path, secret
path, token, or engine identifier. Use a validated newtype (see
`src/types/secret.rs`: `MountPath`, `SecretPath`).

Add a newtype for any new domain primitive rather than a `String` alias.

## Source of Domain Knowledge

The [Vault HTTP API guide](https://developer.hashicorp.com/vault/api-docs).

## Comments, Writing Style and Voice

Keep comments short and to the point. Avoid filler words like "This function does X" when the
function name already says it. Don't add doc comments to obvious methods. Match the existing
comment density — the codebase is deliberately light on comments.

 * Only add important comments: those that communicate information the code cannot
 * Prefer a terse comment (ideally one short line) above the line being commented on; reduce the use of multi-line comment blocks
 * Strictly no trailing comments like `let a = 1; // ...`
 * No comment references the current task, a fix or review-finding number, or callers
 * Doc comments (`///`) do not end with a full stop; module-level `//!` comments may

### Voice

Write like an engineer who values clarity and simplicity. This applies
to all prose: design docs, analyses, notes, and commit messages.

 * Plain and factual: state the why in one line, never narrate the what
 * Literal mechanism over metaphor: name the actual thing, not an image of it
 * Prefer the plainest word. No coined verbs, no jargon for its own sake
 * No flourish, no editorializing, no imagery. Real domain terms are fine
 * If a sentence needs a second clause to justify itself, it is probably too clever

### Writing and Markdown Style

 * Never add full stops to Markdown list items
 * Use `*` for Markdown list bullets, matching this repo and the other Rust projects
 * Use "X and Y" in prose, not "X / Y" slash-shorthand. Exceptions: unit
   fractions (`bytes/sec`), single-concept abbreviations (`I/O`), and paths
   or code (`tests/unit/`, `src/lib.rs`)
 * Wrap code identifiers in backticks in prose: types like `Vec<T>`, traits
   like `Display`, functions like `Iterator::next`, modules, file names, and paths
 * Avoid robotic labels such as `**Thing / other:**`; write a plain sentence or a simple label
 * Match the existing conventions of the file and subdirectory you are
   editing — bullet character, heading depth, ID schemes, and table shape
   vary by project, and the local choice wins

## Change Log

If asked to perform change log updates, consult and modify `CHANGELOG.md` and stick to its
existing writing style.

## Releases

### How to Roll (Produce) a New Release

Suppose the current development version in `Cargo.toml` is `0.N.0` and `CHANGELOG.md` has
a `## 0.N.0 (in development)` section at the top.

To produce a new release:

 1. Update the changelog: replace `(in development)` with today's date, e.g. `(Feb 20, 2026)`. Make sure all notable changes since the previous release are listed
 2. Commit with the message `0.N.0` (just the version number, nothing else)
 3. Tag the commit: `git tag v0.N.0`
 4. Bump the dev version: back on `main`, set `Cargo.toml` workspace version to `0.(N+1).0` and update the `vault-client-rs` dependency version in `crates/vault-client-rs-test/Cargo.toml` to match
 5. Add a new `## 0.(N+1).0 (in development)` section to `CHANGELOG.md` with `No changes yet.` underneath
 6. Commit with the message `Bump dev version`
 7. Push: `git push && git push --tags`

The tag push triggers `.github/workflows/release.yml`, which publishes the crate to crates.io
via Trusted Publishing (OIDC). No manual `cargo publish` needed.

## Git Commits

 * Do not commit changes automatically without an explicit permission to do so
 * Never add yourself as a git commit coauthor
 * Never mention yourself in commit messages in any way (no "Generated by", no AI tool links, etc)
 * Never skip hooks (`--no-verify`) or bypass commit signing unless the user explicitly requests it

## Iterative Post-Implementation Review (IPIR)

Review the changes very carefully and holistically for correctness and safety,
opportunities to meaningfully simplify the implementation without losing
fidelity and effectiveness, the use of Rust idioms, the rich type system
patterns, meaningful test coverage, API usability and whether the changes are
worth adopting to begin with.

Look hard for ways to meaningfully improve both the tests and the implementation.

Perform up to 5 such iterations (holistic analysis runs). If three consecutive
iterations find no meaningful improvement, report that and stop early.
