<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# `blocking` feature review

A focused review of the synchronous client (`blocking` feature): the
`BlockingVaultClient` and its ~360 handler wrappers. Performed on this fork;
the accompanying tests live in
`crates/vault-client-rs/tests/mock/blocking_review_test.rs`.

## Scope & method

The blocking API is a **sync-over-async bridge**: `BlockingVaultClient` owns a
Tokio runtime (`Arc<Runtime>`) and every handler method is a mechanical
`self.rt.block_on(self.inner.<op>(...))` delegation. Reviewing all ~360
delegations by hand is low value; instead the review targeted:

1. the runtime bridge in `client/blocking_client.rs` (where real bugs hide),
2. the runtime footguns (nested runtimes, cross-context calls, threading),
3. behavioural parity of the bridge (results + error mapping), by sampling one
   method per engine family rather than all of them,
4. a structural scan of the delegations for copy-paste anomalies,
5. feature interactions (`blocking` + `auto-renew`).

## Findings

### 1. The runtime bridge is well built ✅

`blocking_client.rs` already defends the top footguns:

- **Nested-runtime guard at construction.** `build()` returns a helpful
  `VaultError::Config` if called from within a Tokio runtime, instead of
  panicking or deadlocking. *(Regression test: `build_inside_tokio_runtime_is_rejected`.)*
- **`Send + Sync` is statically asserted** via a compile-time check.
- **The runtime is shared** (`Arc<Runtime>`); `with_namespace` / `with_wrap_ttl`
  are cheap clones.
- A **single-threaded** runtime (`new_current_thread().enable_all()`) is used.

### 2. Calling a blocking method from an async context panics ⚠️ (by design, undocumented)

The construction guard does **not** cover per-method calls. A
`BlockingVaultClient` built outside a runtime but then used *inside* one (e.g.
passed into async code) panics on the inner `block_on` ("cannot start a runtime
from within a runtime"). It fails loudly — it does not hang or misbehave — but
this is a real footgun. *(Test: `blocking_call_inside_async_context_panics`.)*

**Recommendation:** document on the blocking client that its methods must not be
called from within an async context (use the async `VaultClient` there).

### 3. The client is genuinely safe to share across threads ✅

Despite the single-threaded runtime, the advertised `Send + Sync` holds up in
practice: an `Arc<BlockingVaultClient>` used concurrently from multiple OS
threads works — all calls succeed, with no panic or deadlock. Calls are
serialized on the one runtime thread (no parallelism), but correctness holds.
*(Test: `blocking_client_is_usable_from_multiple_threads`, 4 threads.)*

**Note for users:** for parallel blocking throughput, use multiple clients or
the async client; one blocking client serializes its calls.

### 4. No background renewal is exposed — limitation, not a bug ✅/📝

The blocking layer deliberately does **not** wrap the background renewal API
(`start_token_renewal`, `watch_lease`, `RenewalDaemon`, `LeaseWatcher`). This
sidesteps a real hazard: a `current_thread` runtime only makes progress *during*
`block_on`, so a background renewal task would starve between calls. Proactive
*per-request* renewal (inside `ensure_valid_token`) still works, because it is
awaited within the request's own `block_on`.

**Recommendation:** document that background token/lease renewal is not
available on the blocking client — run it yourself (e.g. a dedicated thread
calling a renew method periodically) if needed.

### 5. Behavioural parity holds through the bridge ✅

- Error mapping travels correctly: a `403` surfaces as
  `VaultError::PermissionDenied`. *(Test: `blocking_surfaces_permission_denied`.)*
- A non-KV engine round-trips correctly: transit `encrypt` returns the expected
  ciphertext. *(Test: `blocking_transit_encrypt_parity`.)*

### 6. Delegation pattern is consistent ✅

A structural scan of all **359** `block_on` delegations found **0** that do not
delegate to `self.inner.<op>` — no wrapper bypasses the async layer. This does
not prove per-method argument order, but rules out the common copy-paste class
of bug. A stratified sample (KV v2, transit) exercises the bridge end-to-end.

## Summary

| Area | Verdict |
| --- | --- |
| Runtime construction / guards | Solid |
| Cross-context (async) call | Panics loudly — document it |
| Thread sharing | Safe (serialized) |
| Background renewal | Not exposed (safe omission) — document it |
| Error / result parity | Correct |
| Delegation consistency | No anomalies (359/359) |

**Overall:** the bridge is soundly engineered; the author already handled the
highest-severity footgun (nested runtime at construction). The residual items
are **documentation gaps**, not correctness bugs: (a) methods must not be called
from an async context, and (b) there is no background renewal on the blocking
client. No code defects were found in this review.
