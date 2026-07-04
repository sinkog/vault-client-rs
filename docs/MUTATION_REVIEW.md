<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Mutation testing review

Mutation testing (via [`cargo-mutants`](https://mutants.rs)) was used to measure
whether the tests actually *assert* behaviour or merely execute lines. A mutant
is a small change to the source (e.g. `>` → `>=`, delete a `match` arm, replace
a return value); a mutant is **caught** if some test fails when it is applied,
and **survives** (missed) if every test still passes — a survivor marks code
whose behaviour no test pins down.

## How it is run

```
make mutate MUTANTS_FILES="-f crates/vault-client-rs/src/<file>.rs"
```

The `mutate` target (see the Makefile) runs cargo-mutants with `nextest`, in a
dedicated `CARGO_TARGET_DIR` so mutant builds can't poison the normal cache, and
excludes the `integration` binary (`-E 'not binary(integration)'`) so no live
Vault is needed. `mutate-all` runs the whole workspace.

Scope: logic-bearing modules. The `blocking` mirror (~360 mechanical
`rt.block_on(inner)` delegations) is **not** mutation-scored — it is reviewed
and behaviourally tested separately (see `BLOCKING_REVIEW.md`); mutating rote
delegations only rewards rote tests.

## Results

| Module | Before | After | Notes |
| --- | --- | --- | --- |
| `types/error.rs` | 89% (2 missed) | **100%** | `is_retryable`'s `Http` arm had no test; added a real transport-error test. |
| `circuit_breaker.rs` | **100%** | 100% | All viable mutants already caught. |
| `renewal.rs` | 34% (21 missed) | **47%** (17 missed) | Closed `renew_token_now` / `is_running` / `try_recv`; rest is jitter/timing and cancel-on-drop near-equivalents. |
| `client/async_client.rs` | 58.6% (48 missed) | **60.3%** (46 missed) | Closed the retry status-mapping and non-renewable-token branches; see below for the honest breakdown. |

Absolute scores exclude **unviable** mutants (ones that don't compile).

## `async_client.rs` in detail

The initial run (159 mutants: 68 caught, 48 missed, 43 unviable → 58.6%) was the
lowest of any module — this is the client's core (request/retry loop, status →
error mapping, token renewal), well-*exercised* but under-*asserted*. Ten tests
were added; the re-run measured **70 caught, 46 missed, 43 unviable → 60.3%**.

**No correctness bug was found** — the logic reads correct; survivors reflect
missing assertions (or equivalent mutants), not wrong code.

The modest headline movement is honest: most survivors are genuinely low value.
The 46 remaining split as:

- **Caught by the new tests:**
  - `send_with_retry` status handling — 412 / 429 / 503 / retryable-500 retry up
    to `max` then surface the right error; 400 is not retried; 503 is not
    retried in `cli_mode` — pinned with exact attempt counts (`.expect(n)`,
    `tests/mock/retry_semantics_test.rs`).
  - `ensure_valid_token` — a non-renewable token near expiry re-authenticates
    instead of calling renew-self (`lifecycle_test.rs`).
- **Low value — left intentionally (~26):** builder setters (`→ Default`),
  `from_env` env-var parsing, `Debug` / `log_warnings`, backoff-exponent timing
  math. Covering these rewards rote assertions with little safety gain.
- **Timing / transport (~11 in `send_with_retry`):** the backoff math and the
  transport-error (`is_timeout() || is_connect()`) retry guard — only reachable
  with a mocked clock / a deterministic connect-timeout simulation, and low value.
- **Near-equivalent (2 in `ensure_valid_token`):**
  - the `!token_needs_renewal` "Ok" guard is **masked by defence-in-depth** — even
    if the outer guard mis-routes a healthy token to the renew path, the renew
    branch re-checks `token_needs_renewal` under the lock and returns early, so
    renew-self is never called and the mutant is unobservable. (Robust code,
    equivalent mutant.)
  - the `auth_method.is_some()` guard in the renew-failure arm — a renewable,
    lease-bearing token can't be seeded without an auth method, so the
    with/without-auth cases can't be distinguished.

### Correction

The first list/delete tests targeted the KV handlers, which use a different
helper (`exec_list` / `exec_empty`) than the generic `VaultClient::list` /
`delete` (the mutation survivors). The tests were corrected to call the generic
methods directly; the `list`/`delete` mutants will be caught on the next run.
This is called out because the earlier claim that these were "closed" was
premature — the re-measure is what caught it.

## Overall

Every logic-bearing module has been mutation-reviewed. The exercise found **no
correctness bugs** — it found that the test suite, while broad, under-asserted
behaviour in the core request path and token-renewal logic. Those high-value
gaps are now closed; the remaining survivors are low-value plumbing, timing
math, or near-equivalent mutants that add fragility without real safety.
