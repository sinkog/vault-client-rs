# vault-client-rs Change Log

## 0.9.0 (in development)

### Bug Fixes

 * `SysHandler::raft_snapshot_restore` returns a typed error on a non-2xx
   response instead of reporting success
 * `VaultResponse<T>` and `KvReadResponse<T>` redact their payload in `Debug`
   output instead of printing it verbatim
 * The circuit breaker recovers from a cancelled half-open probe, admitting a
   fresh probe after `reset_timeout` instead of staying open permanently
 * Concurrent requests near token expiry share a single `renew-self` call and
   fall back to re-authentication when renewal fails
 * `RenewalDaemon` and `LeaseWatcher` shutdown and drop interrupt an in-flight
   renewal instead of waiting for it to return


## 0.8.0 (Mar 7, 2026)

### Enhancements

 * Publishing to `crates.io` now uses [Trusted Publishing](https://crates.io/docs/trusted-publishing)


## 0.7.0 (Feb 25, 2026)

### Enhancements

 * `ClientBuilder::token_str(token: &str)` is a convenience method that accepts a plain `&str`
   in place of `SecretString`, reducing boilerplate in tests and scripts
 * `ClientBuilder::from_env` now falls back to `~/.vault-token` when `VAULT_TOKEN` is not set
 * `ClientBuilder::cli_mode(bool)` optimises the client for short-lived CLI invocations
   by setting `max_retries` to zero and disabling retries on `VaultError::Sealed`
 * `ClientBuilder::circuit_breaker(CircuitBreakerConfig)` enables a client-side circuit breaker
   that short-circuits requests after a configurable number of consecutive failures
 * `ClientBuilder::on_token_changed(f)` registers a callback invoked whenever the client's token
   is updated via renewal or re-authentication
 * `BlockingClientBuilder::from_env` is a new helper for method chaining;
   `BlockingClientBuilder` now also exposes `circuit_breaker` and `on_token_changed`
 * `BlockingVaultClient::builder().build()` now returns a `VaultError::Config` with a clearer message when
   called from inside a Tokio runtime, explaining the nested-runtime restriction and recommending
   a possible workaround
 * `ClientBuilder::from_env` now also accepts `VAULT_SKIP_TLS_VERIFY` as a non-standard alias for
   `VAULT_SKIP_VERIFY`
 * `Kv2Handler` gains four convenience methods available without importing `Kv2Operations`:
   - `read_data<T>` returns just the data, discarding metadata
   - `read_field(path, field)` extracts a single field as a `String`, stringifying non-string values
   - `read_string_data` returns all fields as `HashMap<String, String>` (requires all values to be strings)
   - `write_field(path, field, value)` writes a single field (full overwrite; use `patch` to preserve other fields)
 * `Kv1Handler` gains three matching convenience methods available without importing `Kv1Operations`:
   - `read_data<T>` deserializes the secret into `T`
   - `read_field(path, field)` extracts a single field as a `String`, stringifying non-string values
   - `read_string_data` returns all fields as `HashMap<String, String>` (requires all values to be strings)

### Breaking Changes

 * `VaultError::Sealed` is now a struct variant carrying a `url: String` field with the Vault
   address
 * `VaultError::FieldNotFound` gained a `mount: String` field
 * `VaultError::RetryExhausted` has been removed


## 0.6.0 (Feb 22, 2026)

Initial public release.
