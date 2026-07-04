use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use secrecy::SecretString;

use crate::api::auth::AuthMethod;
use crate::circuit_breaker::CircuitBreakerConfig;
use crate::types::error::VaultError;
use crate::types::response::AuthInfo;

/// A synchronous Vault client that wraps the async [`VaultClient`] with its own
/// single-threaded Tokio runtime.
///
/// # Caveats
///
/// - **Do not call its methods from within an async context.** Each method
///   drives its own runtime via `block_on`, and starting a runtime from within
///   a runtime panics. Build it and use it from synchronous code (or a
///   dedicated `std::thread`); in async code, use [`VaultClient`] with `.await`.
/// - **Safe to share across threads** (`Send + Sync`), but calls are serialized
///   on its single runtime thread — for parallel throughput, use multiple
///   clients or the async client.
/// - **No background renewal.** The background token/lease helpers
///   (`start_token_renewal`, `watch_lease`, …) are not exposed here, because a
///   single-threaded runtime only advances during a `block_on` call. Proactive
///   per-request renewal still works; for background renewal, run it yourself.
///
/// [`VaultClient`]: super::VaultClient
pub struct BlockingVaultClient {
    pub(crate) inner: super::VaultClient,
    pub(crate) rt: Arc<tokio::runtime::Runtime>,
}

impl fmt::Debug for BlockingVaultClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockingVaultClient")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

const _: () = {
    fn _assert_send_sync<T: Send + Sync>() {}
    fn _assert() {
        _assert_send_sync::<BlockingVaultClient>();
    }
};

impl BlockingVaultClient {
    /// Create a client with an address and plaintext token
    ///
    /// For more options, use [`BlockingVaultClient::builder()`]
    pub fn new(address: &str, token: &str) -> Result<Self, VaultError> {
        Self::builder().address(address).token_str(token).build()
    }

    /// Create a client from `VAULT_*` environment variables;
    /// token resolution order: `VAULT_TOKEN` → `~/.vault-token` → `None`
    pub fn from_env() -> Result<Self, VaultError> {
        BlockingClientBuilder::from_env().build()
    }

    pub fn builder() -> BlockingClientBuilder {
        BlockingClientBuilder(super::ClientBuilder::default())
    }

    pub fn set_token(&self, token: SecretString) -> Result<(), VaultError> {
        self.inner.set_token(token)
    }

    /// Return a client view with a different namespace (cheap Arc clone)
    #[must_use]
    pub fn with_namespace(&self, ns: &str) -> Self {
        BlockingVaultClient {
            inner: self.inner.with_namespace(ns),
            rt: Arc::clone(&self.rt),
        }
    }

    /// Return a client view with a different wrap TTL (cheap Arc clone)
    #[must_use]
    pub fn with_wrap_ttl(&self, ttl: &str) -> Self {
        BlockingVaultClient {
            inner: self.inner.with_wrap_ttl(ttl),
            rt: Arc::clone(&self.rt),
        }
    }
}

#[must_use]
pub struct BlockingClientBuilder(super::ClientBuilder);

impl BlockingClientBuilder {
    /// Pre-populate the builder from `VAULT_*` environment variables;
    /// token resolution order: `VAULT_TOKEN` → `~/.vault-token` → `None`
    pub fn from_env() -> Self {
        BlockingClientBuilder(super::ClientBuilder::from_env())
    }

    pub fn address(mut self, addr: &str) -> Self {
        self.0 = self.0.address(addr);
        self
    }

    pub fn token(mut self, token: SecretString) -> Self {
        self.0 = self.0.token(token);
        self
    }

    pub fn token_str(self, token: &str) -> Self {
        self.token(SecretString::from(token))
    }

    pub fn namespace(mut self, ns: &str) -> Self {
        self.0 = self.0.namespace(ns);
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.0 = self.0.timeout(timeout);
        self
    }

    pub fn max_retries(mut self, n: u32) -> Self {
        self.0 = self.0.max_retries(n);
        self
    }

    pub fn initial_retry_delay(mut self, d: Duration) -> Self {
        self.0 = self.0.initial_retry_delay(d);
        self
    }

    pub fn wrap_ttl(mut self, ttl: &str) -> Self {
        self.0 = self.0.wrap_ttl(ttl);
        self
    }

    pub fn forward_to_leader(mut self, yes: bool) -> Self {
        self.0 = self.0.forward_to_leader(yes);
        self
    }

    pub fn cli_mode(mut self, yes: bool) -> Self {
        self.0 = self.0.cli_mode(yes);
        self
    }

    pub fn danger_disable_tls_verify(mut self, yes: bool) -> Self {
        self.0 = self.0.danger_disable_tls_verify(yes);
        self
    }

    pub fn ca_cert_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.0 = self.0.ca_cert_pem(pem);
        self
    }

    pub fn client_cert_pem(mut self, cert: impl Into<Vec<u8>>, key: impl Into<Vec<u8>>) -> Self {
        self.0 = self.0.client_cert_pem(cert, key);
        self
    }

    pub fn auth_method(mut self, method: impl AuthMethod + 'static) -> Self {
        self.0 = self.0.auth_method(method);
        self
    }

    /// Enable the circuit breaker with the given configuration
    pub fn circuit_breaker(mut self, config: CircuitBreakerConfig) -> Self {
        self.0 = self.0.circuit_breaker(config);
        self
    }

    /// Register a callback invoked whenever the client's token changes
    pub fn on_token_changed(mut self, f: impl Fn(&AuthInfo) + Send + Sync + 'static) -> Self {
        self.0 = self.0.on_token_changed(f);
        self
    }

    pub fn with_reqwest_client(mut self, client: reqwest::Client) -> Self {
        self.0 = self.0.with_reqwest_client(client);
        self
    }

    pub fn build(self) -> Result<BlockingVaultClient, VaultError> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(VaultError::Config(
                "BlockingVaultClient cannot be created inside a Tokio runtime. \
                 Reason: BlockingVaultClient spawns its own single-threaded Tokio runtime, \
                 and nested runtimes are not supported. \
                 Fix: use VaultClient (async) with .await, or call \
                 BlockingVaultClient::new() from a std::thread outside the existing runtime."
                    .into(),
            ));
        }
        let inner = self.0.build()?;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| VaultError::Config(format!("tokio runtime: {e}")))?;
        Ok(BlockingVaultClient {
            inner,
            rt: Arc::new(rt),
        })
    }
}
