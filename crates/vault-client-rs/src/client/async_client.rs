use std::fmt::{self, Write};
use std::fs;
use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, Instant};

use rand::RngExt;
use reqwest::{Client, Method, Response};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use serde::de::DeserializeOwned;
use url::Url;
use zeroize::Zeroizing;

use tracing::Instrument;

use crate::api;
use crate::api::auth::{AuthMethod, AuthMethodDyn};
use crate::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
use crate::types::error::VaultError;
use crate::types::kv::ListResponse;
use crate::types::response::{AuthInfo, VaultResponse};

const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// HTTP LIST method used by Vault's list endpoints
static METHOD_LIST: LazyLock<Method> =
    LazyLock::new(|| Method::from_bytes(b"LIST").expect("LIST is a valid HTTP method"));

/// An asynchronous Vault client
///
/// Build instances with [`ClientBuilder`]
#[derive(Clone)]
pub struct VaultClient {
    pub(crate) inner: Arc<VaultClientInner>,
    pub(crate) namespace_override: Option<String>,
    pub(crate) wrap_ttl_override: Option<String>,
}

const _: () = {
    fn _assert_send_sync<T: Send + Sync>() {}
    fn _assert() {
        _assert_send_sync::<VaultClient>();
    }
};

impl fmt::Debug for VaultClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultClient")
            .field("base_url", &self.inner.base_url.as_str())
            .finish_non_exhaustive()
    }
}

type TokenChangedCallback = Arc<dyn Fn(&AuthInfo) + Send + Sync>;

pub(crate) struct VaultClientInner {
    pub(crate) http: Client,
    pub(crate) base_url: Url,
    pub(crate) token: RwLock<Option<TokenState>>,
    pub(crate) namespace: Option<String>,
    pub(crate) config: ClientConfig,
    pub(crate) auth_method: Option<Arc<dyn AuthMethodDyn>>,
    pub(crate) circuit_breaker: Option<CircuitBreaker>,
    pub(crate) on_token_changed: Option<TokenChangedCallback>,
    /// Serializes proactive token renewal so concurrent requests near expiry
    /// don't each fire their own redundant `renew-self` call
    pub(crate) renewal_lock: tokio::sync::Mutex<()>,
}

/// Internal token state; fields beyond `value` are populated by
/// `update_token_from_auth` and used by the renewal daemon
pub(crate) struct TokenState {
    pub value: SecretString,
    pub expires_at: Option<Instant>,
    pub renewable: bool,
    pub lease_duration: Duration,
}

pub(crate) struct ClientConfig {
    pub timeout: Duration,
    pub max_retries: u32,
    pub initial_retry_delay: Duration,
    pub wrap_ttl: Option<String>,
    pub forward_to_leader: bool,
    pub retry_on_sealed: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(60),
            max_retries: 2,
            initial_retry_delay: Duration::from_millis(500),
            wrap_ttl: None,
            forward_to_leader: false,
            retry_on_sealed: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for configuring and constructing a [`VaultClient`]
#[derive(Default)]
#[must_use]
pub struct ClientBuilder {
    address: Option<String>,
    token: Option<SecretString>,
    namespace: Option<String>,
    timeout: Option<Duration>,
    max_retries: Option<u32>,
    initial_retry_delay: Option<Duration>,
    wrap_ttl: Option<String>,
    forward_to_leader: bool,
    danger_disable_tls_verify: bool,
    ca_cert_pem: Option<Vec<u8>>,
    client_cert_pem: Option<Vec<u8>>,
    client_key_pem: Option<Zeroizing<Vec<u8>>>,
    reqwest_client: Option<Client>,
    auth_method: Option<Arc<dyn AuthMethodDyn>>,
    circuit_breaker: Option<CircuitBreakerConfig>,
    on_token_changed: Option<TokenChangedCallback>,
    /// When true: max_retries=0 and Sealed is not retried
    cli_mode: bool,
}

impl ClientBuilder {
    /// Pre-populate the builder from `VAULT_*` environment variables;
    /// token resolution order: `VAULT_TOKEN` → `~/.vault-token` → `None`
    pub fn from_env() -> Self {
        let cli_mode = std::env::var("VAULT_CLI_MODE")
            .ok()
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));

        let skip_tls = std::env::var("VAULT_SKIP_VERIFY")
            .ok()
            .or_else(|| {
                let v = std::env::var("VAULT_SKIP_TLS_VERIFY").ok();
                if v.is_some() {
                    tracing::warn!("VAULT_SKIP_TLS_VERIFY is non-standard; use VAULT_SKIP_VERIFY");
                }
                v
            })
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));

        Self {
            address: std::env::var("VAULT_ADDR").ok(),
            token: std::env::var("VAULT_TOKEN")
                .ok()
                .map(SecretString::from)
                .or_else(read_vault_token_file),
            namespace: std::env::var("VAULT_NAMESPACE").ok(),
            timeout: std::env::var("VAULT_CLIENT_TIMEOUT")
                .ok()
                .and_then(|v| v.parse().ok())
                .map(Duration::from_secs),
            max_retries: if cli_mode {
                Some(0)
            } else {
                std::env::var("VAULT_MAX_RETRIES")
                    .ok()
                    .and_then(|v| v.parse().ok())
            },
            wrap_ttl: std::env::var("VAULT_WRAP_TTL").ok(),
            danger_disable_tls_verify: skip_tls,
            ca_cert_pem: std::env::var("VAULT_CACERT")
                .ok()
                .and_then(|path| fs::read(path).ok()),
            client_cert_pem: std::env::var("VAULT_CLIENT_CERT")
                .ok()
                .and_then(|path| fs::read(path).ok()),
            client_key_pem: std::env::var("VAULT_CLIENT_KEY")
                .ok()
                .and_then(|path| fs::read(path).ok().map(Zeroizing::new)),
            cli_mode,
            ..Self::default()
        }
    }

    pub fn address(mut self, addr: &str) -> Self {
        self.address = Some(addr.to_owned());
        self
    }

    pub fn token(mut self, token: SecretString) -> Self {
        self.token = Some(token);
        self
    }

    pub fn token_str(self, token: &str) -> Self {
        self.token(SecretString::from(token))
    }

    pub fn namespace(mut self, ns: &str) -> Self {
        self.namespace = Some(ns.to_owned());
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn max_retries(mut self, n: u32) -> Self {
        self.max_retries = Some(n);
        self
    }

    pub fn initial_retry_delay(mut self, d: Duration) -> Self {
        self.initial_retry_delay = Some(d);
        self
    }

    pub fn wrap_ttl(mut self, ttl: &str) -> Self {
        self.wrap_ttl = Some(ttl.to_owned());
        self
    }

    pub fn forward_to_leader(mut self, yes: bool) -> Self {
        self.forward_to_leader = yes;
        self
    }

    /// Optimise for short-lived CLI invocations
    ///
    /// Sets `max_retries(0)` and disables sealed-Vault retries —
    /// a sealed Vault will not unseal itself between invocations —
    /// equivalent to `VAULT_CLI_MODE=1` in `from_env()`
    pub fn cli_mode(mut self, yes: bool) -> Self {
        if yes {
            self.max_retries = Some(0);
        }
        self.cli_mode = yes;
        self
    }

    pub fn danger_disable_tls_verify(mut self, yes: bool) -> Self {
        self.danger_disable_tls_verify = yes;
        self
    }

    pub fn ca_cert_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.ca_cert_pem = Some(pem.into());
        self
    }

    pub fn client_cert_pem(mut self, cert: impl Into<Vec<u8>>, key: impl Into<Vec<u8>>) -> Self {
        self.client_cert_pem = Some(cert.into());
        self.client_key_pem = Some(Zeroizing::new(key.into()));
        self
    }

    /// Set an authentication method for automatic token lifecycle management
    ///
    /// When set, the client will automatically re-authenticate when the token
    /// nears expiry or is missing
    pub fn auth_method(mut self, method: impl AuthMethod + 'static) -> Self {
        self.auth_method = Some(Arc::new(method));
        self
    }

    /// Enable the circuit breaker with the given configuration
    ///
    /// When enabled, consecutive failures will trip the circuit and
    /// short-circuit subsequent requests until the reset timeout elapses
    pub fn circuit_breaker(mut self, config: CircuitBreakerConfig) -> Self {
        self.circuit_breaker = Some(config);
        self
    }

    /// Register a callback invoked whenever the client's token changes
    /// via renewal or re-authentication
    pub fn on_token_changed(mut self, f: impl Fn(&AuthInfo) + Send + Sync + 'static) -> Self {
        self.on_token_changed = Some(Arc::new(f));
        self
    }

    pub fn with_reqwest_client(mut self, client: Client) -> Self {
        self.reqwest_client = Some(client);
        self
    }

    pub fn build(self) -> Result<VaultClient, VaultError> {
        let addr = self
            .address
            .ok_or_else(|| VaultError::Config("address is required".into()))?;
        let mut base_url =
            Url::parse(&addr).map_err(|e| VaultError::Config(format!("invalid address: {e}")))?;
        // Ensure trailing slash so path joins work correctly
        if !base_url.path().ends_with('/') {
            base_url.set_path(&format!("{}/", base_url.path()));
        }

        let config = ClientConfig {
            timeout: self.timeout.unwrap_or(Duration::from_secs(60)),
            max_retries: self.max_retries.unwrap_or(2),
            initial_retry_delay: self
                .initial_retry_delay
                .unwrap_or(Duration::from_millis(500)),
            wrap_ttl: self.wrap_ttl,
            forward_to_leader: self.forward_to_leader,
            retry_on_sealed: !self.cli_mode,
        };

        // Build the HTTP client. We must do this after constructing config
        // (for timeout) but handle the partial-move by matching reqwest_client
        // separately: in the None arm we still need &self for TLS fields.
        let http = if let Some(c) = self.reqwest_client {
            c
        } else {
            build_reqwest_client(
                &config,
                self.danger_disable_tls_verify,
                self.ca_cert_pem.as_deref(),
                self.client_cert_pem.as_deref(),
                self.client_key_pem.as_ref().map(|k| k.as_slice()),
            )?
        };

        let token_state = self.token.map(|t| TokenState {
            value: t,
            expires_at: None,
            renewable: false,
            lease_duration: Duration::ZERO,
        });

        if self.danger_disable_tls_verify {
            tracing::warn!(
                vault_address = %base_url,
                "TLS certificate verification is DISABLED (danger_disable_tls_verify). \
                 This must not be used in production."
            );
        }

        Ok(VaultClient {
            inner: Arc::new(VaultClientInner {
                http,
                base_url,
                token: RwLock::new(token_state),
                namespace: self.namespace,
                config,
                auth_method: self.auth_method,
                circuit_breaker: self.circuit_breaker.map(CircuitBreaker::new),
                on_token_changed: self.on_token_changed,
                renewal_lock: tokio::sync::Mutex::new(()),
            }),
            namespace_override: None,
            wrap_ttl_override: None,
        })
    }
}

fn build_reqwest_client(
    config: &ClientConfig,
    danger_disable_tls_verify: bool,
    ca_cert_pem: Option<&[u8]>,
    client_cert_pem: Option<&[u8]>,
    client_key_pem: Option<&[u8]>,
) -> Result<Client, VaultError> {
    let mut builder = Client::builder()
        .timeout(config.timeout)
        .danger_accept_invalid_certs(danger_disable_tls_verify);

    if let Some(ca_pem) = ca_cert_pem {
        let cert = reqwest::tls::Certificate::from_pem(ca_pem)
            .map_err(|e| VaultError::Config(format!("CA cert: {e}")))?;
        builder = builder.add_root_certificate(cert);
    }

    if let (Some(cert_pem), Some(key_pem)) = (client_cert_pem, client_key_pem) {
        let mut combined = Zeroizing::new(Vec::with_capacity(cert_pem.len() + key_pem.len()));
        combined.extend_from_slice(cert_pem);
        combined.extend_from_slice(key_pem);
        let identity = reqwest::tls::Identity::from_pem(&combined)
            .map_err(|e| VaultError::Config(format!("TLS identity: {e}")))?;
        drop(combined); // zeroize on drop
        builder = builder.identity(identity);
    }

    builder
        .build()
        .map_err(|e| VaultError::Config(format!("reqwest client: {e}")))
}

// ---------------------------------------------------------------------------
// Handler accessors
// ---------------------------------------------------------------------------

impl VaultClient {
    /// Create a client with an address and plaintext token
    ///
    /// For more options, use [`VaultClient::builder()`]
    pub fn new(address: &str, token: &str) -> Result<Self, VaultError> {
        Self::builder().address(address).token_str(token).build()
    }

    /// Create a client from `VAULT_*` environment variables;
    /// token resolution order: `VAULT_TOKEN` → `~/.vault-token` → `None`
    pub fn from_env() -> Result<Self, VaultError> {
        ClientBuilder::from_env().build()
    }

    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    #[must_use]
    pub fn cubbyhole(&self, mount: &str) -> api::cubbyhole::CubbyholeHandler<'_> {
        api::cubbyhole::CubbyholeHandler {
            client: self,
            mount: encode_path(mount),
        }
    }

    #[must_use]
    pub fn kv1(&self, mount: &str) -> api::kv1::Kv1Handler<'_> {
        api::kv1::Kv1Handler {
            client: self,
            mount: encode_path(mount),
        }
    }

    #[must_use]
    pub fn kv2(&self, mount: &str) -> api::kv2::Kv2Handler<'_> {
        api::kv2::Kv2Handler {
            client: self,
            mount: encode_path(mount),
        }
    }

    #[must_use]
    pub fn transit(&self, mount: &str) -> api::transit::TransitHandler<'_> {
        api::transit::TransitHandler {
            client: self,
            mount: encode_path(mount),
        }
    }

    #[must_use]
    pub fn pki(&self, mount: &str) -> api::pki::PkiHandler<'_> {
        api::pki::PkiHandler {
            client: self,
            mount: encode_path(mount),
        }
    }

    #[must_use]
    pub fn database(&self, mount: &str) -> api::database::DatabaseHandler<'_> {
        api::database::DatabaseHandler {
            client: self,
            mount: encode_path(mount),
        }
    }

    #[must_use]
    pub fn ssh(&self, mount: &str) -> api::ssh::SshHandler<'_> {
        api::ssh::SshHandler {
            client: self,
            mount: encode_path(mount),
        }
    }

    #[must_use]
    pub fn aws_secrets(&self, mount: &str) -> api::aws::AwsSecretsHandler<'_> {
        api::aws::AwsSecretsHandler {
            client: self,
            mount: encode_path(mount),
        }
    }

    #[must_use]
    pub fn totp(&self, mount: &str) -> api::totp::TotpHandler<'_> {
        api::totp::TotpHandler {
            client: self,
            mount: encode_path(mount),
        }
    }

    #[must_use]
    pub fn consul_secrets(&self, mount: &str) -> api::consul::ConsulHandler<'_> {
        api::consul::ConsulHandler {
            client: self,
            mount: encode_path(mount),
        }
    }

    #[must_use]
    pub fn nomad_secrets(&self, mount: &str) -> api::nomad::NomadHandler<'_> {
        api::nomad::NomadHandler {
            client: self,
            mount: encode_path(mount),
        }
    }

    #[must_use]
    pub fn azure_secrets(&self, mount: &str) -> api::azure::AzureHandler<'_> {
        api::azure::AzureHandler {
            client: self,
            mount: encode_path(mount),
        }
    }

    #[must_use]
    pub fn gcp_secrets(&self, mount: &str) -> api::gcp::GcpHandler<'_> {
        api::gcp::GcpHandler {
            client: self,
            mount: encode_path(mount),
        }
    }

    #[must_use]
    pub fn rabbitmq(&self, mount: &str) -> api::rabbitmq::RabbitmqHandler<'_> {
        api::rabbitmq::RabbitmqHandler {
            client: self,
            mount: encode_path(mount),
        }
    }

    #[must_use]
    pub fn terraform_cloud(&self, mount: &str) -> api::terraform::TerraformCloudHandler<'_> {
        api::terraform::TerraformCloudHandler {
            client: self,
            mount: encode_path(mount),
        }
    }

    #[must_use]
    pub fn identity(&self) -> api::identity::IdentityHandler<'_> {
        api::identity::IdentityHandler { client: self }
    }

    #[must_use]
    pub fn sys(&self) -> api::sys::SysHandler<'_> {
        api::sys::SysHandler { client: self }
    }

    #[must_use]
    pub fn auth(&self) -> api::auth::AuthHandler<'_> {
        api::auth::AuthHandler { client: self }
    }

    /// Replace the current token at runtime
    pub fn set_token(&self, token: SecretString) -> Result<(), VaultError> {
        let mut guard = self
            .inner
            .token
            .write()
            .map_err(|_| VaultError::LockPoisoned)?;
        *guard = Some(TokenState {
            value: token,
            expires_at: None,
            renewable: false,
            lease_duration: Duration::ZERO,
        });
        Ok(())
    }

    /// Return a client view with a different namespace (cheap Arc clone)
    #[must_use]
    pub fn with_namespace(&self, ns: &str) -> Self {
        VaultClient {
            inner: Arc::clone(&self.inner),
            namespace_override: Some(ns.to_owned()),
            wrap_ttl_override: self.wrap_ttl_override.clone(),
        }
    }

    /// Return a client view with a different wrap TTL (cheap Arc clone)
    #[must_use]
    pub fn with_wrap_ttl(&self, ttl: &str) -> Self {
        VaultClient {
            inner: Arc::clone(&self.inner),
            namespace_override: self.namespace_override.clone(),
            wrap_ttl_override: Some(ttl.to_owned()),
        }
    }

    /// Update internal token state from an auth response
    pub(crate) fn update_token_from_auth(&self, auth: &AuthInfo) -> Result<(), VaultError> {
        let mut guard = self
            .inner
            .token
            .write()
            .map_err(|_| VaultError::LockPoisoned)?;
        *guard = Some(TokenState {
            value: auth.client_token.clone(),
            lease_duration: Duration::from_secs(auth.lease_duration),
            expires_at: if auth.lease_duration > 0 {
                Instant::now().checked_add(Duration::from_secs(auth.lease_duration))
            } else {
                None
            },
            renewable: auth.renewable,
        });
        drop(guard);

        if let Some(cb) = &self.inner.on_token_changed {
            cb(auth);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Generic escape hatch
// ---------------------------------------------------------------------------

impl VaultClient {
    /// Read from an arbitrary Vault path, deserializing the `data` field
    pub async fn read<T: DeserializeOwned>(&self, path: &str) -> Result<T, VaultError> {
        self.exec_with_data(Method::GET, path, None).await
    }

    /// Read from an arbitrary path, returning the full Vault response envelope
    pub async fn read_raw(
        &self,
        path: &str,
    ) -> Result<VaultResponse<serde_json::Value>, VaultError> {
        self.exec_with_auth(Method::GET, path, None).await
    }

    /// Write to an arbitrary Vault path
    pub async fn write<T: DeserializeOwned>(
        &self,
        path: &str,
        data: &impl Serialize,
    ) -> Result<VaultResponse<T>, VaultError> {
        let body = to_body(data)?;
        self.exec_with_auth(Method::POST, path, Some(&body)).await
    }

    /// Delete at an arbitrary Vault path
    pub async fn delete(&self, path: &str) -> Result<(), VaultError> {
        self.exec_empty(Method::DELETE, path, None).await
    }

    /// List keys at an arbitrary Vault path
    pub async fn list(&self, path: &str) -> Result<Vec<String>, VaultError> {
        self.exec_list(path).await
    }
}

// ---------------------------------------------------------------------------
// Request execution
// ---------------------------------------------------------------------------

impl VaultClient {
    pub(crate) async fn exec_with_data<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<T, VaultError> {
        let resp = self.execute(method, path, body).await?;
        if resp.status().as_u16() == 404 {
            return Err(VaultError::NotFound {
                path: path.to_owned(),
            });
        }
        let envelope: VaultResponse<T> = resp.json().await?;
        self.log_warnings(&envelope.warnings);
        envelope.data.ok_or(VaultError::EmptyResponse)
    }

    pub(crate) async fn exec_with_auth<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<VaultResponse<T>, VaultError> {
        let resp = self.execute(method, path, body).await?;
        if resp.status().as_u16() == 404 {
            return Err(VaultError::NotFound {
                path: path.to_owned(),
            });
        }
        let envelope: VaultResponse<T> = resp.json().await?;
        self.log_warnings(&envelope.warnings);
        Ok(envelope)
    }

    pub(crate) async fn exec_empty(
        &self,
        method: Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<(), VaultError> {
        let resp = self.execute(method, path, body).await?;
        if resp.status().as_u16() == 404 {
            return Err(VaultError::NotFound {
                path: path.to_owned(),
            });
        }
        Ok(())
    }

    /// Deserialize response body directly (that is, not through the Vault envelope)
    ///
    /// Used for endpoints like /sys/health that return flat JSON
    pub(crate) async fn exec_direct<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<T, VaultError> {
        let resp = self.execute(method, path, body).await?;
        Ok(resp.json().await?)
    }

    pub(crate) async fn exec_list(&self, path: &str) -> Result<Vec<String>, VaultError> {
        let resp = self.execute(METHOD_LIST.clone(), path, None).await?;
        if resp.status().as_u16() == 404 {
            return Ok(vec![]);
        }
        let envelope: VaultResponse<ListResponse> = resp.json().await?;
        Ok(envelope.data.map(|d| d.keys).unwrap_or_default())
    }

    pub(crate) async fn exec_patch<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<T, VaultError> {
        let resp = self.execute(Method::PATCH, path, Some(body)).await?;
        if resp.status().as_u16() == 404 {
            return Err(VaultError::NotFound {
                path: path.to_owned(),
            });
        }
        let envelope: VaultResponse<T> = resp.json().await?;
        self.log_warnings(&envelope.warnings);
        envelope.data.ok_or(VaultError::EmptyResponse)
    }

    fn token_needs_renewal(ts: &TokenState) -> bool {
        match ts.expires_at {
            Some(expires) => {
                let threshold = ts.lease_duration.mul_f64(0.2);
                Instant::now() + threshold >= expires
            }
            None => false, // root token or no expiry
        }
    }

    /// Proactively renew or re-authenticate before the token expires
    ///
    /// Renewal is serialized via `renewal_lock` and double-checked after acquiring
    /// it, so concurrent callers near expiry share a single renew-self call instead
    /// of each firing their own
    async fn ensure_valid_token(&self) -> Result<(), VaultError> {
        enum Action {
            Ok,
            ReAuth,
            Renew,
        }

        let action = {
            let guard = self
                .inner
                .token
                .read()
                .map_err(|_| VaultError::LockPoisoned)?;
            match guard.as_ref() {
                Some(ts) if !Self::token_needs_renewal(ts) => Action::Ok,
                Some(ts) if ts.renewable => Action::Renew,
                _ if self.inner.auth_method.is_some() => Action::ReAuth,
                // No token and no auth method: let the request through.
                _ => Action::Ok,
            }
        }; // guard dropped

        match action {
            Action::Ok => Ok(()),
            Action::ReAuth => self.try_re_authenticate().await,
            Action::Renew => {
                // Serialize renewals across concurrent callers so only one in-flight
                // renew-self call happens near expiry, instead of a thundering herd
                let _renewal_guard = self.inner.renewal_lock.lock().await;

                // Re-check now that we hold the renewal lock: another caller may have
                // already renewed the token while we were waiting for it
                let still_needed = {
                    let guard = self
                        .inner
                        .token
                        .read()
                        .map_err(|_| VaultError::LockPoisoned)?;
                    guard.as_ref().is_some_and(Self::token_needs_renewal)
                }; // read lock dropped

                if !still_needed {
                    return Ok(());
                }

                match self.renew_token_via_api().await {
                    Ok(()) => Ok(()),
                    Err(renew_err) if self.inner.auth_method.is_some() => {
                        tracing::warn!(
                            error = %renew_err,
                            "proactive token renewal failed, falling back to re-authentication"
                        );
                        self.try_re_authenticate().await
                    }
                    Err(renew_err) => Err(renew_err),
                }
            }
        }
    }

    /// Attempt re-authentication using the configured auth method
    pub(crate) async fn try_re_authenticate(&self) -> Result<(), VaultError> {
        match &self.inner.auth_method {
            Some(method) => {
                let auth = method.login_dyn(self).await?;
                self.update_token_from_auth(&auth)?;
                Ok(())
            }
            None => Err(VaultError::AuthRequired),
        }
    }

    /// Renew the client token directly via `auth/token/renew-self`, updating
    /// internal token state from the response
    ///
    /// Uses `execute_raw` to bypass `ensure_valid_token` and avoid recursion
    pub(crate) async fn renew_token_via_api(&self) -> Result<(), VaultError> {
        let raw_resp = self
            .execute_raw(Method::POST, "auth/token/renew-self", None)
            .await?;
        let resp: VaultResponse<serde_json::Value> = raw_resp.json().await?;
        if let Some(auth) = resp.auth {
            self.update_token_from_auth(&auth)?;
        }
        Ok(())
    }

    pub(crate) async fn execute(
        &self,
        method: Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<Response, VaultError> {
        // Skip token lifecycle only for login endpoints to avoid infinite
        // recursion (the call chain is: `try_re_authenticate` => `login_dyn` => `execute` => `ensure_valid_token`)
        let is_login = path.starts_with("auth/") && path.contains("/login");
        if !is_login {
            self.ensure_valid_token().await?;
        }
        self.execute_raw(method, path, body).await
    }

    /// Low-level execute that bypasses token lifecycle, used internally by
    /// `ensure_valid_token` to avoid recursion
    pub(crate) async fn execute_raw(
        &self,
        method: Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<Response, VaultError> {
        let span = tracing::info_span!(
            "vault.request",
            http.method = %method,
            vault.path = %path,
            http.status_code = tracing::field::Empty,
        );

        async {
            if let Some(cb) = &self.inner.circuit_breaker {
                cb.check()?;
            }

            let url_str = format!("{}v1/{}", self.inner.base_url, path.trim_start_matches('/'));
            let url = Url::parse(&url_str)?;

            let mut req = self
                .inner
                .http
                .request(method.clone(), url.clone())
                .header("X-Vault-Request", "true");

            if method == Method::PATCH {
                req = req.header("Content-Type", "application/merge-patch+json");
            }

            req = self.inject_headers(req)?;

            if let Some(body) = body {
                req = req.json(body);
            }

            match self.send_with_retry(req, &url, &method).await {
                Ok(resp) => {
                    if let Some(cb) = &self.inner.circuit_breaker {
                        cb.record_success();
                    }
                    tracing::Span::current().record("http.status_code", resp.status().as_u16());
                    tracing::debug!(status = resp.status().as_u16(), "vault response");
                    Ok(resp)
                }
                Err(e) => {
                    if let Some(cb) = &self.inner.circuit_breaker {
                        cb.record_failure();
                    }
                    Err(e)
                }
            }
        }
        .instrument(span)
        .await
    }

    pub(crate) fn inject_headers(
        &self,
        mut req: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, VaultError> {
        let guard = self
            .inner
            .token
            .read()
            .map_err(|_| VaultError::LockPoisoned)?;
        if let Some(ts) = guard.as_ref() {
            req = req.header("X-Vault-Token", ts.value.expose_secret());
        }
        drop(guard);

        let ns = self
            .namespace_override
            .as_deref()
            .or(self.inner.namespace.as_deref());
        if let Some(ns) = ns {
            req = req.header("X-Vault-Namespace", ns);
        }
        let ttl = self
            .wrap_ttl_override
            .as_deref()
            .or(self.inner.config.wrap_ttl.as_deref());
        if let Some(ttl) = ttl {
            req = req.header("X-Vault-Wrap-TTL", ttl);
        }
        if self.inner.config.forward_to_leader {
            req = req.header("X-Vault-Forward", "active-node");
        }
        Ok(req)
    }

    async fn send_with_retry(
        &self,
        builder: reqwest::RequestBuilder,
        url: &Url,
        method: &Method,
    ) -> Result<Response, VaultError> {
        let max = self.inner.config.max_retries;
        let mut skip_backoff = false;

        for attempt in 0..=max {
            if attempt > 0 && !skip_backoff {
                let base = self
                    .inner
                    .config
                    .initial_retry_delay
                    .checked_mul(2u32.saturating_pow(attempt - 1))
                    .unwrap_or(MAX_BACKOFF);
                let capped = base.min(MAX_BACKOFF);
                let capped_ms = u64::try_from(capped.as_millis()).unwrap_or(u64::MAX).max(1);
                let delay = Duration::from_millis(rand::rng().random_range(0u64..capped_ms));
                tracing::warn!(attempt, max, %url, %method, ?delay, "retrying");
                tokio::time::sleep(delay).await;
            }
            skip_backoff = false;

            let req = match builder.try_clone() {
                Some(r) => r,
                None => {
                    return Err(VaultError::Config(
                        "request body not cloneable (stream body?)".into(),
                    ));
                }
            };

            match req.send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    match status {
                        200..=299 | 404 => return Ok(resp),
                        401 => {
                            return Err(VaultError::AuthRequired);
                        }
                        403 => {
                            let errors = Self::extract_errors(resp).await;
                            return Err(VaultError::PermissionDenied { errors });
                        }
                        429 => {
                            let retry_after = resp
                                .headers()
                                .get("Retry-After")
                                .and_then(|v| v.to_str().ok())
                                .and_then(|v| v.parse::<u64>().ok());
                            if attempt >= max {
                                return Err(VaultError::RateLimited { retry_after });
                            }
                            if let Some(secs) = retry_after {
                                let capped = Duration::from_secs(secs).min(MAX_BACKOFF);
                                tokio::time::sleep(capped).await;
                                skip_backoff = true;
                            }
                            continue;
                        }
                        412 => {
                            if attempt >= max {
                                return Err(VaultError::ConsistencyRetry);
                            }
                            continue;
                        }
                        503 => {
                            let e = VaultError::Sealed {
                                url: url.to_string(),
                            };
                            if attempt >= max || !self.inner.config.retry_on_sealed {
                                return Err(e);
                            }
                            continue;
                        }
                        _ => {
                            let errors = Self::extract_errors(resp).await;
                            let err = VaultError::Api { status, errors };
                            if err.is_retryable() && attempt < max {
                                continue;
                            }
                            return Err(err);
                        }
                    }
                }
                Err(e) if (e.is_timeout() || e.is_connect()) && attempt < max => {
                    continue;
                }
                Err(e) => return Err(VaultError::Http(e)),
            }
        }

        unreachable!("retry loop always returns from within")
    }

    pub(crate) async fn extract_errors(resp: Response) -> Vec<String> {
        let body = resp.text().await.unwrap_or_default();
        serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("errors")?.as_array().cloned())
            .map(|arr| {
                arr.into_iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_else(|| if body.is_empty() { vec![] } else { vec![body] })
    }

    fn log_warnings(&self, warnings: &Option<Vec<String>>) {
        if let Some(warns) = warnings {
            for w in warns {
                tracing::debug!(warning = %w, "vault response warning");
            }
        }
    }
}

/// Serialize a value to `serde_json::Value`, mapping errors to `VaultError::Config`
pub(crate) fn to_body(value: &impl Serialize) -> Result<serde_json::Value, VaultError> {
    serde_json::to_value(value).map_err(|e| VaultError::Config(format!("serialize: {e}")))
}

/// Read `~/.vault-token`, mirroring the Vault CLI token helper
///
/// Returns `None` on any I/O error or empty file. Trims trailing whitespace —
/// `vault login` writes a trailing newline
fn read_vault_token_file() -> Option<SecretString> {
    let path = home::home_dir()?.join(".vault-token");
    let raw = fs::read_to_string(path).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(SecretString::from(trimmed))
    }
}

/// Percent-encode characters in a path segment that would cause URL parsing issues
///
/// Preserves `/` as path separators; encodes `?`, `#`, `%`, spaces, and control chars
pub fn encode_path(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for &byte in raw.as_bytes() {
        match byte {
            b'?' | b'#' | b'%' | b' ' | b'[' | b']' | 0..=0x1F | 0x7F | 0x80..=0xFF => {
                write!(out, "%{byte:02X}").unwrap();
            }
            _ => out.push(byte as char),
        }
    }
    out
}
