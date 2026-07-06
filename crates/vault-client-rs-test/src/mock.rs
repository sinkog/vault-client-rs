//! Driver-level (trait) mocks for `vault-client-rs`.
//!
//! Unlike the WireMock helpers in the crate root — which mock Vault at the
//! **HTTP** layer — these types implement the driver's operation traits
//! directly, so code generic over `Kv2Operations` / `CertAuthOperations` can be
//! unit-tested with programmable, deterministic responses and no network.
//!
//! Each mock records the paths/roles it is asked for (see `calls`), returns a
//! programmed success or a programmed [`VaultError`], and — for the many
//! operations a given test does not exercise — `unimplemented!()`s, the standard
//! test-double behaviour for an unexpected call. Program only what the code
//! under test touches.
//!
//! `Transit`/`Pki` mocks follow the same template and are added when the
//! signing-key custody slice exercises them.

use std::collections::HashMap;
use std::sync::Mutex;

use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use vault_client_rs::{
    AuthInfo, CertAuthOperations, CertRoleInfo, CertRoleRequest, Kv2Operations, KvConfig,
    KvFullMetadata, KvMetadata, KvMetadataParams, KvReadResponse, PkiAcmeConfig, PkiCertificate,
    PkiCertificateEntry, PkiCrossSignRequest, PkiCsr, PkiImportResult, PkiIntermediateParams,
    PkiIssueParams, PkiIssuedCert, PkiIssuerInfo, PkiIssuerUpdateParams, PkiOperations,
    PkiRevocationInfo, PkiRole, PkiRoleParams, PkiRootParams, PkiSignParams, PkiSignedCert,
    PkiTidyParams, PkiTidyStatus, PkiUrlsConfig, SecretString, VaultError,
};

/// A programmable error a mock can inject.
///
/// [`VaultError`] is not `Clone` (it wraps `reqwest`/`serde_json` errors), so a
/// mock stores this lightweight descriptor and constructs the real error on
/// demand — covering the variants the adapter layer actually classifies.
#[derive(Clone, Debug)]
pub enum MockError {
    /// Maps to [`VaultError::NotFound`].
    NotFound,
    /// Maps to [`VaultError::PermissionDenied`].
    Denied,
    /// Maps to [`VaultError::AuthRequired`].
    AuthRequired,
    /// Maps to [`VaultError::Api`] with the given status and messages.
    Api {
        /// HTTP status the fake backend "returned".
        status: u16,
        /// Vault error strings.
        errors: Vec<String>,
    },
}

impl MockError {
    fn to_vault(&self, path: &str) -> VaultError {
        match self {
            Self::NotFound => VaultError::NotFound {
                path: path.to_owned(),
            },
            Self::Denied => VaultError::PermissionDenied {
                errors: vec!["permission denied".to_owned()],
            },
            Self::AuthRequired => VaultError::AuthRequired,
            Self::Api { status, errors } => VaultError::Api {
                status: *status,
                errors: errors.clone(),
            },
        }
    }
}

/// Builds a minimal [`AuthInfo`]-shaped JSON value for programming
/// [`MockCertAuth`] logins. Only the fields the adapter projects are meaningful;
/// the rest carry innocuous defaults.
#[must_use]
pub fn auth_info(
    token: &str,
    accessor: &str,
    policies: &[&str],
    lease: u64,
    renewable: bool,
) -> Value {
    json!({
        "client_token": token,
        "accessor": accessor,
        "policies": policies,
        "token_policies": policies,
        "lease_duration": lease,
        "renewable": renewable,
        "entity_id": "",
        "token_type": "service",
    })
}

// ---------------------------------------------------------------------------
// MockKv2
// ---------------------------------------------------------------------------

/// A programmable [`Kv2Operations`] double.
///
/// Program the *data object* stored at a path with [`MockKv2::with_data`] (the
/// value the KV v2 secret holds), or an error with [`MockKv2::with_error`].
/// `read`/`read_data`/`read_version` and the inherent [`MockKv2::read_field`]
/// resolve against that map; unprogrammed paths report [`VaultError::NotFound`].
#[derive(Default)]
pub struct MockKv2 {
    responses: HashMap<String, Result<Value, MockError>>,
    calls: Mutex<Vec<String>>,
}

impl MockKv2 {
    /// An empty mock — every read reports not-found until programmed.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Programs the data object returned for `path`.
    #[must_use]
    pub fn with_data(mut self, path: &str, data: Value) -> Self {
        self.responses.insert(path.to_owned(), Ok(data));
        self
    }

    /// Programs an error for `path`.
    #[must_use]
    pub fn with_error(mut self, path: &str, err: MockError) -> Self {
        self.responses.insert(path.to_owned(), Err(err));
        self
    }

    /// The paths this mock was asked to read, in call order.
    #[must_use]
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("mock lock poisoned").clone()
    }

    fn lookup(&self, path: &str) -> Result<Value, VaultError> {
        self.calls
            .lock()
            .expect("mock lock poisoned")
            .push(path.to_owned());
        match self.responses.get(path) {
            Some(Ok(v)) => Ok(v.clone()),
            Some(Err(e)) => Err(e.to_vault(path)),
            None => Err(VaultError::NotFound {
                path: path.to_owned(),
            }),
        }
    }

    /// Reads a single string `field` from the data at `path`, mirroring the real
    /// `Kv2Handler::read_field` (an inherent convenience, not part of the trait).
    ///
    /// # Errors
    /// [`VaultError::NotFound`] / the programmed error for `path`, or
    /// [`VaultError::FieldNotFound`] if the field is absent or not a string.
    pub async fn read_field(&self, path: &str, field: &str) -> Result<String, VaultError> {
        let data = self.lookup(path)?;
        data.get(field)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| VaultError::FieldNotFound {
                mount: String::new(),
                path: path.to_owned(),
                field: field.to_owned(),
            })
    }
}

/// A [`KvMetadata`]-shaped JSON value. `KvMetadata` and `KvReadResponse` are
/// `#[non_exhaustive]` with no constructor, so the mock builds them by
/// deserializing rather than with a struct literal.
fn mock_metadata_json() -> Value {
    json!({
        "created_time": "",
        "custom_metadata": null,
        "deletion_time": "",
        "destroyed": false,
        "version": 1,
    })
}

impl Kv2Operations for MockKv2 {
    async fn read<T: DeserializeOwned + Send>(
        &self,
        path: &str,
    ) -> Result<KvReadResponse<T>, VaultError> {
        let data = self.lookup(path)?;
        let envelope = json!({ "data": data, "metadata": mock_metadata_json() });
        serde_json::from_value(envelope).map_err(VaultError::Deserialize)
    }

    async fn read_data<T: DeserializeOwned + Send>(&self, path: &str) -> Result<T, VaultError> {
        let data = self.lookup(path)?;
        serde_json::from_value(data).map_err(VaultError::Deserialize)
    }

    async fn read_version<T: DeserializeOwned + Send>(
        &self,
        path: &str,
        _version: u64,
    ) -> Result<KvReadResponse<T>, VaultError> {
        self.read(path).await
    }

    async fn read_config(&self) -> Result<KvConfig, VaultError> {
        unimplemented!("MockKv2::read_config not programmed")
    }

    async fn write_config(&self, _cfg: &KvConfig) -> Result<(), VaultError> {
        unimplemented!("MockKv2::write_config not programmed")
    }

    async fn write(&self, _path: &str, _data: &Value) -> Result<KvMetadata, VaultError> {
        unimplemented!("MockKv2::write not programmed")
    }

    async fn write_cas(
        &self,
        _path: &str,
        _data: &Value,
        _cas: u64,
    ) -> Result<KvMetadata, VaultError> {
        unimplemented!("MockKv2::write_cas not programmed")
    }

    async fn patch(&self, _path: &str, _data: &Value) -> Result<KvMetadata, VaultError> {
        unimplemented!("MockKv2::patch not programmed")
    }

    async fn list(&self, _path: &str) -> Result<Vec<String>, VaultError> {
        unimplemented!("MockKv2::list not programmed")
    }

    async fn delete(&self, _path: &str) -> Result<(), VaultError> {
        unimplemented!("MockKv2::delete not programmed")
    }

    async fn delete_versions(&self, _path: &str, _versions: &[u64]) -> Result<(), VaultError> {
        unimplemented!("MockKv2::delete_versions not programmed")
    }

    async fn undelete_versions(&self, _path: &str, _versions: &[u64]) -> Result<(), VaultError> {
        unimplemented!("MockKv2::undelete_versions not programmed")
    }

    async fn destroy_versions(&self, _path: &str, _versions: &[u64]) -> Result<(), VaultError> {
        unimplemented!("MockKv2::destroy_versions not programmed")
    }

    async fn read_metadata(&self, _path: &str) -> Result<KvFullMetadata, VaultError> {
        unimplemented!("MockKv2::read_metadata not programmed")
    }

    async fn write_metadata(
        &self,
        _path: &str,
        _meta: &KvMetadataParams,
    ) -> Result<(), VaultError> {
        unimplemented!("MockKv2::write_metadata not programmed")
    }

    async fn patch_metadata(
        &self,
        _path: &str,
        _meta: &KvMetadataParams,
    ) -> Result<(), VaultError> {
        unimplemented!("MockKv2::patch_metadata not programmed")
    }

    async fn delete_metadata(&self, _path: &str) -> Result<(), VaultError> {
        unimplemented!("MockKv2::delete_metadata not programmed")
    }

    async fn read_subkeys(&self, _path: &str, _depth: Option<u32>) -> Result<Value, VaultError> {
        unimplemented!("MockKv2::read_subkeys not programmed")
    }
}

// ---------------------------------------------------------------------------
// MockCertAuth
// ---------------------------------------------------------------------------

/// A programmable [`CertAuthOperations`] double.
///
/// Program the login outcome with [`MockCertAuth::with_login`] (an
/// [`auth_info`]-shaped value) or [`MockCertAuth::with_error`]. Role-management
/// methods are unprogrammed.
#[derive(Default)]
pub struct MockCertAuth {
    login: Option<Result<Value, MockError>>,
    calls: Mutex<Vec<Option<String>>>,
}

impl MockCertAuth {
    /// An empty mock — `login` reports [`VaultError::AuthRequired`] until programmed.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Programs a successful login returning `auth` (see [`auth_info`]).
    #[must_use]
    pub fn with_login(mut self, auth: Value) -> Self {
        self.login = Some(Ok(auth));
        self
    }

    /// Programs a login error.
    #[must_use]
    pub fn with_error(mut self, err: MockError) -> Self {
        self.login = Some(Err(err));
        self
    }

    /// The role names passed to `login`, in call order.
    #[must_use]
    pub fn calls(&self) -> Vec<Option<String>> {
        self.calls.lock().expect("mock lock poisoned").clone()
    }
}

impl CertAuthOperations for MockCertAuth {
    async fn login(&self, name: Option<&str>) -> Result<AuthInfo, VaultError> {
        self.calls
            .lock()
            .expect("mock lock poisoned")
            .push(name.map(str::to_owned));
        match &self.login {
            Some(Ok(v)) => serde_json::from_value(v.clone()).map_err(VaultError::Deserialize),
            Some(Err(e)) => Err(e.to_vault("auth/cert/login")),
            None => Err(VaultError::AuthRequired),
        }
    }

    async fn create_role(&self, _name: &str, _params: &CertRoleRequest) -> Result<(), VaultError> {
        unimplemented!("MockCertAuth::create_role not programmed")
    }

    async fn read_role(&self, _name: &str) -> Result<CertRoleInfo, VaultError> {
        unimplemented!("MockCertAuth::read_role not programmed")
    }

    async fn delete_role(&self, _name: &str) -> Result<(), VaultError> {
        unimplemented!("MockCertAuth::delete_role not programmed")
    }

    async fn list_roles(&self) -> Result<Vec<String>, VaultError> {
        unimplemented!("MockCertAuth::list_roles not programmed")
    }
}

// ---------------------------------------------------------------------------
// MockPki
// ---------------------------------------------------------------------------

/// Builds a minimal [`PkiSignedCert`]-shaped JSON value for programming
/// [`MockPki::with_signed`]. `ca_chain`'s first entry is reused as `issuing_ca`.
#[must_use]
pub fn pki_signed(certificate: &str, ca_chain: &[&str]) -> Value {
    json!({
        "certificate": certificate,
        "issuing_ca": ca_chain.first().copied().unwrap_or(""),
        "ca_chain": ca_chain,
        "serial_number": "00:11:22:33",
        "expiration": 0,
    })
}

/// A programmable [`PkiOperations`] double, focused on the CA-signing path the
/// countersign flow uses.
///
/// Program the `sign_verbatim` outcome with [`MockPki::with_signed`] (a
/// [`pki_signed`] value) or [`MockPki::with_error`]. Other operations are
/// unprogrammed; `sign_verbatim` on an empty mock reports [`VaultError::Api`].
#[derive(Default)]
pub struct MockPki {
    sign_verbatim: Option<Result<Value, MockError>>,
    calls: Mutex<Vec<(String, String)>>,
}

impl MockPki {
    /// An empty mock — `sign_verbatim` errors until programmed.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Programs a successful `sign_verbatim` returning `signed` (see [`pki_signed`]).
    #[must_use]
    pub fn with_signed(mut self, signed: Value) -> Self {
        self.sign_verbatim = Some(Ok(signed));
        self
    }

    /// Programs a `sign_verbatim` error.
    #[must_use]
    pub fn with_error(mut self, err: MockError) -> Self {
        self.sign_verbatim = Some(Err(err));
        self
    }

    /// The `(role, csr)` pairs passed to `sign_verbatim`, in call order.
    #[must_use]
    pub fn calls(&self) -> Vec<(String, String)> {
        self.calls.lock().expect("mock lock poisoned").clone()
    }
}

impl PkiOperations for MockPki {
    async fn sign_verbatim(&self, role: &str, csr: &str) -> Result<PkiSignedCert, VaultError> {
        self.calls
            .lock()
            .expect("mock lock poisoned")
            .push((role.to_owned(), csr.to_owned()));
        match &self.sign_verbatim {
            Some(Ok(v)) => serde_json::from_value(v.clone()).map_err(VaultError::Deserialize),
            Some(Err(e)) => Err(e.to_vault("pki/sign-verbatim")),
            None => Err(VaultError::Api {
                status: 500,
                errors: vec!["MockPki::sign_verbatim not programmed".to_owned()],
            }),
        }
    }

    async fn generate_root(&self, _params: &PkiRootParams) -> Result<PkiCertificate, VaultError> {
        unimplemented!("MockPki::generate_root not programmed")
    }

    async fn generate_intermediate_csr(
        &self,
        _params: &PkiIntermediateParams,
    ) -> Result<PkiCsr, VaultError> {
        unimplemented!("MockPki::generate_intermediate_csr not programmed")
    }

    async fn set_signed_intermediate(
        &self,
        _certificate: &str,
    ) -> Result<PkiImportResult, VaultError> {
        unimplemented!("MockPki::set_signed_intermediate not programmed")
    }

    async fn delete_root(&self) -> Result<(), VaultError> {
        unimplemented!("MockPki::delete_root not programmed")
    }

    async fn list_issuers(&self) -> Result<Vec<String>, VaultError> {
        unimplemented!("MockPki::list_issuers not programmed")
    }

    async fn read_issuer(&self, _issuer_ref: &str) -> Result<PkiIssuerInfo, VaultError> {
        unimplemented!("MockPki::read_issuer not programmed")
    }

    async fn update_issuer(
        &self,
        _issuer_ref: &str,
        _params: &PkiIssuerUpdateParams,
    ) -> Result<PkiIssuerInfo, VaultError> {
        unimplemented!("MockPki::update_issuer not programmed")
    }

    async fn delete_issuer(&self, _issuer_ref: &str) -> Result<(), VaultError> {
        unimplemented!("MockPki::delete_issuer not programmed")
    }

    async fn create_role(&self, _name: &str, _params: &PkiRoleParams) -> Result<(), VaultError> {
        unimplemented!("MockPki::create_role not programmed")
    }

    async fn read_role(&self, _name: &str) -> Result<PkiRole, VaultError> {
        unimplemented!("MockPki::read_role not programmed")
    }

    async fn list_roles(&self) -> Result<Vec<String>, VaultError> {
        unimplemented!("MockPki::list_roles not programmed")
    }

    async fn delete_role(&self, _name: &str) -> Result<(), VaultError> {
        unimplemented!("MockPki::delete_role not programmed")
    }

    async fn issue(
        &self,
        _role: &str,
        _params: &PkiIssueParams,
    ) -> Result<PkiIssuedCert, VaultError> {
        unimplemented!("MockPki::issue not programmed")
    }

    async fn sign(
        &self,
        _role: &str,
        _params: &PkiSignParams,
    ) -> Result<PkiSignedCert, VaultError> {
        unimplemented!("MockPki::sign not programmed")
    }

    async fn list_certs(&self) -> Result<Vec<String>, VaultError> {
        unimplemented!("MockPki::list_certs not programmed")
    }

    async fn read_cert(&self, _serial: &str) -> Result<PkiCertificateEntry, VaultError> {
        unimplemented!("MockPki::read_cert not programmed")
    }

    async fn set_urls(&self, _config: &PkiUrlsConfig) -> Result<(), VaultError> {
        unimplemented!("MockPki::set_urls not programmed")
    }

    async fn read_urls(&self) -> Result<PkiUrlsConfig, VaultError> {
        unimplemented!("MockPki::read_urls not programmed")
    }

    async fn revoke(&self, _serial: &str) -> Result<PkiRevocationInfo, VaultError> {
        unimplemented!("MockPki::revoke not programmed")
    }

    async fn revoke_with_key(
        &self,
        _serial: &str,
        _private_key: &SecretString,
    ) -> Result<PkiRevocationInfo, VaultError> {
        unimplemented!("MockPki::revoke_with_key not programmed")
    }

    async fn rotate_crl(&self) -> Result<(), VaultError> {
        unimplemented!("MockPki::rotate_crl not programmed")
    }

    async fn tidy(&self, _params: &PkiTidyParams) -> Result<(), VaultError> {
        unimplemented!("MockPki::tidy not programmed")
    }

    async fn tidy_status(&self) -> Result<PkiTidyStatus, VaultError> {
        unimplemented!("MockPki::tidy_status not programmed")
    }

    async fn cross_sign_intermediate(
        &self,
        _params: &PkiCrossSignRequest,
    ) -> Result<PkiCertificate, VaultError> {
        unimplemented!("MockPki::cross_sign_intermediate not programmed")
    }

    async fn read_acme_config(&self) -> Result<PkiAcmeConfig, VaultError> {
        unimplemented!("MockPki::read_acme_config not programmed")
    }

    async fn write_acme_config(&self, _config: &PkiAcmeConfig) -> Result<(), VaultError> {
        unimplemented!("MockPki::write_acme_config not programmed")
    }

    async fn rotate_delta_crl(&self) -> Result<(), VaultError> {
        unimplemented!("MockPki::rotate_delta_crl not programmed")
    }

    async fn read_crl(&self) -> Result<Vec<u8>, VaultError> {
        unimplemented!("MockPki::read_crl not programmed")
    }

    async fn read_crl_delta(&self) -> Result<Vec<u8>, VaultError> {
        unimplemented!("MockPki::read_crl_delta not programmed")
    }
}

#[cfg(test)]
mod tests {
    use super::{MockCertAuth, MockError, MockKv2, MockPki, auth_info, pki_signed};
    use secrecy::ExposeSecret;
    use serde_json::json;
    use std::collections::HashMap;
    use std::future::Future;
    use vault_client_rs::{CertAuthOperations, Kv2Operations, PkiOperations, VaultError};

    fn block_on<F: Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(f)
    }

    #[test]
    fn kv2_read_field_returns_programmed_value() {
        let kv = MockKv2::new().with_data("db/creds", json!({ "sealed": "Y2lwaGVy" }));
        let got = block_on(kv.read_field("db/creds", "sealed")).expect("field");
        assert_eq!(got, "Y2lwaGVy");
        assert_eq!(kv.calls(), vec!["db/creds".to_owned()]);
    }

    #[test]
    fn kv2_read_field_missing_path_is_not_found() {
        let kv = MockKv2::new();
        let err = block_on(kv.read_field("nope", "sealed")).unwrap_err();
        assert!(matches!(err, VaultError::NotFound { .. }));
    }

    #[test]
    fn kv2_read_field_absent_field_is_field_not_found() {
        let kv = MockKv2::new().with_data("db/creds", json!({ "other": "x" }));
        let err = block_on(kv.read_field("db/creds", "sealed")).unwrap_err();
        assert!(matches!(err, VaultError::FieldNotFound { .. }));
    }

    #[test]
    fn kv2_programmed_error_is_denied() {
        let kv = MockKv2::new().with_error("db/creds", MockError::Denied);
        let err = block_on(kv.read_field("db/creds", "sealed")).unwrap_err();
        assert!(matches!(err, VaultError::PermissionDenied { .. }));
    }

    #[test]
    fn kv2_read_data_deserializes() {
        let kv = MockKv2::new().with_data("db/creds", json!({ "sealed": "abc" }));
        let data: HashMap<String, String> = block_on(kv.read_data("db/creds")).expect("data");
        assert_eq!(data.get("sealed").map(String::as_str), Some("abc"));
    }

    #[test]
    fn cert_login_returns_programmed_token() {
        let cert =
            MockCertAuth::new().with_login(auth_info("s.tok", "acc-1", &["reader"], 3600, true));
        let auth = block_on(cert.login(Some("web"))).expect("login");
        assert_eq!(auth.client_token.expose_secret(), "s.tok");
        assert_eq!(auth.accessor, "acc-1");
        assert!(auth.renewable);
        assert_eq!(cert.calls(), vec![Some("web".to_owned())]);
    }

    #[test]
    fn cert_login_programmed_error() {
        let cert = MockCertAuth::new().with_error(MockError::AuthRequired);
        let err = block_on(cert.login(None)).unwrap_err();
        assert!(matches!(err, VaultError::AuthRequired));
    }

    #[test]
    fn cert_login_unprogrammed_is_auth_required() {
        let cert = MockCertAuth::new();
        let err = block_on(cert.login(Some("web"))).unwrap_err();
        assert!(matches!(err, VaultError::AuthRequired));
    }

    #[test]
    fn pki_sign_verbatim_returns_programmed_cert() {
        let pki = MockPki::new().with_signed(pki_signed(
            "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----",
            &["-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----"],
        ));
        let signed = block_on(pki.sign_verbatim("cic-module", "CSR")).expect("signed");
        assert!(signed.certificate.contains("LEAF"));
        assert_eq!(signed.ca_chain.len(), 1);
        assert_eq!(
            pki.calls(),
            vec![("cic-module".to_owned(), "CSR".to_owned())]
        );
    }

    #[test]
    fn pki_sign_verbatim_programmed_error() {
        let pki = MockPki::new().with_error(MockError::Denied);
        let err = block_on(pki.sign_verbatim("cic-module", "CSR")).unwrap_err();
        assert!(matches!(err, VaultError::PermissionDenied { .. }));
    }

    #[test]
    fn pki_sign_verbatim_unprogrammed_is_api_error() {
        let pki = MockPki::new();
        let err = block_on(pki.sign_verbatim("cic-module", "CSR")).unwrap_err();
        assert!(matches!(err, VaultError::Api { status: 500, .. }));
    }
}
