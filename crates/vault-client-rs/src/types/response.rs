use std::collections::HashMap;
use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::redaction::{redact, redacted_debug};

#[derive(Deserialize, Clone)]
#[non_exhaustive]
pub struct VaultResponse<T> {
    pub request_id: Option<String>,
    pub lease_id: Option<String>,
    pub lease_duration: Option<u64>,
    pub renewable: Option<bool>,
    pub data: Option<T>,
    pub auth: Option<AuthInfo>,
    pub warnings: Option<Vec<String>>,
    pub wrap_info: Option<WrapInfo>,
}

// `T` is caller-supplied secret payload, so it must go through redaction rather than
// a derived Debug that would print it verbatim
impl<T: fmt::Debug> fmt::Debug for VaultResponse<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultResponse")
            .field("request_id", &self.request_id)
            .field("lease_id", &self.lease_id)
            .field("lease_duration", &self.lease_duration)
            .field("renewable", &self.renewable)
            .field("data", &self.data.as_ref().map(redacted_debug))
            .field("auth", &self.auth)
            .field("warnings", &self.warnings)
            .field("wrap_info", &self.wrap_info)
            .finish()
    }
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct AuthInfo {
    pub client_token: SecretString,
    pub accessor: String,
    #[serde(default)]
    pub policies: Vec<String>,
    #[serde(default)]
    pub token_policies: Vec<String>,
    #[zeroize(skip)]
    pub metadata: Option<HashMap<String, String>>,
    pub lease_duration: u64,
    pub renewable: bool,
    pub entity_id: String,
    pub token_type: String,
    #[serde(default)]
    pub orphan: bool,
    #[zeroize(skip)]
    pub mfa_requirement: Option<serde_json::Value>,
    pub num_uses: Option<u64>,
}

impl Clone for AuthInfo {
    fn clone(&self) -> Self {
        Self {
            client_token: self.client_token.clone(),
            accessor: self.accessor.clone(),
            policies: self.policies.clone(),
            token_policies: self.token_policies.clone(),
            metadata: self.metadata.clone(),
            lease_duration: self.lease_duration,
            renewable: self.renewable,
            entity_id: self.entity_id.clone(),
            token_type: self.token_type.clone(),
            orphan: self.orphan,
            mfa_requirement: self.mfa_requirement.clone(),
            num_uses: self.num_uses,
        }
    }
}

impl fmt::Debug for AuthInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthInfo")
            .field("client_token", &redact(self.client_token.expose_secret()))
            .field("accessor", &self.accessor)
            .field("policies", &self.policies)
            .field("token_policies", &self.token_policies)
            .field("metadata", &self.metadata)
            .field("lease_duration", &self.lease_duration)
            .field("renewable", &self.renewable)
            .field("entity_id", &self.entity_id)
            .field("token_type", &self.token_type)
            .field("orphan", &self.orphan)
            .field("mfa_requirement", &self.mfa_requirement)
            .field("num_uses", &self.num_uses)
            .finish()
    }
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct WrapInfo {
    pub token: SecretString,
    pub accessor: String,
    pub ttl: u64,
    pub creation_time: String,
    pub creation_path: String,
    pub wrapped_accessor: Option<String>,
}

impl Clone for WrapInfo {
    fn clone(&self) -> Self {
        Self {
            token: self.token.clone(),
            accessor: self.accessor.clone(),
            ttl: self.ttl,
            creation_time: self.creation_time.clone(),
            creation_path: self.creation_path.clone(),
            wrapped_accessor: self.wrapped_accessor.clone(),
        }
    }
}

impl fmt::Debug for WrapInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WrapInfo")
            .field("token", &redact(self.token.expose_secret()))
            .field("accessor", &self.accessor)
            .field("ttl", &self.ttl)
            .field("creation_time", &self.creation_time)
            .field("creation_path", &self.creation_path)
            .field("wrapped_accessor", &self.wrapped_accessor)
            .finish()
    }
}
