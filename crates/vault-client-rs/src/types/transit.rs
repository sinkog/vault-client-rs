use std::collections::HashMap;
use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::redaction::{RedactionLevel, redact, redaction_level};

#[derive(Debug, Serialize, Default, Clone)]
pub struct TransitKeyParams {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub convergent_encryption: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exportable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_plaintext_backup: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_rotate_period: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_size: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct TransitKeyInfo {
    #[serde(rename = "type")]
    pub key_type: String,
    pub deletion_allowed: bool,
    pub derived: bool,
    pub exportable: bool,
    pub allow_plaintext_backup: bool,
    #[serde(default)]
    pub keys: HashMap<String, serde_json::Value>,
    pub min_decryption_version: u64,
    pub min_encryption_version: u64,
    pub name: String,
    pub supports_encryption: bool,
    pub supports_decryption: bool,
    pub supports_derivation: bool,
    pub supports_signing: bool,
    #[serde(default)]
    pub auto_rotate_period: u64,
    pub latest_version: u64,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct TransitKeyConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_decryption_version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_encryption_version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deletion_allowed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exportable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_plaintext_backup: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_rotate_period: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TransitEncryptResponse {
    pub ciphertext: String,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct TransitDecryptResponse {
    pub plaintext: SecretString,
}

impl fmt::Debug for TransitDecryptResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransitDecryptResponse")
            .field("plaintext", &redact(self.plaintext.expose_secret()))
            .finish()
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct TransitRewrapResponse {
    pub ciphertext: String,
}

#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
pub struct TransitBatchPlaintext {
    #[serde(serialize_with = "super::serde_secret::serialize")]
    pub plaintext: SecretString,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

impl Clone for TransitBatchPlaintext {
    fn clone(&self) -> Self {
        Self {
            plaintext: self.plaintext.clone(),
            context: self.context.clone(),
        }
    }
}

impl fmt::Debug for TransitBatchPlaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransitBatchPlaintext")
            .field("plaintext", &"[REDACTED]")
            .field("context", &self.context)
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TransitBatchCiphertext {
    pub ciphertext: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct TransitSignParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub marshaling_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prehashed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt_length: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TransitSignResponse {
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TransitVerifyResponse {
    pub valid: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TransitHashResponse {
    pub sum: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TransitHmacResponse {
    pub hmac: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TransitRandomResponse {
    pub random_bytes: String,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct TransitDataKey {
    pub ciphertext: String,
    pub plaintext: Option<SecretString>,
}

impl Clone for TransitDataKey {
    fn clone(&self) -> Self {
        Self {
            ciphertext: self.ciphertext.clone(),
            plaintext: self.plaintext.clone(),
        }
    }
}

impl fmt::Debug for TransitDataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransitDataKey")
            .field("ciphertext", &self.ciphertext)
            .field(
                "plaintext",
                &self.plaintext.as_ref().map(|s| redact(s.expose_secret())),
            )
            .finish()
    }
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct TransitExportedKey {
    pub name: String,
    #[zeroize(skip)]
    pub keys: HashMap<String, SecretString>,
    #[serde(rename = "type")]
    pub key_type: String,
}

impl Clone for TransitExportedKey {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            keys: self.keys.clone(),
            key_type: self.key_type.clone(),
        }
    }
}

impl fmt::Debug for TransitExportedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match redaction_level() {
            RedactionLevel::Full => {
                let summary = format!("[REDACTED; {} versions]", self.keys.len());
                f.debug_struct("TransitExportedKey")
                    .field("name", &self.name)
                    .field("keys", &summary)
                    .field("key_type", &self.key_type)
                    .finish()
            }
            _ => {
                let map: HashMap<String, String> = self
                    .keys
                    .iter()
                    .map(|(k, v)| (k.clone(), redact(v.expose_secret())))
                    .collect();
                f.debug_struct("TransitExportedKey")
                    .field("name", &self.name)
                    .field("keys", &map)
                    .field("key_type", &self.key_type)
                    .finish()
            }
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct TransitCacheConfig {
    pub size: u64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TransitBatchEncryptResponse {
    #[serde(default)]
    pub batch_results: Vec<TransitBatchCiphertext>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TransitBatchDecryptResponse {
    #[serde(default)]
    pub batch_results: Vec<TransitBatchDecryptItem>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct TransitBatchDecryptItem {
    pub plaintext: Option<SecretString>,
    #[serde(default)]
    pub error: String,
}

impl Clone for TransitBatchDecryptItem {
    fn clone(&self) -> Self {
        Self {
            plaintext: self.plaintext.clone(),
            error: self.error.clone(),
        }
    }
}

impl fmt::Debug for TransitBatchDecryptItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransitBatchDecryptItem")
            .field(
                "plaintext",
                &self.plaintext.as_ref().map(|s| redact(s.expose_secret())),
            )
            .field("error", &self.error)
            .finish()
    }
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct TransitBackupResponse {
    pub backup: SecretString,
}

impl fmt::Debug for TransitBackupResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransitBackupResponse")
            .field("backup", &redact(self.backup.expose_secret()))
            .finish()
    }
}

// --- Batch sign/verify ---

#[derive(Debug, Serialize, Clone)]
pub struct TransitBatchSignInput {
    pub input: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct TransitBatchSignResult {
    pub signature: String,
    #[serde(default)]
    pub error: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct TransitBatchVerifyInput {
    pub input: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct TransitBatchVerifyResult {
    pub valid: bool,
    #[serde(default)]
    pub error: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TransitBatchSignResponse {
    #[serde(default)]
    pub batch_results: Vec<TransitBatchSignResult>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TransitBatchVerifyResponse {
    #[serde(default)]
    pub batch_results: Vec<TransitBatchVerifyResult>,
}

#[cfg(test)]
mod tests {
    //! In-crate coverage for the redacting `Debug` impls that external tests
    //! can't reach: the `pub(crate)` wire responses and the non-`Full`
    //! redaction arm of `TransitExportedKey`. nextest isolates each test in its
    //! own process, so mutating the global redaction level here is safe.
    use std::collections::HashMap;

    use secrecy::SecretString;

    use super::{TransitBackupResponse, TransitDecryptResponse, TransitExportedKey};
    use crate::types::redaction::{RedactionLevel, set_redaction_level};

    #[test]
    fn decrypt_response_debug_redacts_plaintext() {
        let resp = TransitDecryptResponse {
            plaintext: SecretString::from("super-secret-plaintext"),
        };
        let debug = format!("{resp:?}");
        assert!(debug.contains("TransitDecryptResponse"));
        assert!(!debug.contains("super-secret-plaintext"));
    }

    #[test]
    fn backup_response_debug_redacts_backup() {
        let resp = TransitBackupResponse {
            backup: SecretString::from("super-secret-backup-blob"),
        };
        let debug = format!("{resp:?}");
        assert!(debug.contains("TransitBackupResponse"));
        assert!(!debug.contains("super-secret-backup-blob"));
    }

    #[test]
    fn exported_key_debug_non_full_arm_redacts_each_key() {
        let mut keys = HashMap::new();
        keys.insert(
            "1".to_string(),
            SecretString::from("super-secret-key-material"),
        );
        let exported = TransitExportedKey {
            name: "my-key".to_string(),
            keys,
            key_type: "aes256-gcm96".to_string(),
        };

        // Partial redaction takes the non-`Full` match arm, which redacts each
        // map entry individually rather than summarising.
        set_redaction_level(RedactionLevel::Partial);
        let debug = format!("{exported:?}");
        set_redaction_level(RedactionLevel::Full);

        assert!(debug.contains("TransitExportedKey"));
        assert!(!debug.contains("super-secret-key-material"));
    }
}
