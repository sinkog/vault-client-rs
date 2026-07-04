use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::redaction::redacted_debug;

#[derive(Deserialize, Clone)]
#[non_exhaustive]
pub struct KvReadResponse<T> {
    pub data: T,
    pub metadata: KvMetadata,
}

// `T` is the caller's secret payload, so it must go through redaction rather than
// a derived Debug that would print it verbatim
impl<T: fmt::Debug> fmt::Debug for KvReadResponse<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KvReadResponse")
            .field("data", &redacted_debug(&self.data))
            .field("metadata", &self.metadata)
            .finish()
    }
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct KvMetadata {
    pub created_time: String,
    pub custom_metadata: Option<HashMap<String, String>>,
    #[serde(default)]
    pub deletion_time: String,
    #[serde(default)]
    pub destroyed: bool,
    pub version: u64,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct KvFullMetadata {
    pub cas_required: bool,
    pub created_time: String,
    pub current_version: u64,
    pub custom_metadata: Option<HashMap<String, String>>,
    #[serde(default)]
    pub delete_version_after: String,
    pub max_versions: u64,
    pub oldest_version: u64,
    pub updated_time: String,
    #[serde(default)]
    pub versions: HashMap<String, KvVersionMetadata>,
}

#[derive(Debug, Deserialize, Clone)]
#[non_exhaustive]
pub struct KvVersionMetadata {
    pub created_time: String,
    #[serde(default)]
    pub deletion_time: String,
    #[serde(default)]
    pub destroyed: bool,
}

#[derive(Debug, Serialize, Default, Clone)]
pub struct KvMetadataParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_versions: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cas_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete_version_after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct KvConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cas_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_versions: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete_version_after: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ListResponse {
    #[serde(default)]
    pub keys: Vec<String>,
}
