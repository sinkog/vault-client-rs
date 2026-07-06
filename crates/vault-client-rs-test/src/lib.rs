//! Test utilities for vault-client-rs
//!
//! Provides mock server helpers, response builders, and pre-configured test
//! clients for writing integration-style tests against a fake Vault backend

use secrecy::SecretString;
use serde_json::{Value, json};
use wiremock::MockServer;

pub use wiremock;

/// Driver-level (trait) mocks — an alternative to the HTTP-layer WireMock
/// helpers for unit-testing code generic over the operation traits.
pub mod mock;

/// Build a [`VaultClient`](vault_client_rs::VaultClient) pointed at `server`
/// with a default test token and zero retries
pub async fn test_client(server: &MockServer) -> vault_client_rs::VaultClient {
    test_client_with_token(server, "test-token").await
}

/// Build a [`VaultClient`](vault_client_rs::VaultClient) pointed at `server`
/// with the given token and zero retries
pub async fn test_client_with_token(
    server: &MockServer,
    token: &str,
) -> vault_client_rs::VaultClient {
    vault_client_rs::VaultClient::builder()
        .address(&server.uri())
        .token(SecretString::from(token.to_owned()))
        .max_retries(0)
        .build()
        .unwrap()
}

// ---------------------------------------------------------------------------
// Response builders
// ---------------------------------------------------------------------------

/// Build a KV2 `read` response envelope
pub fn kv2_response(data: Value) -> Value {
    json!({
        "data": {
            "data": data,
            "metadata": {
                "created_time": "2024-01-01T00:00:00.000000Z",
                "custom_metadata": null,
                "deletion_time": "",
                "destroyed": false,
                "version": 1
            }
        }
    })
}

/// Build a Vault auth response envelope (e.g. from login endpoints)
pub fn auth_response(token: &str, ttl: u64) -> Value {
    json!({
        "auth": {
            "client_token": token,
            "accessor": "test-accessor",
            "policies": ["default"],
            "token_policies": ["default"],
            "metadata": null,
            "lease_duration": ttl,
            "renewable": true,
            "entity_id": "entity-123",
            "token_type": "service",
            "orphan": false,
            "mfa_requirement": null,
            "num_uses": 0
        }
    })
}

/// Build a wrapped-secret response envelope
pub fn wrap_response(token: &str, ttl: u64) -> Value {
    json!({
        "wrap_info": {
            "token": token,
            "accessor": "wrap-accessor",
            "ttl": ttl,
            "creation_time": "2024-01-01T00:00:00.000000Z",
            "creation_path": "sys/wrapping/wrap",
            "wrapped_accessor": null
        }
    })
}

/// Build a leased-secret response envelope (for dynamic credentials)
pub fn lease_response(lease_id: &str, ttl: u64, data: Value) -> Value {
    json!({
        "request_id": "test-request-id",
        "lease_id": lease_id,
        "lease_duration": ttl,
        "renewable": true,
        "data": data
    })
}

/// Build a Vault error response
pub fn error_response(errors: &[&str]) -> Value {
    json!({ "errors": errors })
}

/// Build a `sys/leases/renew` success response
pub fn lease_renew_response(lease_id: &str, ttl: u64) -> Value {
    json!({
        "lease_id": lease_id,
        "lease_duration": ttl,
        "renewable": true
    })
}

/// Build a KV2 list response
pub fn list_response(keys: &[&str]) -> Value {
    json!({ "data": { "keys": keys } })
}

/// Build a simple data-only response envelope
pub fn data_response(data: Value) -> Value {
    json!({ "data": data })
}
