//! API-level coverage for the hand-written Clone/Debug (redaction) impls on
//! `AuthInfo`, `WrapInfo`, and `TransitBatchDecryptItem`: response types with
//! no existing redaction test, only ever produced by a live client call.
//! `TransitDataKey` and `TransitExportedKey` already have direct redaction
//! coverage in `tests/unit/response_redaction_test.rs`.
//!
//! Debug assertions check the struct name only — the redaction level is a
//! process-global that other tests in this binary flip, so asserting on the
//! [REDACTED] marker would be racy.

use secrecy::SecretString;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::build_test_client;
use vault_client_rs::types::transit::TransitBatchCiphertext;
use vault_client_rs::{TransitOperations, UserpassAuthOperations};

#[tokio::test]
async fn auth_info_from_login_clones_and_redacts() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/auth/userpass/login/alice"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "auth": {
                "client_token": "s.supersecret",
                "accessor": "acc-1",
                "policies": ["default"],
                "token_policies": ["default"],
                "metadata": {"user": "alice"},
                "lease_duration": 3600,
                "renewable": true,
                "entity_id": "ent-1",
                "token_type": "service",
                "orphan": false,
                "mfa_requirement": null,
                "num_uses": 0
            }
        })))
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let auth = client
        .auth()
        .userpass()
        .login("alice", &SecretString::from("pw"))
        .await
        .unwrap();

    let cloned = auth.clone();
    assert_eq!(cloned.accessor, "acc-1");
    let debug = format!("{cloned:?}");
    assert!(debug.contains("AuthInfo"));
    // The secret token must never appear verbatim, regardless of redaction level
    assert!(!debug.contains("s.supersecret"));
}

#[tokio::test]
async fn wrap_info_from_lookup_clones_and_redacts() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/sys/wrapping/lookup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "token": "s.wrapsecret",
                "accessor": "wrap-acc",
                "ttl": 300,
                "creation_time": "2024-06-01T12:00:00Z",
                "creation_path": "secret/data/app",
                "wrapped_accessor": "inner-acc"
            }
        })))
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let info = client
        .sys()
        .wrap_lookup(&SecretString::from("s.wrapsecret"))
        .await
        .unwrap();

    let cloned = info.clone();
    assert_eq!(cloned.accessor, "wrap-acc");
    let debug = format!("{cloned:?}");
    assert!(debug.contains("WrapInfo"));
    assert!(!debug.contains("s.wrapsecret"));
}

#[tokio::test]
async fn transit_batch_decrypt_item_clones_and_redacts() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/transit/decrypt/my-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"batch_results": [{"plaintext": "aGVsbG8="}, {"error": "bad ciphertext"}]}
        })))
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let items: Vec<TransitBatchCiphertext> = serde_json::from_value(serde_json::json!([
        {"ciphertext": "vault:v1:ct1"},
        {"ciphertext": "vault:v1:ct2"}
    ]))
    .unwrap();
    let results = client
        .transit("transit")
        .batch_decrypt("my-key", &items)
        .await
        .unwrap();

    assert_eq!(results.len(), 2);
    let cloned = results[0].clone();
    let debug = format!("{cloned:?}");
    assert!(debug.contains("TransitBatchDecryptItem"));
    assert!(!debug.contains("aGVsbG8="));
    // Per-item error is surfaced on the second result
    assert_eq!(results[1].error, "bad ciphertext");
}
