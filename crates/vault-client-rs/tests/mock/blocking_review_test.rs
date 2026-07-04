//! Focused review of the sync-over-async bridge in the `blocking` feature.
//!
//! The ~360 handler methods are mechanical `rt.block_on(self.inner.<op>())`
//! delegations; the real risk lives in the runtime bridge (`blocking_client.rs`)
//! and its footguns. These tests exercise those, not every delegation. See
//! docs/BLOCKING_REVIEW.md for the findings.

use std::collections::HashMap;
use std::sync::Arc;

use secrecy::SecretString;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use vault_client_rs::blocking::VaultClient as BlockingVaultClient;
use vault_client_rs::{KvReadResponse, VaultError};

fn kv2_body(data: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "data": {
            "data": data,
            "metadata": {
                "version": 1, "created_time": "2025-01-01T00:00:00Z",
                "deletion_time": "", "destroyed": false
            }
        }
    })
}

// --- Footgun 1: constructing the client inside a running runtime is rejected ---

#[tokio::test]
async fn build_inside_tokio_runtime_is_rejected() {
    // The blocking client spawns its own runtime; building it while already
    // inside one must fail with a helpful error rather than deadlock/panic.
    let err = BlockingVaultClient::builder()
        .address("http://127.0.0.1:8200")
        .token_str("t")
        .build()
        .expect_err("building inside a Tokio runtime must be rejected");
    match err {
        VaultError::Config(msg) => assert!(
            msg.contains("runtime"),
            "error should explain the nested-runtime problem: {msg}"
        ),
        other => panic!("expected Config error, got {other:?}"),
    }
}

// --- Footgun 2: calling a blocking method from within an async context panics ---

#[test]
fn blocking_call_inside_async_context_panics() {
    let setup = tokio::runtime::Runtime::new().unwrap();
    let server = setup.block_on(MockServer::start());
    setup.block_on(async {
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/key"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(kv2_body(serde_json::json!({"foo": "bar"}))),
            )
            .mount(&server)
            .await;
    });

    // Built outside any running runtime — fine.
    let client = BlockingVaultClient::builder()
        .address(&server.uri())
        .token_str("t")
        .max_retries(0)
        .build()
        .unwrap();

    // Now call it from *within* a runtime: the inner `rt.block_on` starts a
    // runtime from within a runtime, which Tokio panics on. We document that
    // this is the failure mode (it does not silently hang or misbehave).
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        setup.block_on(async {
            let _: KvReadResponse<HashMap<String, String>> =
                client.kv2("secret").read("key").unwrap();
        });
    }));
    assert!(
        outcome.is_err(),
        "a blocking call from inside an async context must panic (nested block_on), \
         not hang or return silently"
    );
}

// --- Concurrency: the client is Send+Sync; is it actually usable from threads? ---

#[test]
fn blocking_client_is_usable_from_multiple_threads() {
    let setup = tokio::runtime::Runtime::new().unwrap();
    let server = setup.block_on(MockServer::start());
    setup.block_on(async {
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/key"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(kv2_body(serde_json::json!({"foo": "bar"}))),
            )
            .mount(&server)
            .await;
    });

    let client = Arc::new(
        BlockingVaultClient::builder()
            .address(&server.uri())
            .token_str("t")
            .max_retries(0)
            .build()
            .unwrap(),
    );

    // Share the single-runtime client across OS threads and hit it concurrently.
    // This verifies the advertised Send+Sync is actually safe to use (calls may
    // be serialized on the one runtime thread, but must all succeed — not panic
    // or deadlock).
    let mut handles = Vec::new();
    for _ in 0..4 {
        let c = Arc::clone(&client);
        handles.push(std::thread::spawn(move || {
            let resp: KvReadResponse<HashMap<String, String>> =
                c.kv2("secret").read("key").unwrap();
            assert_eq!(resp.data["foo"], "bar");
        }));
    }
    for h in handles {
        h.join()
            .expect("a worker thread panicked using the shared blocking client");
    }
}

// --- Behavioural parity: error mapping travels through the bridge ---

#[test]
fn blocking_surfaces_permission_denied() {
    let setup = tokio::runtime::Runtime::new().unwrap();
    let server = setup.block_on(MockServer::start());
    setup.block_on(async {
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/key"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "errors": ["permission denied"]
            })))
            .mount(&server)
            .await;
    });

    let client = BlockingVaultClient::builder()
        .address(&server.uri())
        .token_str("t")
        .max_retries(0)
        .build()
        .unwrap();

    let err = client
        .kv2("secret")
        .read::<HashMap<String, String>>("key")
        .unwrap_err();
    assert!(
        matches!(err, VaultError::PermissionDenied { .. }),
        "403 must map to PermissionDenied through the blocking bridge, got {err:?}"
    );
}

// --- Behavioural parity: a non-KV engine (transit) round-trips through the bridge ---

#[test]
fn blocking_transit_encrypt_parity() {
    let setup = tokio::runtime::Runtime::new().unwrap();
    let server = setup.block_on(MockServer::start());
    setup.block_on(async {
        Mock::given(method("POST"))
            .and(path("/v1/transit/encrypt/my-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {"ciphertext": "vault:v1:abcdef"}
            })))
            .mount(&server)
            .await;
    });

    let client = BlockingVaultClient::builder()
        .address(&server.uri())
        .token_str("t")
        .max_retries(0)
        .build()
        .unwrap();

    let ct = client
        .transit("transit")
        .encrypt("my-key", &SecretString::from("hello"))
        .unwrap();
    assert_eq!(ct, "vault:v1:abcdef");
}
