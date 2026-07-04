//! Behavioural coverage for the core request path in `async_client`
//! (`send_with_retry` + the generic list/delete helpers). Mutation testing
//! showed these were exercised but under-asserted: the exact retry counts and
//! returned values weren't pinned down. Each test asserts the precise behaviour
//! (via wiremock `.expect(n)` for attempt counts).

use std::time::Duration;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use vault_client_rs::{Kv1Operations, VaultClient, VaultError};

fn client(server: &MockServer, max_retries: u32) -> VaultClient {
    VaultClient::builder()
        .address(&server.uri())
        .token_str("t")
        .max_retries(max_retries)
        // Keep retries fast — we only care about counts, not timing.
        .initial_retry_delay(Duration::from_millis(1))
        .build()
        .unwrap()
}

// --- generic list/delete return values ---

#[tokio::test]
async fn list_returns_the_response_keys() {
    let server = MockServer::start().await;
    Mock::given(method("LIST"))
        .and(path("/v1/secret/app"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["alpha", "beta", "gamma"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    // Call the arbitrary-path VaultClient::list directly (the KV handlers use a
    // different helper, so this targets the generic list method).
    let keys = client(&server, 0).list("secret/app").await.unwrap();
    // Pins the actual keys (guards `list` against returning an arbitrary Vec).
    assert_eq!(keys, vec!["alpha", "beta", "gamma"]);
}

#[tokio::test]
async fn delete_issues_a_delete_request() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/v1/secret/app"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1) // guards `delete` against being a no-op that skips the call
        .mount(&server)
        .await;

    // Call the arbitrary-path VaultClient::delete directly.
    client(&server, 0).delete("secret/app").await.unwrap();
    // wiremock verifies the DELETE was actually sent on drop.
}

// --- retry semantics: retryable statuses retry up to `max`, then surface ---

#[tokio::test]
async fn consistency_412_retries_up_to_max_then_gives_up() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/app"))
        .respond_with(ResponseTemplate::new(412))
        .expect(3) // initial + 2 retries (max_retries = 2)
        .mount(&server)
        .await;

    let err = client(&server, 2)
        .kv1("secret")
        .read::<serde_json::Value>("app")
        .await
        .unwrap_err();
    assert!(matches!(err, VaultError::ConsistencyRetry), "got {err:?}");
}

#[tokio::test]
async fn rate_limited_429_retries_up_to_max_then_gives_up() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/app"))
        .respond_with(ResponseTemplate::new(429))
        .expect(3)
        .mount(&server)
        .await;

    let err = client(&server, 2)
        .kv1("secret")
        .read::<serde_json::Value>("app")
        .await
        .unwrap_err();
    assert!(matches!(err, VaultError::RateLimited { .. }), "got {err:?}");
}

#[tokio::test]
async fn sealed_503_retries_when_enabled_then_gives_up() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/app"))
        .respond_with(ResponseTemplate::new(503))
        .expect(3) // retry_on_sealed is on by default
        .mount(&server)
        .await;

    let err = client(&server, 2)
        .kv1("secret")
        .read::<serde_json::Value>("app")
        .await
        .unwrap_err();
    assert!(matches!(err, VaultError::Sealed { .. }), "got {err:?}");
}

#[tokio::test]
async fn sealed_503_is_not_retried_in_cli_mode() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/app"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1) // cli_mode disables sealed retries -> single attempt
        .mount(&server)
        .await;

    let client = VaultClient::builder()
        .address(&server.uri())
        .token_str("t")
        .cli_mode(true)
        .build()
        .unwrap();
    let err = client
        .kv1("secret")
        .read::<serde_json::Value>("app")
        .await
        .unwrap_err();
    assert!(matches!(err, VaultError::Sealed { .. }), "got {err:?}");
}

#[tokio::test]
async fn retryable_500_retries_then_surfaces_api_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/app"))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
            "errors": ["internal server error"]
        })))
        .expect(3)
        .mount(&server)
        .await;

    let err = client(&server, 2)
        .kv1("secret")
        .read::<serde_json::Value>("app")
        .await
        .unwrap_err();
    assert!(
        matches!(err, VaultError::Api { status: 500, .. }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn non_retryable_400_is_not_retried() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/app"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "errors": ["bad request"]
        })))
        .expect(1) // 400 is not retryable -> exactly one attempt even with retries enabled
        .mount(&server)
        .await;

    let err = client(&server, 2)
        .kv1("secret")
        .read::<serde_json::Value>("app")
        .await
        .unwrap_err();
    assert!(
        matches!(err, VaultError::Api { status: 400, .. }),
        "got {err:?}"
    );
}
