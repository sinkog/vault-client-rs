use std::collections::HashMap;
use std::net::TcpListener;
use std::time::Duration;

use secrecy::SecretString;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::build_test_client;
use vault_client_rs::{
    AppRoleAuthOperations, Kv2Operations, KvReadResponse, TokenAuthOperations, VaultClient,
    VaultError,
};

#[tokio::test]
async fn vault_client_new_builds_successfully() {
    let server = MockServer::start().await;
    let client = VaultClient::new(&server.uri(), "my-token");
    assert!(
        client.is_ok(),
        "VaultClient::new() should succeed: {client:?}"
    );
}

#[tokio::test]
async fn builder_requires_address() {
    let err = VaultClient::builder().token_str("t").build().unwrap_err();
    assert!(matches!(err, VaultError::Config(_)));
}

#[tokio::test]
async fn builder_accepts_valid_url() {
    let server = MockServer::start().await;
    let client = VaultClient::builder()
        .address(&server.uri())
        .token_str("t")
        .build();
    assert!(client.is_ok());
}

#[tokio::test]
async fn builder_rejects_invalid_url() {
    let err = VaultClient::builder()
        .address("not a url")
        .token_str("t")
        .build()
        .unwrap_err();
    assert!(matches!(err, VaultError::Config(_)));
}

#[tokio::test]
async fn token_header_is_injected() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/key"))
        .and(header("X-Vault-Token", "test-token"))
        .and(header("X-Vault-Request", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "data": {"foo": "bar"},
                "metadata": {"version": 1, "created_time": "2025-01-01T00:00:00Z", "deletion_time": "", "destroyed": false}
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let resp: KvReadResponse<HashMap<String, String>> =
        client.kv2("secret").read("key").await.unwrap();
    assert_eq!(resp.data["foo"], "bar");
}

#[tokio::test]
async fn namespace_header_is_injected() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .and(header("X-Vault-Namespace", "admin/prod"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "initialized": true, "sealed": false, "standby": false, "version": "1.17.0"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = VaultClient::builder()
        .address(&server.uri())
        .token_str("t")
        .namespace("admin/prod")
        .max_retries(0)
        .build()
        .unwrap();

    let health = client.sys().health().await.unwrap();
    assert!(health.initialized);
}

#[tokio::test]
async fn wrap_ttl_header_is_sent() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/wrapped"))
        .and(header("X-Vault-Wrap-TTL", "5m"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "wrap_info": {
                "token": "s.wrapped",
                "accessor": "acc",
                "ttl": 300,
                "creation_time": "2025-01-01T00:00:00Z",
                "creation_path": "secret/data/wrapped"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = VaultClient::builder()
        .address(&server.uri())
        .token_str("t")
        .wrap_ttl("5m")
        .max_retries(0)
        .build()
        .unwrap();

    let _ = client
        .kv2("secret")
        .read::<serde_json::Value>("wrapped")
        .await;
}

#[tokio::test]
async fn set_token_changes_header() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/key"))
        .and(header("X-Vault-Token", "new-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "data": {"a": "b"},
                "metadata": {"version": 1, "created_time": "2025-01-01T00:00:00Z", "deletion_time": "", "destroyed": false}
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.set_token(SecretString::from("new-token")).unwrap();
    let _: KvReadResponse<HashMap<String, String>> =
        client.kv2("secret").read("key").await.unwrap();
}

#[tokio::test]
async fn retry_on_429_then_succeed() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/key"))
        .respond_with(ResponseTemplate::new(429))
        .up_to_n_times(2)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "data": {"value": "success"},
                "metadata": {"version": 1, "created_time": "2025-01-01T00:00:00Z", "deletion_time": "", "destroyed": false}
            }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::builder()
        .address(&server.uri())
        .token_str("t")
        .max_retries(3)
        .initial_retry_delay(Duration::from_millis(10))
        .build()
        .unwrap();

    let resp: KvReadResponse<HashMap<String, String>> =
        client.kv2("secret").read("key").await.unwrap();
    assert_eq!(resp.data["value"], "success");
}

#[tokio::test]
async fn retry_exhausted_returns_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/key"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let client = VaultClient::builder()
        .address(&server.uri())
        .token_str("t")
        .max_retries(1)
        .initial_retry_delay(Duration::from_millis(1))
        .build()
        .unwrap();

    let err = client
        .kv2("secret")
        .read::<serde_json::Value>("key")
        .await
        .unwrap_err();
    assert!(matches!(err, VaultError::Sealed { .. }));
}

#[tokio::test]
async fn sealed_vault_is_retried() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/key"))
        .respond_with(ResponseTemplate::new(503).set_body_json(serde_json::json!({
            "errors": ["Vault is sealed"]
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "data": {"ok": "yes"},
                "metadata": {"version": 1, "created_time": "2025-01-01T00:00:00Z", "deletion_time": "", "destroyed": false}
            }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::builder()
        .address(&server.uri())
        .token_str("t")
        .max_retries(2)
        .initial_retry_delay(Duration::from_millis(1))
        .build()
        .unwrap();

    let resp: KvReadResponse<HashMap<String, String>> =
        client.kv2("secret").read("key").await.unwrap();
    assert_eq!(resp.data["ok"], "yes");
}

#[tokio::test]
async fn permission_denied_not_retried() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/key"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "errors": ["1 error occurred:\n\t* permission denied\n\n"]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = VaultClient::builder()
        .address(&server.uri())
        .token_str("t")
        .max_retries(3)
        .build()
        .unwrap();

    let err = client
        .kv2("secret")
        .read::<serde_json::Value>("key")
        .await
        .unwrap_err();
    assert!(matches!(err, VaultError::PermissionDenied { .. }));
}

#[tokio::test]
async fn not_found_returns_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/missing"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let err = client
        .kv2("secret")
        .read::<serde_json::Value>("missing")
        .await
        .unwrap_err();
    assert!(matches!(err, VaultError::NotFound { .. }));
}

#[tokio::test]
async fn list_returns_empty_on_404() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/secret/metadata/empty/"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let keys = client.kv2("secret").list("empty/").await.unwrap();
    assert!(keys.is_empty());
}

#[tokio::test]
async fn concurrent_reads_are_safe() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "data": {"value": "ok"},
                "metadata": {"version": 1, "created_time": "2025-01-01T00:00:00Z", "deletion_time": "", "destroyed": false}
            }
        })))
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;

    let handles: Vec<_> = (0..50)
        .map(|i| {
            let c = client.clone();
            tokio::spawn(async move {
                let _: KvReadResponse<HashMap<String, String>> =
                    c.kv2("secret").read(&format!("key/{i}")).await.unwrap();
            })
        })
        .collect();

    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn patch_sends_merge_patch_content_type() {
    let server = MockServer::start().await;

    Mock::given(method("PATCH"))
        .and(path("/v1/secret/data/myapp/config"))
        .and(header("Content-Type", "application/merge-patch+json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"version": 2, "created_time": "2025-01-01T00:00:00Z", "deletion_time": "", "destroyed": false}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let _ = client
        .kv2("secret")
        .patch("myapp/config", &serde_json::json!({"new_key": "value"}))
        .await;
}

#[tokio::test]
async fn unauthorized_returns_api_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/key"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "errors": ["missing client token"]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let err = client
        .kv2("secret")
        .read::<serde_json::Value>("key")
        .await
        .unwrap_err();
    assert!(
        matches!(err, VaultError::AuthRequired),
        "expected AuthRequired, got: {err:?}"
    );
}

#[tokio::test]
async fn malformed_json_returns_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/key"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not valid json at all"))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let err = client
        .kv2("secret")
        .read::<serde_json::Value>("key")
        .await
        .unwrap_err();
    assert!(
        matches!(err, VaultError::Http(_)),
        "expected Http (deser) error, got: {err:?}"
    );
}

#[tokio::test]
async fn empty_data_envelope_returns_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": null
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let err = client
        .kv2("secret")
        .read::<serde_json::Value>("key")
        .await
        .unwrap_err();
    assert!(
        matches!(err, VaultError::EmptyResponse),
        "expected EmptyResponse, got: {err:?}"
    );
}

#[tokio::test]
async fn server_error_500_not_retried_when_max_zero() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/key"))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
            "errors": ["internal error"]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let err = client
        .kv2("secret")
        .read::<serde_json::Value>("key")
        .await
        .unwrap_err();
    match err {
        VaultError::Api { status, errors } => {
            assert_eq!(status, 500);
            assert_eq!(errors, vec!["internal error"]);
        }
        other => panic!("expected Api error, got: {other:?}"),
    }
}

#[tokio::test]
async fn rate_limited_exhaustion() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/key"))
        .respond_with(ResponseTemplate::new(429))
        .mount(&server)
        .await;

    let client = VaultClient::builder()
        .address(&server.uri())
        .token_str("t")
        .max_retries(1)
        .initial_retry_delay(Duration::from_millis(1))
        .build()
        .unwrap();

    let err = client
        .kv2("secret")
        .read::<serde_json::Value>("key")
        .await
        .unwrap_err();
    assert!(
        matches!(err, VaultError::RateLimited { .. }),
        "expected RateLimited, got: {err:?}"
    );
}

#[tokio::test]
async fn consistency_retry_exhaustion() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/key"))
        .respond_with(ResponseTemplate::new(412))
        .mount(&server)
        .await;

    let client = VaultClient::builder()
        .address(&server.uri())
        .token_str("t")
        .max_retries(1)
        .initial_retry_delay(Duration::from_millis(1))
        .build()
        .unwrap();

    let err = client
        .kv2("secret")
        .read::<serde_json::Value>("key")
        .await
        .unwrap_err();
    assert!(
        matches!(err, VaultError::ConsistencyRetry),
        "expected ConsistencyRetry, got: {err:?}"
    );
}

#[tokio::test]
async fn list_uses_list_method() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/secret/metadata/apps/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["app1", "app2/"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let keys = client.kv2("secret").list("apps/").await.unwrap();
    assert_eq!(keys, vec!["app1", "app2/"]);
}

#[tokio::test]
async fn server_500_retried_then_succeeds() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/key"))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
            "errors": ["internal error"]
        })))
        .up_to_n_times(2)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "data": {"recovered": "yes"},
                "metadata": {"version": 1, "created_time": "2025-01-01T00:00:00Z", "deletion_time": "", "destroyed": false}
            }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::builder()
        .address(&server.uri())
        .token_str("t")
        .max_retries(3)
        .initial_retry_delay(Duration::from_millis(1))
        .build()
        .unwrap();

    let resp: KvReadResponse<HashMap<String, String>> =
        client.kv2("secret").read("key").await.unwrap();
    assert_eq!(resp.data["recovered"], "yes");
}

#[tokio::test]
async fn client_without_token_omits_header() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "initialized": true, "sealed": false, "standby": false, "version": "1.17.0"
        })))
        .expect(1)
        .mount(&server)
        .await;

    // Build a client without a token — should still be able to call unauthenticated endpoints
    let client = VaultClient::builder()
        .address(&server.uri())
        .max_retries(0)
        .build()
        .unwrap();

    let health = client.sys().health().await.unwrap();
    assert!(health.initialized);
}

#[tokio::test]
async fn forward_to_leader_sends_header() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .and(header("X-Vault-Forward", "active-node"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "initialized": true, "sealed": false, "standby": false, "version": "1.17.0"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = VaultClient::builder()
        .address(&server.uri())
        .token_str("t")
        .forward_to_leader(true)
        .max_retries(0)
        .build()
        .unwrap();

    let health = client.sys().health().await.unwrap();
    assert!(health.initialized);
}

#[tokio::test]
async fn rate_limited_with_retry_after_header() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/key"))
        .respond_with(ResponseTemplate::new(429).append_header("Retry-After", "2"))
        .mount(&server)
        .await;

    let client = VaultClient::builder()
        .address(&server.uri())
        .token_str("t")
        .max_retries(0)
        .build()
        .unwrap();

    let err = client
        .kv2("secret")
        .read::<serde_json::Value>("key")
        .await
        .unwrap_err();
    match err {
        VaultError::RateLimited { retry_after } => {
            assert_eq!(retry_after, Some(2));
        }
        other => panic!("expected RateLimited, got: {other:?}"),
    }
}

#[tokio::test]
async fn bad_request_returns_api_error_with_details() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/secret/data/key"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "errors": ["check-and-set parameter required for this call"]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let err = client
        .kv2("secret")
        .write("key", &serde_json::json!({"foo": "bar"}))
        .await
        .unwrap_err();
    match err {
        VaultError::Api { status, errors } => {
            assert_eq!(status, 400);
            assert!(errors[0].contains("check-and-set"));
        }
        other => panic!("expected Api error, got: {other:?}"),
    }
}

#[tokio::test]
async fn not_found_not_retried_even_with_retries() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/missing"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1) // must be called exactly once (no retries)
        .mount(&server)
        .await;

    let client = VaultClient::builder()
        .address(&server.uri())
        .token_str("t")
        .max_retries(3)
        .build()
        .unwrap();

    let err = client
        .kv2("secret")
        .read::<serde_json::Value>("missing")
        .await
        .unwrap_err();
    assert!(matches!(err, VaultError::NotFound { .. }));
}

#[tokio::test]
async fn token_renew_self_updates_internal_token() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/token/renew-self"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "auth": {
                "client_token": "s.renewed",
                "accessor": "acc-renewed",
                "policies": ["default"],
                "token_policies": ["default"],
                "metadata": null,
                "lease_duration": 7200,
                "renewable": true,
                "entity_id": "ent-1",
                "token_type": "service",
                "orphan": false,
                "mfa_requirement": null,
                "num_uses": 0
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    // After renew, the internal token should be "s.renewed"
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/verify"))
        .and(header("X-Vault-Token", "s.renewed"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "data": {"ok": "yes"},
                "metadata": {"version": 1, "created_time": "2025-01-01T00:00:00Z", "deletion_time": "", "destroyed": false}
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.auth().token().renew_self(None).await.unwrap();

    let resp: KvReadResponse<HashMap<String, String>> =
        client.kv2("secret").read("verify").await.unwrap();
    assert_eq!(resp.data["ok"], "yes");
}

#[tokio::test]
async fn approle_login_missing_auth_returns_error() {
    let server = MockServer::start().await;

    // Vault returns 200 but with no auth field
    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "request_id": "abc",
            "data": null,
            "auth": null
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let err = client
        .auth()
        .approle()
        .login("role-id", &SecretString::from("secret-id"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, VaultError::EmptyResponse),
        "expected EmptyResponse for missing auth, got: {err:?}"
    );
}

#[tokio::test]
async fn connect_error_is_http_and_retryable() {
    // Bind then drop to get a port with nothing listening, so the request fails to connect
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let client = VaultClient::builder()
        .address(&format!("http://{addr}"))
        .token_str("test-token")
        .max_retries(0)
        .build()
        .unwrap();

    let err = client
        .kv2("secret")
        .read::<serde_json::Value>("key")
        .await
        .unwrap_err();
    assert!(
        matches!(err, VaultError::Http(_)),
        "expected Http, got: {err:?}"
    );
    assert!(err.is_retryable(), "connect errors must be retryable");
}
