use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use vault_client_rs::{AppRoleLogin, Kv1Operations, TokenAuthOperations, VaultClient};
use vault_client_rs_test::auth_response;

#[tokio::test]
async fn ensure_valid_token_skipped_for_auth_endpoints() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/auth/token/lookup-self"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "accessor": "acc-123",
                "creation_time": 1700000000,
                "creation_ttl": 3600,
                "display_name": "token",
                "entity_id": "ent-1",
                "expire_time": null,
                "explicit_max_ttl": 0,
                "id": "s.my-token",
                "issue_time": "2025-01-01T00:00:00Z",
                "meta": null,
                "num_uses": 0,
                "orphan": false,
                "path": "auth/token/create",
                "policies": ["default"],
                "renewable": true,
                "ttl": 3500,
                "type": "service"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    // No renewal mock needed; auth endpoints bypass the token lifecycle check
    let client = VaultClient::builder()
        .address(&server.uri())
        .token_str("test-token")
        .max_retries(0)
        .build()
        .unwrap();

    let info = client.auth().token().lookup_self().await.unwrap();
    assert_eq!(info.accessor, "acc-123");
    assert!(info.renewable);
}

#[tokio::test]
async fn request_with_valid_token_does_not_renew() {
    let server = MockServer::start().await;

    // The renewal endpoint should never be called
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
        .expect(0)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/my-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "username": "admin",
                "password": "s3cret"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    // A fresh token without lease info has no expiry, so no renewal should trigger
    let client = VaultClient::builder()
        .address(&server.uri())
        .token_str("test-token")
        .max_retries(0)
        .build()
        .unwrap();

    let data: HashMap<String, String> = client.kv1("secret").read("my-secret").await.unwrap();
    assert_eq!(data["username"], "admin");
    assert_eq!(data["password"], "s3cret");
}

#[tokio::test]
async fn on_token_changed_fires_on_renewal() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/token/renew-self"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "auth": {
                "client_token": "s.new-token",
                "accessor": "acc-new",
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

    let tokens: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let cb_tokens = Arc::clone(&tokens);

    let client = VaultClient::builder()
        .address(&server.uri())
        .token_str("old-token")
        .max_retries(0)
        .on_token_changed(move |auth| {
            cb_tokens
                .lock()
                .unwrap()
                .push(auth.client_token.expose_secret().to_string());
        })
        .build()
        .unwrap();

    // Renew the token via the auth/token/renew-self endpoint
    let renewed = client.auth().token().renew_self(None).await.unwrap();
    assert_eq!(renewed.client_token.expose_secret(), "s.new-token");

    let captured = tokens.lock().unwrap();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0], "s.new-token");
}

fn approle_login() -> AppRoleLogin {
    AppRoleLogin {
        role_id: "r".into(),
        secret_id: SecretString::from("s"),
        mount: "approle".into(),
    }
}

#[tokio::test]
async fn proactive_renewal_is_serialized() {
    let server = MockServer::start().await;

    // Login yields a short-lived, renewable token
    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(auth_response("s.initial", 1)))
        .mount(&server)
        .await;

    // renew-self yields a long-lived token and must be hit exactly once
    Mock::given(method("POST"))
        .and(path("/v1/auth/token/renew-self"))
        .respond_with(ResponseTemplate::new(200).set_body_json(auth_response("s.renewed", 7200)))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/item"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "k": "v" }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::builder()
        .address(&server.uri())
        .max_retries(0)
        .auth_method(approle_login())
        .build()
        .unwrap();

    // First request logs in (lease_duration = 1s)
    let _: HashMap<String, String> = client.kv1("secret").read("item").await.unwrap();

    // Cross the renewal threshold (needs elapsed >= 0.8 * lease)
    tokio::time::sleep(Duration::from_millis(900)).await;

    // Many concurrent callers near expiry must share a single renew-self call
    let mut handles = Vec::new();
    for _ in 0..20 {
        let c = client.clone();
        handles.push(tokio::spawn(async move {
            let _: HashMap<String, String> = c.kv1("secret").read("item").await.unwrap();
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    // renew-self `.expect(1)` is verified when the server drops
}

#[tokio::test]
async fn proactive_renewal_falls_back_to_reauth() {
    let server = MockServer::start().await;

    // Every login yields a short-lived token; used both initially and for the fallback
    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(auth_response("s.fresh", 1)))
        .mount(&server)
        .await;

    // renew-self fails, forcing the fallback to re-authentication
    Mock::given(method("POST"))
        .and(path("/v1/auth/token/renew-self"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "errors": ["permission denied"]
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/item"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "k": "v" }
        })))
        .mount(&server)
        .await;

    let client = VaultClient::builder()
        .address(&server.uri())
        .max_retries(0)
        .auth_method(approle_login())
        .build()
        .unwrap();

    let _: HashMap<String, String> = client.kv1("secret").read("item").await.unwrap();
    tokio::time::sleep(Duration::from_millis(900)).await;

    // renew-self returns 403; the request still succeeds because re-auth kicks in
    let data: HashMap<String, String> = client.kv1("secret").read("item").await.unwrap();
    assert_eq!(data["k"], "v");
}
