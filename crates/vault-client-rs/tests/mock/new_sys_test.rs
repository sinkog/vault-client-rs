use secrecy::{ExposeSecret, SecretString};
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::build_test_client;
use vault_client_rs::VaultError;
use vault_client_rs::types::sys::*;

#[tokio::test]
async fn list_plugins() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/sys/plugins/catalog/auth"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["approle", "token", "userpass"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let plugins = client.sys().list_plugins("auth").await.unwrap();
    assert_eq!(plugins, vec!["approle", "token", "userpass"]);
}

#[tokio::test]
async fn read_plugin() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/plugins/catalog/auth/approle"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "name": "approle",
                "command": "approle",
                "args": [],
                "sha256": "abc123def456",
                "version": "v1.0.0",
                "builtin": true
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let info = client.sys().read_plugin("auth", "approle").await.unwrap();
    assert_eq!(info.name, "approle");
    assert_eq!(info.command, "approle");
    assert_eq!(info.sha256, "abc123def456");
    assert!(info.builtin);
}

#[tokio::test]
async fn register_plugin() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/plugins/catalog/auth/my-plugin"))
        .and(body_json(serde_json::json!({
            "name": "my-plugin",
            "type": "auth",
            "command": "my-plugin-bin",
            "sha256": "deadbeef1234567890"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = RegisterPluginRequest {
        name: "my-plugin".into(),
        plugin_type: "auth".into(),
        command: "my-plugin-bin".into(),
        sha256: "deadbeef1234567890".into(),
        args: None,
        env: None,
        version: None,
    };
    client.sys().register_plugin(&params).await.unwrap();
}

#[tokio::test]
async fn deregister_plugin() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/sys/plugins/catalog/auth/my-plugin"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .sys()
        .deregister_plugin("auth", "my-plugin")
        .await
        .unwrap();
}

#[tokio::test]
async fn reload_plugin() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/v1/sys/plugins/reload/backend"))
        .and(body_json(serde_json::json!({"plugin": "my-plugin"})))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.sys().reload_plugin("my-plugin").await.unwrap();
}

#[tokio::test]
async fn raft_config() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/storage/raft/configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "servers": [
                    {"node_id": "node1", "address": "10.0.0.1:8201", "leader": true, "voter": true},
                    {"node_id": "node2", "address": "10.0.0.2:8201", "leader": false, "voter": true}
                ],
                "index": 42
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let config = client.sys().raft_config().await.unwrap();
    assert_eq!(config.servers.len(), 2);
    assert_eq!(config.servers[0].node_id, "node1");
    assert!(config.servers[0].leader);
    assert_eq!(config.index, 42);
}

#[tokio::test]
async fn raft_autopilot_state() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/storage/raft/autopilot/state"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "healthy": true,
                "failure_tolerance": 1,
                "leader": "node1",
                "voters": ["node1", "node2"],
                "servers": {
                    "node1": {
                        "id": "node1",
                        "name": "node1",
                        "address": "10.0.0.1:8201",
                        "node_status": "alive",
                        "status": "leader",
                        "healthy": true,
                        "last_contact": "0s",
                        "last_index": 100,
                        "last_term": 3,
                        "voter": true,
                        "leader": true
                    }
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let state = client.sys().raft_autopilot_state().await.unwrap();
    assert!(state.healthy);
    assert_eq!(state.leader, "node1");
}

#[tokio::test]
async fn raft_remove_peer() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/storage/raft/remove-peer"))
        .and(body_json(serde_json::json!({"server_id": "node1"})))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.sys().raft_remove_peer("node1").await.unwrap();
}

#[tokio::test]
async fn raft_snapshot_restore_success() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/storage/raft/snapshot"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .sys()
        .raft_snapshot_restore(b"fake snapshot bytes")
        .await
        .unwrap();
}

#[tokio::test]
async fn raft_snapshot_restore_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/storage/raft/snapshot"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "errors": ["invalid snapshot"]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let err = client
        .sys()
        .raft_snapshot_restore(b"corrupt")
        .await
        .unwrap_err();
    match err {
        VaultError::Api { status, errors } => {
            assert_eq!(status, 400);
            assert_eq!(errors, vec!["invalid snapshot".to_string()]);
        }
        other => panic!("expected VaultError::Api, got {other:?}"),
    }
}

#[tokio::test]
async fn list_namespaces() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/sys/namespaces"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["child-ns/", "another-ns/"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let namespaces = client.sys().list_namespaces().await.unwrap();
    assert_eq!(namespaces, vec!["child-ns/", "another-ns/"]);
}

#[tokio::test]
async fn create_namespace() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/namespaces/child-ns"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "id": "ns-id-123",
                "path": "child-ns/"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let ns = client.sys().create_namespace("child-ns").await.unwrap();
    assert_eq!(ns.id, "ns-id-123");
    assert_eq!(ns.path, "child-ns/");
}

#[tokio::test]
async fn delete_namespace() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/sys/namespaces/child-ns"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.sys().delete_namespace("child-ns").await.unwrap();
}

#[tokio::test]
async fn list_rate_limit_quotas() {
    let server = MockServer::start().await;

    Mock::given(method("LIST"))
        .and(path("/v1/sys/quotas/rate-limit"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {"keys": ["my-quota", "global-quota"]}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let quotas = client.sys().list_rate_limit_quotas().await.unwrap();
    assert_eq!(quotas, vec!["my-quota", "global-quota"]);
}

#[tokio::test]
async fn read_rate_limit_quota() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/quotas/rate-limit/my-quota"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "name": "my-quota",
                "rate": 100.0,
                "burst": 200,
                "path": "",
                "interval": null,
                "block_interval": null,
                "role": null,
                "type": "rate-limit"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let quota = client
        .sys()
        .read_rate_limit_quota("my-quota")
        .await
        .unwrap();
    assert_eq!(quota.name, "my-quota");
    assert_eq!(quota.rate, 100.0);
}

#[tokio::test]
async fn write_rate_limit_quota() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/quotas/rate-limit/my-quota"))
        .and(body_json(serde_json::json!({
            "name": "my-quota",
            "rate": 50.0
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = RateLimitQuotaRequest {
        name: "my-quota".into(),
        rate: 50.0,
        ..Default::default()
    };
    client
        .sys()
        .write_rate_limit_quota("my-quota", &params)
        .await
        .unwrap();
}

#[tokio::test]
async fn delete_rate_limit_quota() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/sys/quotas/rate-limit/my-quota"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client
        .sys()
        .delete_rate_limit_quota("my-quota")
        .await
        .unwrap();
}

#[tokio::test]
async fn rekey_init() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/v1/sys/rekey/init"))
        .and(body_json(serde_json::json!({
            "secret_shares": 5,
            "secret_threshold": 3
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "started": true,
            "nonce": "abc-nonce-123",
            "t": 3,
            "n": 5,
            "progress": 0,
            "required": 3,
            "pgp_finger_prints": null,
            "backup": false,
            "verification_required": false,
            "complete": false,
            "keys": null,
            "keys_base64": null
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = RekeyInitRequest {
        secret_shares: 5,
        secret_threshold: 3,
        pgp_keys: None,
        backup: None,
    };
    let status = client.sys().rekey_init(&params).await.unwrap();
    assert!(status.started);
    assert_eq!(status.nonce, "abc-nonce-123");
    assert_eq!(status.n, 5);
    assert_eq!(status.t, 3);
}

#[tokio::test]
async fn rekey_status() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/rekey/init"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "started": false,
            "nonce": "",
            "t": 0,
            "n": 0,
            "progress": 0,
            "required": 3,
            "pgp_finger_prints": null,
            "backup": false,
            "verification_required": false,
            "complete": false,
            "keys": null,
            "keys_base64": null
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let status = client.sys().rekey_status().await.unwrap();
    assert!(!status.started);
    assert_eq!(status.nonce, "");
}

#[tokio::test]
async fn rekey_cancel() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/sys/rekey/init"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.sys().rekey_cancel().await.unwrap();
}

#[tokio::test]
async fn generate_root_status() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/generate-root/attempt"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "started": true,
            "nonce": "root-nonce-456",
            "progress": 1,
            "required": 3,
            "complete": false,
            "encoded_token": null,
            "encoded_root_token": null,
            "otp_length": 24,
            "otp": null
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let status = client.sys().generate_root_status().await.unwrap();
    assert!(status.started);
    assert_eq!(status.nonce, "root-nonce-456");
    assert_eq!(status.progress, 1);
    assert_eq!(status.required, 3);
}

#[tokio::test]
async fn remount() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/remount"))
        .and(body_json(serde_json::json!({"from": "old/", "to": "new/"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "migration_id": "mig-abc-123"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let status = client.sys().remount("old/", "new/").await.unwrap();
    assert_eq!(status.migration_id, "mig-abc-123");
}

#[tokio::test]
async fn host_info() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/host-info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "timestamp": "2025-06-15T10:30:00Z",
                "cpu": [{"cpu": 0, "vendorId": "GenuineIntel"}],
                "disk": null,
                "host": null,
                "memory": null
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let info = client.sys().host_info().await.unwrap();
    assert_eq!(info.timestamp, "2025-06-15T10:30:00Z");
    assert!(info.cpu.is_some());
}

#[tokio::test]
async fn version_history() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/version-history"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "keys": ["1.16.0", "1.17.3"],
                "key_info": {
                    "1.16.0": {
                        "timestamp_installed": "2025-01-01T00:00:00Z",
                        "build_date": "2024-12-15T00:00:00Z",
                        "previous_version": null
                    },
                    "1.17.3": {
                        "timestamp_installed": "2025-06-01T00:00:00Z",
                        "build_date": "2025-05-20T00:00:00Z",
                        "previous_version": "1.16.0"
                    }
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let history = client.sys().version_history().await.unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].version, "1.16.0");
    assert_eq!(history[1].version, "1.17.3");
}

#[tokio::test]
async fn rewrap() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/wrapping/rewrap"))
        .and(body_json(serde_json::json!({"token": "s.original-wrap"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "wrap_info": {
                "token": "s.new-wrap-token",
                "accessor": "acc-rewrap",
                "ttl": 300,
                "creation_time": "2025-06-15T10:30:00Z",
                "creation_path": "sys/wrapping/rewrap"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let info = client
        .sys()
        .rewrap(&SecretString::from("s.original-wrap"))
        .await
        .unwrap();
    assert_eq!(info.accessor, "acc-rewrap");
    assert_eq!(info.ttl, 300);
    assert_eq!(info.token.expose_secret(), "s.new-wrap-token");
}

#[tokio::test]
async fn in_flight_requests() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/in-flight-req"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "req-uuid-1": {
                "request_id": "req-uuid-1",
                "request_path": "/v1/secret/data/test",
                "client_address": "127.0.0.1:52000",
                "start_time": "2025-06-15T10:30:00Z"
            },
            "req-uuid-2": {
                "request_id": "req-uuid-2",
                "request_path": "/v1/sys/health",
                "client_address": "127.0.0.1:52001",
                "start_time": "2025-06-15T10:30:01Z"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let reqs = client.sys().in_flight_requests().await.unwrap();
    assert_eq!(reqs.len(), 2);

    let r1 = &reqs["req-uuid-1"];
    assert_eq!(r1.request_path, "/v1/secret/data/test");
    assert_eq!(r1.client_address, "127.0.0.1:52000");

    let r2 = &reqs["req-uuid-2"];
    assert_eq!(r2.request_path, "/v1/sys/health");
}

#[tokio::test]
async fn rekey_update() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/v1/sys/rekey/update"))
        .and(body_json(serde_json::json!({
            "key": "unseal-key-1",
            "nonce": "abc-nonce-123"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "started": true,
            "nonce": "abc-nonce-123",
            "t": 3,
            "n": 5,
            "progress": 1,
            "required": 3,
            "pgp_finger_prints": null,
            "backup": false,
            "verification_required": false,
            "complete": false,
            "keys": null,
            "keys_base64": null
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let key = SecretString::from("unseal-key-1");
    let status = client
        .sys()
        .rekey_update(&key, "abc-nonce-123")
        .await
        .unwrap();
    assert!(status.started);
    assert_eq!(status.nonce, "abc-nonce-123");
    assert_eq!(status.progress, 1);
    assert_eq!(status.required, 3);
    assert!(!status.complete);
    assert!(status.keys.is_none());
}

#[tokio::test]
async fn rekey_update_complete() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/v1/sys/rekey/update"))
        .and(body_json(serde_json::json!({
            "key": "unseal-key-3",
            "nonce": "abc-nonce-123"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "started": true,
            "nonce": "abc-nonce-123",
            "t": 3,
            "n": 5,
            "progress": 3,
            "required": 3,
            "pgp_finger_prints": null,
            "backup": false,
            "verification_required": false,
            "complete": true,
            "keys": ["new-key-1", "new-key-2", "new-key-3", "new-key-4", "new-key-5"],
            "keys_base64": ["bmV3LWtleS0x", "bmV3LWtleS0y", "bmV3LWtleS0z", "bmV3LWtleS00", "bmV3LWtleS01"]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let key = SecretString::from("unseal-key-3");
    let status = client
        .sys()
        .rekey_update(&key, "abc-nonce-123")
        .await
        .unwrap();
    assert!(status.complete);
    assert_eq!(status.progress, 3);
    let keys = status
        .keys
        .as_ref()
        .expect("keys should be present on completion");
    assert_eq!(keys.len(), 5);
    assert_eq!(keys[0].expose_secret(), "new-key-1");
    let keys_b64 = status
        .keys_base64
        .as_ref()
        .expect("keys_base64 should be present on completion");
    assert_eq!(keys_b64.len(), 5);
}

#[tokio::test]
async fn generate_root_init() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/v1/sys/generate-root/attempt"))
        .and(body_json(serde_json::json!({})))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "started": true,
            "nonce": "root-init-nonce-789",
            "progress": 0,
            "required": 3,
            "complete": false,
            "encoded_token": null,
            "encoded_root_token": null,
            "otp_length": 24,
            "otp": "Fz4k2CBRGBHAQ9mt4sdn6Q=="
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = GenerateRootInitRequest::default();
    let status = client.sys().generate_root_init(&params).await.unwrap();
    assert!(status.started);
    assert_eq!(status.nonce, "root-init-nonce-789");
    assert_eq!(status.progress, 0);
    assert_eq!(status.required, 3);
    assert!(!status.complete);
    assert_eq!(status.otp_length, Some(24));
    assert_eq!(
        status.otp.as_ref().unwrap().expose_secret(),
        "Fz4k2CBRGBHAQ9mt4sdn6Q=="
    );
}

#[tokio::test]
async fn generate_root_init_with_pgp_key() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/v1/sys/generate-root/attempt"))
        .and(body_json(serde_json::json!({
            "pgp_key": "mQENBF..."
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "started": true,
            "nonce": "pgp-nonce-abc",
            "progress": 0,
            "required": 3,
            "complete": false,
            "encoded_token": null,
            "encoded_root_token": null,
            "otp_length": null,
            "otp": null
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let params = GenerateRootInitRequest {
        pgp_key: Some("mQENBF...".into()),
    };
    let status = client.sys().generate_root_init(&params).await.unwrap();
    assert!(status.started);
    assert_eq!(status.nonce, "pgp-nonce-abc");
    assert!(status.otp.is_none());
    assert!(status.otp_length.is_none());
}

#[tokio::test]
async fn generate_root_cancel() {
    let server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/v1/sys/generate-root/attempt"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    client.sys().generate_root_cancel().await.unwrap();
}

#[tokio::test]
async fn generate_root_update() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/v1/sys/generate-root/update"))
        .and(body_json(serde_json::json!({
            "key": "unseal-key-1",
            "nonce": "root-nonce-456"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "started": true,
            "nonce": "root-nonce-456",
            "progress": 1,
            "required": 3,
            "complete": false,
            "encoded_token": null,
            "encoded_root_token": null,
            "otp_length": 24,
            "otp": null
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let key = SecretString::from("unseal-key-1");
    let status = client
        .sys()
        .generate_root_update(&key, "root-nonce-456")
        .await
        .unwrap();
    assert!(status.started);
    assert_eq!(status.nonce, "root-nonce-456");
    assert_eq!(status.progress, 1);
    assert_eq!(status.required, 3);
    assert!(!status.complete);
    assert!(status.encoded_token.is_none());
}

#[tokio::test]
async fn generate_root_update_complete() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/v1/sys/generate-root/update"))
        .and(body_json(serde_json::json!({
            "key": "unseal-key-3",
            "nonce": "root-nonce-456"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "started": true,
            "nonce": "root-nonce-456",
            "progress": 3,
            "required": 3,
            "complete": true,
            "encoded_token": "encoded-new-root-token",
            "encoded_root_token": "encoded-new-root-token",
            "otp_length": 24,
            "otp": null
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let key = SecretString::from("unseal-key-3");
    let status = client
        .sys()
        .generate_root_update(&key, "root-nonce-456")
        .await
        .unwrap();
    assert!(status.complete);
    assert_eq!(status.progress, 3);
    assert_eq!(
        status.encoded_token.as_ref().unwrap().expose_secret(),
        "encoded-new-root-token"
    );
    assert_eq!(
        status.encoded_root_token.as_ref().unwrap().expose_secret(),
        "encoded-new-root-token"
    );
}

#[tokio::test]
async fn metrics_json() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/metrics"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Timestamp": "2025-06-15T10:30:00Z",
            "Gauges": [
                {"Name": "vault.runtime.alloc_bytes", "Value": 123456, "Labels": {}},
                {"Name": "vault.runtime.num_goroutines", "Value": 42, "Labels": {}}
            ],
            "Counters": [
                {"Name": "vault.audit.log_response", "Count": 1000, "Sum": 1000.0, "Min": 1.0, "Max": 1.0, "Mean": 1.0, "Labels": {}}
            ],
            "Samples": [],
            "Points": []
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let metrics = client.sys().metrics_json().await.unwrap();
    assert_eq!(metrics["Timestamp"], "2025-06-15T10:30:00Z");

    let gauges = metrics["Gauges"]
        .as_array()
        .expect("Gauges should be an array");
    assert_eq!(gauges.len(), 2);
    assert_eq!(gauges[0]["Name"], "vault.runtime.alloc_bytes");
    assert_eq!(gauges[0]["Value"], 123456);

    let counters = metrics["Counters"]
        .as_array()
        .expect("Counters should be an array");
    assert_eq!(counters.len(), 1);
    assert_eq!(counters[0]["Name"], "vault.audit.log_response");
    assert_eq!(counters[0]["Count"], 1000);
}

#[tokio::test]
async fn internal_counters_activity() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/internal/counters/activity"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "start_time": "2025-01-01T00:00:00Z",
                "end_time": "2025-06-15T23:59:59Z",
                "total": {
                    "clients": 150,
                    "entity_clients": 100,
                    "non_entity_clients": 50
                },
                "by_namespace": [
                    {
                        "namespace_id": "root",
                        "namespace_path": "",
                        "counts": {
                            "clients": 150,
                            "entity_clients": 100,
                            "non_entity_clients": 50
                        }
                    }
                ],
                "months": [
                    {
                        "timestamp": "2025-06-01T00:00:00Z",
                        "counts": {
                            "clients": 30,
                            "entity_clients": 20,
                            "non_entity_clients": 10
                        }
                    }
                ]
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let activity = client.sys().internal_counters_activity().await.unwrap();
    assert_eq!(activity["start_time"], "2025-01-01T00:00:00Z");
    assert_eq!(activity["end_time"], "2025-06-15T23:59:59Z");
    assert_eq!(activity["total"]["clients"], 150);
    assert_eq!(activity["total"]["entity_clients"], 100);
    assert_eq!(activity["total"]["non_entity_clients"], 50);

    let namespaces = activity["by_namespace"]
        .as_array()
        .expect("by_namespace should be an array");
    assert_eq!(namespaces.len(), 1);
    assert_eq!(namespaces[0]["namespace_id"], "root");

    let months = activity["months"]
        .as_array()
        .expect("months should be an array");
    assert_eq!(months.len(), 1);
    assert_eq!(months[0]["counts"]["clients"], 30);
}
