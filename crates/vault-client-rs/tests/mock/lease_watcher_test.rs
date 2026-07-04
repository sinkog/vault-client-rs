use std::time::Duration;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::build_test_client;
use vault_client_rs::{LeaseEvent, LeaseWatcher, VaultClient, VaultError};

// The watcher sleeps for ~66% of TTL + 0-5s random jitter before renewing.
// With TTL=1s that's 0.66s + 0-5s = up to 5.66s. We use a generous timeout.
const RECV_TIMEOUT: Duration = Duration::from_secs(10);

async fn recv_timeout(watcher: &mut LeaseWatcher) -> Option<LeaseEvent> {
    tokio::time::timeout(RECV_TIMEOUT, watcher.recv())
        .await
        .ok()
        .flatten()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watch_lease_events_emits_renewed() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/v1/sys/leases/renew"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "lease_id": "database/creds/my-role/abc123",
            "lease_duration": 3600,
            "renewable": true
        })))
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let mut watcher = client.watch_lease_events(
        "database/creds/my-role/abc123".to_owned(),
        Duration::from_secs(1),
    );

    let event = recv_timeout(&mut watcher)
        .await
        .expect("timed out waiting for event");
    match event {
        LeaseEvent::Renewed { lease_id, ttl } => {
            assert_eq!(lease_id, "database/creds/my-role/abc123");
            assert_eq!(ttl, Duration::from_secs(3600));
        }
        other => panic!("expected Renewed, got {:?}", other),
    }

    assert!(watcher.is_running());
    watcher.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watch_lease_events_emits_error_and_expired_on_failure() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/v1/sys/leases/renew"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "errors": ["lease not found"]
        })))
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let mut watcher = client.watch_lease_events(
        "database/creds/my-role/gone".to_owned(),
        Duration::from_secs(1),
    );

    let event = recv_timeout(&mut watcher)
        .await
        .expect("timed out waiting for error");
    assert!(matches!(event, LeaseEvent::Error { .. }));

    let event = recv_timeout(&mut watcher)
        .await
        .expect("timed out waiting for expired");
    assert!(
        matches!(event, LeaseEvent::Expired { lease_id } if lease_id == "database/creds/my-role/gone")
    );

    // Watcher should have stopped
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!watcher.is_running());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watch_lease_rotate_calls_callback_on_renewal_failure() {
    let server = MockServer::start().await;

    // Renewal fails
    Mock::given(method("PUT"))
        .and(path("/v1/sys/leases/renew"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "errors": ["lease expired"]
        })))
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;

    let mut watcher =
        client.watch_lease_rotate(
            "old-lease-id".to_owned(),
            Duration::from_secs(1),
            |_client: VaultClient| async move {
                Ok(("new-lease-id".to_owned(), Duration::from_secs(7200)))
            },
        );

    // First event: Error from failed renewal
    let event = recv_timeout(&mut watcher)
        .await
        .expect("timed out waiting for error");
    assert!(matches!(event, LeaseEvent::Error { .. }));

    // Second event: Rotated with new lease
    let event = recv_timeout(&mut watcher)
        .await
        .expect("timed out waiting for rotated");
    match event {
        LeaseEvent::Rotated { lease_id } => {
            assert_eq!(lease_id, "new-lease-id");
        }
        other => panic!("expected Rotated, got {:?}", other),
    }

    assert!(watcher.is_running());
    watcher.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watch_lease_rotate_emits_expired_after_all_retries_fail() {
    let server = MockServer::start().await;

    // Renewal fails
    Mock::given(method("PUT"))
        .and(path("/v1/sys/leases/renew"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "errors": ["lease expired"]
        })))
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;

    let mut watcher = client.watch_lease_rotate(
        "doomed-lease".to_owned(),
        Duration::from_secs(1),
        |_client: VaultClient| async move {
            Err(VaultError::Config("rotation unavailable".into()))
        },
    );

    // Collect events until channel closes or we get Expired
    let mut got_error = false;
    let mut got_expired = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(RECV_TIMEOUT, watcher.recv()).await {
            Ok(Some(LeaseEvent::Error { .. })) => got_error = true,
            Ok(Some(LeaseEvent::Expired { lease_id })) => {
                assert_eq!(lease_id, "doomed-lease");
                got_expired = true;
                break;
            }
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => break,
        }
    }

    assert!(got_error, "expected at least one Error event");
    assert!(got_expired, "expected Expired event after all retries fail");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watch_lease_events_cancels_on_drop() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/v1/sys/leases/renew"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "lease_id": "some-lease",
            "lease_duration": 3600,
            "renewable": true
        })))
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let watcher = client.watch_lease_events("some-lease".to_owned(), Duration::from_secs(100));

    assert!(watcher.is_running());
    drop(watcher); // Should cancel the background task

    // Give the runtime a chance to process the cancellation
    tokio::task::yield_now().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_interrupts_in_flight_renewal() {
    let server = MockServer::start().await;

    // Renewal hangs long enough that shutdown must interrupt it, not wait it out
    Mock::given(method("PUT"))
        .and(path("/v1/sys/leases/renew"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "lease_id": "l",
                    "lease_duration": 3600,
                    "renewable": true
                }))
                .set_delay(Duration::from_secs(20)),
        )
        .mount(&server)
        .await;

    let client = build_test_client(&server).await;
    let watcher = client.watch_lease_events("l".to_owned(), Duration::from_secs(1));

    // Initial sleep is at most 0.66s + 5s jitter, so by 6s the daemon is inside the
    // delayed renew call
    tokio::time::sleep(Duration::from_secs(6)).await;

    let start = std::time::Instant::now();
    watcher.shutdown().await;
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(3),
        "shutdown should interrupt the in-flight renewal promptly, took {elapsed:?}"
    );
}
