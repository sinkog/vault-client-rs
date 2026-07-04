use std::future::Future;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::VaultClient;
use crate::types::error::VaultError;

/// Minimum sleep between lease renewal attempts to prevent busy-looping
/// when Vault returns a zero or very short TTL
const MIN_RENEWAL_SLEEP: Duration = Duration::from_secs(1);

/// Race a future against cancellation, returning `None` if cancelled first
///
/// Lets `shutdown()` and `Drop` interrupt an in-flight call, including its
/// internal retries, instead of only being observed between sleep cycles
async fn race_cancel<F: Future>(fut: F, cancel: &CancellationToken) -> Option<F::Output> {
    tokio::select! {
        result = fut => Some(result),
        () = cancel.cancelled() => None,
    }
}

/// Handle to a background renewal task, cancelled on drop
pub struct RenewalDaemon {
    cancel: CancellationToken,
    handle: Option<JoinHandle<()>>,
}

impl RenewalDaemon {
    /// Stop the background task and wait for it to finish
    pub async fn shutdown(mut self) {
        self.cancel.cancel();
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }

    /// Check whether the background task is still running
    pub fn is_running(&self) -> bool {
        self.handle.as_ref().is_some_and(|h| !h.is_finished())
    }
}

impl Drop for RenewalDaemon {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl VaultClient {
    /// Spawn a background task that renews the client token before expiry
    ///
    /// The daemon sleeps until ~2/3 of the current lease duration, then
    /// calls `auth/token/renew-self`. If renewal fails and an auth method
    /// is configured, it attempts re-authentication
    ///
    /// Returns a handle that cancels the task on drop
    pub fn start_token_renewal(&self) -> RenewalDaemon {
        let client = self.clone();
        let cancel = CancellationToken::new();
        let token = cancel.clone();

        let handle = tokio::spawn(async move {
            loop {
                let sleep_dur = {
                    let guard = match client.inner.token.read() {
                        Ok(g) => g,
                        Err(_) => {
                            tracing::error!("token lock poisoned, stopping renewal");
                            break;
                        }
                    };
                    match guard.as_ref() {
                        Some(ts) if ts.renewable && ts.lease_duration > Duration::ZERO => {
                            let base = ts.lease_duration.mul_f64(0.66);
                            let jitter_ms = rand::random::<u64>() % 5000;
                            base + Duration::from_millis(jitter_ms)
                        }
                        _ => Duration::from_secs(60),
                    }
                };

                tokio::select! {
                    () = tokio::time::sleep(sleep_dur) => {
                        match race_cancel(client.renew_token_now(), &token).await {
                            Some(Ok(())) => {}
                            Some(Err(e)) => {
                                tracing::error!(error = %e, "background token renewal failed");
                                // Try re-authentication as fallback
                                if let Some(Err(e2)) = race_cancel(client.try_re_authenticate(), &token).await {
                                    tracing::error!(error = %e2, "re-authentication also failed");
                                }
                            }
                            None => break,
                        }
                    }
                    () = token.cancelled() => break,
                }
            }
        });

        RenewalDaemon {
            cancel,
            handle: Some(handle),
        }
    }

    /// Spawn a background task that watches a specific lease and renews it
    /// before expiry
    ///
    /// Useful for database credentials, dynamic AWS creds, etc
    /// Returns a handle that cancels the watcher on drop
    pub fn watch_lease(&self, lease_id: String, ttl: Duration) -> RenewalDaemon {
        let client = self.clone();
        let cancel = CancellationToken::new();
        let token = cancel.clone();

        let handle = tokio::spawn(async move {
            let mut current_ttl = ttl;
            loop {
                let base = current_ttl.mul_f64(0.66);
                let jitter_ms = rand::random::<u64>() % 5000;
                let sleep_dur = (base + Duration::from_millis(jitter_ms)).max(MIN_RENEWAL_SLEEP);

                tokio::select! {
                    () = tokio::time::sleep(sleep_dur) => {
                        match race_cancel(client.sys().renew_lease(&lease_id, None), &token).await {
                            Some(Ok(info)) => {
                                current_ttl = Duration::from_secs(info.lease_duration);
                                tracing::debug!(lease_id = %lease_id, ttl = ?current_ttl, "lease renewed");
                            }
                            Some(Err(e)) => {
                                tracing::error!(lease_id = %lease_id, error = %e, "lease renewal failed");
                                break;
                            }
                            None => break,
                        }
                    }
                    () = token.cancelled() => break,
                }
            }
        });

        RenewalDaemon {
            cancel,
            handle: Some(handle),
        }
    }

    /// Perform an immediate token renewal via POST auth/token/renew-self
    pub async fn renew_token_now(&self) -> Result<(), VaultError> {
        self.renew_token_via_api().await
    }

    /// Spawn a background task that watches a lease and emits [`LeaseEvent`]s
    /// on each renewal, error, or expiry
    ///
    /// Unlike [`watch_lease`](Self::watch_lease) (which only logs), this
    /// variant lets callers react programmatically via the returned
    /// [`LeaseWatcher`]
    pub fn watch_lease_events(&self, lease_id: String, ttl: Duration) -> LeaseWatcher {
        let client = self.clone();
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        let (tx, rx) = mpsc::channel(16);

        let handle = tokio::spawn(async move {
            let mut current_ttl = ttl;
            loop {
                let base = current_ttl.mul_f64(0.66);
                let jitter_ms = rand::random::<u64>() % 5000;
                let sleep_dur = (base + Duration::from_millis(jitter_ms)).max(MIN_RENEWAL_SLEEP);

                tokio::select! {
                    () = tokio::time::sleep(sleep_dur) => {
                        match race_cancel(client.sys().renew_lease(&lease_id, None), &token).await {
                            Some(Ok(info)) => {
                                current_ttl = Duration::from_secs(info.lease_duration);
                                let _ = tx.send(LeaseEvent::Renewed {
                                    lease_id: lease_id.clone(),
                                    ttl: current_ttl,
                                }).await;
                            }
                            Some(Err(e)) => {
                                let _ = tx.send(LeaseEvent::Error {
                                    lease_id: lease_id.clone(),
                                    error: e.to_string(),
                                }).await;
                                let _ = tx.send(LeaseEvent::Expired {
                                    lease_id: lease_id.clone(),
                                }).await;
                                break;
                            }
                            None => break,
                        }
                    }
                    () = token.cancelled() => break,
                }
            }
        });

        LeaseWatcher {
            cancel,
            handle: Some(handle),
            rx,
        }
    }

    /// Like [`watch_lease_events`](Self::watch_lease_events), but when renewal
    /// fails, calls `rotate_fn` to obtain fresh credentials instead of giving up
    ///
    /// `rotate_fn` receives a clone of the client and should return the new
    /// `(lease_id, ttl)`. If rotation also fails after 3 retries with
    /// exponential back-off, a [`LeaseEvent::Expired`] is emitted
    pub fn watch_lease_rotate<F, Fut>(
        &self,
        lease_id: String,
        ttl: Duration,
        rotate_fn: F,
    ) -> LeaseWatcher
    where
        F: Fn(VaultClient) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(String, Duration), VaultError>> + Send,
    {
        let client = self.clone();
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        let (tx, rx) = mpsc::channel(16);

        let handle = tokio::spawn(async move {
            let mut current_lease = lease_id;
            let mut current_ttl = ttl;

            loop {
                let base = current_ttl.mul_f64(0.66);
                let jitter_ms = rand::random::<u64>() % 5000;
                let sleep_dur = (base + Duration::from_millis(jitter_ms)).max(MIN_RENEWAL_SLEEP);

                tokio::select! {
                    () = tokio::time::sleep(sleep_dur) => {
                        let renew_result = match race_cancel(
                            client.sys().renew_lease(&current_lease, None),
                            &token,
                        ).await {
                            Some(r) => r,
                            None => break,
                        };

                        match renew_result {
                            Ok(info) => {
                                current_ttl = Duration::from_secs(info.lease_duration);
                                let _ = tx.send(LeaseEvent::Renewed {
                                    lease_id: current_lease.clone(),
                                    ttl: current_ttl,
                                }).await;
                            }
                            Err(renew_err) => {
                                let _ = tx.send(LeaseEvent::Error {
                                    lease_id: current_lease.clone(),
                                    error: renew_err.to_string(),
                                }).await;

                                // Attempt rotation with retries
                                let mut rotated = false;
                                let mut cancelled = false;
                                for attempt in 0u32..3 {
                                    if attempt > 0 {
                                        let backoff = Duration::from_millis(500 * 2u64.pow(attempt));
                                        if race_cancel(tokio::time::sleep(backoff), &token).await.is_none() {
                                            cancelled = true;
                                            break;
                                        }
                                    }
                                    match race_cancel(rotate_fn(client.clone()), &token).await {
                                        Some(Ok((new_lease, new_ttl))) => {
                                            let _ = tx.send(LeaseEvent::Rotated {
                                                lease_id: new_lease.clone(),
                                            }).await;
                                            current_lease = new_lease;
                                            current_ttl = new_ttl;
                                            rotated = true;
                                            break;
                                        }
                                        Some(Err(e)) => {
                                            tracing::warn!(
                                                attempt = attempt + 1,
                                                error = %e,
                                                "rotation attempt failed"
                                            );
                                        }
                                        None => {
                                            cancelled = true;
                                            break;
                                        }
                                    }
                                }

                                if cancelled {
                                    break;
                                }

                                if !rotated {
                                    let _ = tx.send(LeaseEvent::Expired {
                                        lease_id: current_lease.clone(),
                                    }).await;
                                    break;
                                }
                            }
                        }
                    }
                    () = token.cancelled() => break,
                }
            }
        });

        LeaseWatcher {
            cancel,
            handle: Some(handle),
            rx,
        }
    }
}

// ---------------------------------------------------------------------------
// LeaseEvent + LeaseWatcher
// ---------------------------------------------------------------------------

/// Events emitted by [`LeaseWatcher`]
#[derive(Debug, Clone)]
pub enum LeaseEvent {
    /// Lease was successfully renewed
    Renewed { lease_id: String, ttl: Duration },
    /// A renewal or rotation attempt encountered an error
    Error { lease_id: String, error: String },
    /// The lease could not be renewed or rotated and has expired
    Expired { lease_id: String },
    /// The lease was replaced by a fresh credential via the rotation callback
    Rotated { lease_id: String },
}

/// Handle to a background lease-watching task that produces [`LeaseEvent`]s
///
/// The background task is cancelled when this handle is dropped
pub struct LeaseWatcher {
    cancel: CancellationToken,
    handle: Option<JoinHandle<()>>,
    rx: mpsc::Receiver<LeaseEvent>,
}

impl LeaseWatcher {
    /// Receive the next event, waiting if necessary
    pub async fn recv(&mut self) -> Option<LeaseEvent> {
        self.rx.recv().await
    }

    /// Try to receive an event without blocking
    pub fn try_recv(&mut self) -> Option<LeaseEvent> {
        self.rx.try_recv().ok()
    }

    /// Cancel the background task and wait for it to finish
    pub async fn shutdown(mut self) {
        self.cancel.cancel();
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }

    /// Check whether the background task is still running
    pub fn is_running(&self) -> bool {
        self.handle.as_ref().is_some_and(|h| !h.is_finished())
    }
}

impl Drop for LeaseWatcher {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
