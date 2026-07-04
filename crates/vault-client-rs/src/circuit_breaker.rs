use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::types::error::VaultError;

/// Configuration for the client-side circuit breaker
///
/// When enabled, the circuit breaker tracks consecutive failures and
/// short-circuits requests during prolonged outages, reducing latency
/// and load on an unreachable Vault server
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Consecutive failures required to trip the circuit (default: 5)
    pub failure_threshold: u32,
    /// Time in Open state before allowing a probe request (default: 30s)
    pub reset_timeout: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            reset_timeout: Duration::from_secs(30),
        }
    }
}

enum State {
    Closed { consecutive_failures: u32 },
    Open { since: Instant },
    HalfOpen { since: Instant },
}

pub(crate) struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: Mutex<State>,
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: Mutex::new(State::Closed {
                consecutive_failures: 0,
            }),
        }
    }

    /// Returns `Ok(())` if a request may proceed, or
    /// `Err(VaultError::CircuitOpen)` if the circuit is open
    pub fn check(&self) -> Result<(), VaultError> {
        let mut state = self.state.lock().map_err(|_| VaultError::LockPoisoned)?;
        match *state {
            State::Closed { .. } => Ok(()),
            // A stale half-open (its probe future was cancelled before recording a
            // result) is treated like open, so a fresh probe is admitted after reset_timeout
            State::Open { since } | State::HalfOpen { since } => {
                if since.elapsed() >= self.config.reset_timeout {
                    *state = State::HalfOpen {
                        since: Instant::now(),
                    };
                    Ok(())
                } else {
                    Err(VaultError::CircuitOpen)
                }
            }
        }
    }

    /// Record a successful response, resetting the circuit to Closed
    pub fn record_success(&self) {
        if let Ok(mut state) = self.state.lock() {
            *state = State::Closed {
                consecutive_failures: 0,
            };
        }
    }

    /// Record a failure, incrementing the counter and potentially
    /// transitioning to Open
    pub fn record_failure(&self) {
        if let Ok(mut state) = self.state.lock() {
            match *state {
                State::Closed {
                    consecutive_failures,
                } => {
                    let new_count = consecutive_failures + 1;
                    if new_count >= self.config.failure_threshold {
                        *state = State::Open {
                            since: Instant::now(),
                        };
                    } else {
                        *state = State::Closed {
                            consecutive_failures: new_count,
                        };
                    }
                }
                State::HalfOpen { .. } => {
                    // Probe failed, back to Open
                    *state = State::Open {
                        since: Instant::now(),
                    };
                }
                State::Open { .. } => {
                    // Already open, nothing to do
                }
            }
        }
    }
}
