//! Coverage for the `VaultError::Http` arm of `is_retryable()`, which needs a
//! real `reqwest::Error` (transport-level failure) that can't be constructed
//! synthetically. A connection to a closed local port yields a deterministic
//! connect error, exercising `e.is_timeout() || e.is_connect()`.

use vault_client_rs::types::error::VaultError;

#[tokio::test]
async fn http_transport_error_is_retryable() {
    // Port 1 is never listening — this fails fast with a connect error.
    let reqwest_err = reqwest::Client::new()
        .get("http://127.0.0.1:1/")
        .send()
        .await
        .expect_err("request to a closed port must fail");

    // Sanity: it really is a connect (or timeout) error, so the retryable arm
    // should return true — killing both the "delete arm" and "|| -> &&" mutants.
    assert!(
        reqwest_err.is_connect() || reqwest_err.is_timeout(),
        "expected a connect/timeout transport error, got: {reqwest_err:?}"
    );

    let err = VaultError::from(reqwest_err);
    assert!(matches!(err, VaultError::Http(_)));
    assert!(
        err.is_retryable(),
        "a transport-level Http error must be retryable"
    );
    // Http errors carry no HTTP status.
    assert_eq!(err.status_code(), None);
}
