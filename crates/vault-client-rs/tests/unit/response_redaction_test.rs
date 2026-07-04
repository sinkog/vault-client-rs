use std::collections::HashMap;
use std::fmt;

use proptest::prelude::*;
use vault_client_rs::{
    AwsCredentials, AzureCredentials, ConsulCredentials, DatabaseCredentials, GcpServiceAccountKey,
    KvReadResponse, NomadCredentials, RedactionLevel, SshSignedKey, TerraformCloudToken, TotpCode,
    TransitDataKey, TransitExportedKey, VaultResponse, set_redaction_level,
};

const SENTINEL: &str = "super-secret-sentinel-value";

// Full must hide the secret and None must reveal it. The None direction is what
// distinguishes a redacting Debug impl from `SecretString`'s own always-redacted Debug,
// so it catches a manual impl being lost to a plain derive
fn assert_respects_redaction(value: &impl fmt::Debug, label: &str) {
    set_redaction_level(RedactionLevel::None);
    let revealed = format!("{value:?}");
    assert!(
        revealed.contains(SENTINEL),
        "{label} should reveal at None: {revealed}"
    );

    set_redaction_level(RedactionLevel::Full);
    let hidden = format!("{value:?}");
    assert!(
        !hidden.contains(SENTINEL),
        "{label} should redact at Full: {hidden}"
    );
}

fn vault_response_with(secret: &str) -> VaultResponse<HashMap<String, String>> {
    let json = serde_json::json!({
        "request_id": "req-1",
        "data": { "password": secret },
    });
    serde_json::from_value(json).unwrap()
}

fn kv_read_response_with(secret: &str) -> KvReadResponse<HashMap<String, String>> {
    let json = serde_json::json!({
        "data": { "password": secret },
        "metadata": {
            "created_time": "2025-01-01T00:00:00Z",
            "custom_metadata": null,
            "deletion_time": "",
            "destroyed": false,
            "version": 1
        }
    });
    serde_json::from_value(json).unwrap()
}

#[test]
fn vault_response_debug_redacts_data_at_full() {
    set_redaction_level(RedactionLevel::Full);
    let resp = vault_response_with(SENTINEL);
    let debug = format!("{resp:?}");
    assert!(debug.contains("VaultResponse"));
    assert!(!debug.contains(SENTINEL), "secret leaked: {debug}");
}

#[test]
fn vault_response_debug_shows_data_at_none() {
    set_redaction_level(RedactionLevel::None);
    let resp = vault_response_with(SENTINEL);
    let debug = format!("{resp:?}");
    assert!(debug.contains(SENTINEL));
    set_redaction_level(RedactionLevel::Full);
}

#[test]
fn kv_read_response_debug_redacts_data_at_full() {
    set_redaction_level(RedactionLevel::Full);
    let resp = kv_read_response_with(SENTINEL);
    let debug = format!("{resp:?}");
    assert!(debug.contains("KvReadResponse"));
    assert!(!debug.contains(SENTINEL), "secret leaked: {debug}");
    // metadata is not secret and stays visible
    assert!(debug.contains("version"));
}

proptest! {
    // The marker prefix cannot appear in the struct's structural text, so an
    // absent whole value proves the payload was redacted, not a coincidence
    #[test]
    fn prop_response_debug_never_leaks(suffix in "[a-zA-Z0-9]{8,32}") {
        set_redaction_level(RedactionLevel::Full);
        let secret = format!("SENTINEL_{suffix}");
        let resp = vault_response_with(&secret);
        let debug = format!("{resp:?}");
        prop_assert!(!debug.contains(&secret));
    }
}

#[test]
fn transit_secret_types_respect_redaction() {
    let data_key: TransitDataKey = serde_json::from_value(serde_json::json!({
        "ciphertext": "vault:v1:abc",
        "plaintext": SENTINEL
    }))
    .unwrap();
    assert_respects_redaction(&data_key, "TransitDataKey");

    let exported: TransitExportedKey = serde_json::from_value(serde_json::json!({
        "name": "my-key",
        "keys": { "1": SENTINEL },
        "type": "aes256-gcm96"
    }))
    .unwrap();
    assert_respects_redaction(&exported, "TransitExportedKey");
}

#[test]
fn credential_types_respect_redaction() {
    let aws: AwsCredentials = serde_json::from_value(serde_json::json!({
        "access_key": "AKIA",
        "secret_key": SENTINEL
    }))
    .unwrap();
    assert_respects_redaction(&aws, "AwsCredentials");

    let gcp: GcpServiceAccountKey = serde_json::from_value(serde_json::json!({
        "private_key_data": SENTINEL
    }))
    .unwrap();
    assert_respects_redaction(&gcp, "GcpServiceAccountKey");

    let consul: ConsulCredentials =
        serde_json::from_value(serde_json::json!({ "token": SENTINEL })).unwrap();
    assert_respects_redaction(&consul, "ConsulCredentials");

    let ssh: SshSignedKey = serde_json::from_value(serde_json::json!({
        "serial_number": "1",
        "signed_key": SENTINEL
    }))
    .unwrap();
    assert_respects_redaction(&ssh, "SshSignedKey");

    let totp: TotpCode = serde_json::from_value(serde_json::json!({ "code": SENTINEL })).unwrap();
    assert_respects_redaction(&totp, "TotpCode");

    let terraform: TerraformCloudToken =
        serde_json::from_value(serde_json::json!({ "token": SENTINEL })).unwrap();
    assert_respects_redaction(&terraform, "TerraformCloudToken");

    // Tuple `From` credential types take the secret as the second element
    assert_respects_redaction(
        &DatabaseCredentials::from(("user", SENTINEL)),
        "DatabaseCredentials",
    );
    assert_respects_redaction(
        &AzureCredentials::from(("id", SENTINEL)),
        "AzureCredentials",
    );
    assert_respects_redaction(
        &NomadCredentials::from(("id", SENTINEL)),
        "NomadCredentials",
    );
}
