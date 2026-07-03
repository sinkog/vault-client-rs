//! Serde / `Clone` / `Debug` coverage for the public, data-only transit types
//! (params, batch inputs/results, key info). The response types produced by
//! live API calls (TransitDataKey, TransitExportedKey, TransitBatchDecryptItem)
//! are covered by the API-level mock tests instead, since they are only reached
//! through the client; the pub(crate) wire responses aren't reachable here.

use secrecy::SecretString;
use serde_json::{from_value, json, to_value};

use vault_client_rs::types::transit::*;

#[test]
fn transit_param_types() {
    let key = TransitKeyParams {
        key_type: Some("aes256-gcm96".into()),
        derived: Some(false),
        convergent_encryption: Some(false),
        exportable: Some(true),
        allow_plaintext_backup: Some(true),
        auto_rotate_period: Some("24h".into()),
        key_size: Some(32),
    };
    assert_eq!(to_value(&key).unwrap()["type"], "aes256-gcm96");
    let _ = key.clone();
    assert!(format!("{key:?}").contains("TransitKeyParams"));

    let cfg = TransitKeyConfig {
        min_decryption_version: Some(1),
        min_encryption_version: Some(0),
        deletion_allowed: Some(true),
        exportable: Some(true),
        allow_plaintext_backup: Some(true),
        auto_rotate_period: Some("24h".into()),
    };
    assert!(
        to_value(&cfg).unwrap()["deletion_allowed"]
            .as_bool()
            .unwrap()
    );
    let _ = cfg.clone();
    assert!(format!("{cfg:?}").contains("TransitKeyConfig"));

    let sign = TransitSignParams {
        hash_algorithm: Some("sha2-256".into()),
        signature_algorithm: Some("pss".into()),
        marshaling_algorithm: Some("asn1".into()),
        prehashed: Some(false),
        salt_length: Some("auto".into()),
    };
    assert_eq!(to_value(&sign).unwrap()["hash_algorithm"], "sha2-256");
    let _ = sign.clone();
    assert!(format!("{sign:?}").contains("TransitSignParams"));

    // Custom Clone + Debug (redacts plaintext to a literal).
    let bp = TransitBatchPlaintext {
        plaintext: SecretString::from("hello"),
        context: Some("ctx".into()),
    };
    assert_eq!(to_value(&bp).unwrap()["plaintext"], "hello");
    let _ = bp.clone();
    assert!(format!("{bp:?}").contains("TransitBatchPlaintext"));

    let bc = TransitBatchCiphertext {
        ciphertext: "vault:v1:abc".into(),
        error: String::new(),
    };
    assert_eq!(to_value(&bc).unwrap()["ciphertext"], "vault:v1:abc");
    let _ = bc.clone();
    assert!(format!("{bc:?}").contains("TransitBatchCiphertext"));

    let bsi = TransitBatchSignInput {
        input: "aGVsbG8=".into(),
        context: Some("ctx".into()),
    };
    assert!(to_value(&bsi).unwrap()["input"].is_string());
    let _ = bsi.clone();
    assert!(format!("{bsi:?}").contains("TransitBatchSignInput"));

    let bvi = TransitBatchVerifyInput {
        input: "aGVsbG8=".into(),
        signature: "vault:v1:sig".into(),
        context: None,
    };
    assert!(to_value(&bvi).unwrap()["signature"].is_string());
    let _ = bvi.clone();
    assert!(format!("{bvi:?}").contains("TransitBatchVerifyInput"));
}

#[test]
fn transit_response_data_types() {
    let key_info: TransitKeyInfo = from_value(json!({
        "type": "aes256-gcm96", "deletion_allowed": false, "derived": false,
        "exportable": true, "allow_plaintext_backup": true,
        "keys": {"1": {"creation_time": "t"}},
        "min_decryption_version": 1, "min_encryption_version": 0, "name": "my-key",
        "supports_encryption": true, "supports_decryption": true,
        "supports_derivation": true, "supports_signing": false,
        "auto_rotate_period": 0, "latest_version": 1
    }))
    .unwrap();
    assert_eq!(key_info.name, "my-key");
    let _ = key_info.clone();
    assert!(format!("{key_info:?}").contains("TransitKeyInfo"));

    let cache: TransitCacheConfig = from_value(json!({"size": 500})).unwrap();
    assert_eq!(cache.size, 500);
    let _ = cache.clone();
    assert!(format!("{cache:?}").contains("TransitCacheConfig"));

    let sign_result: TransitBatchSignResult =
        from_value(json!({"signature": "vault:v1:sig", "error": ""})).unwrap();
    let _ = sign_result.clone();
    assert!(format!("{sign_result:?}").contains("TransitBatchSignResult"));

    let verify_result: TransitBatchVerifyResult =
        from_value(json!({"valid": true, "error": ""})).unwrap();
    assert!(verify_result.valid);
    let _ = verify_result.clone();
    assert!(format!("{verify_result:?}").contains("TransitBatchVerifyResult"));
}
