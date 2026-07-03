use std::collections::HashMap;
use std::time::Duration;

use proptest::prelude::*;
use vault_client_rs::types::error::VaultError;
use vault_client_rs::types::secret::{MountPath, SecretPath};
use vault_client_rs::{
    AuthInfo, KvReadResponse, RedactionLevel, VaultResponse, set_redaction_level,
};

// ---------------------------------------------------------------------------
// MountPath validation
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_mount_path_rejects_traversal(s in ".*\\.\\./.*") {
        prop_assert!(MountPath::new(s).is_err());
    }

    #[test]
    fn prop_mount_path_rejects_leading_slash(s in "/[a-z]{1,10}") {
        prop_assert!(MountPath::new(s).is_err());
    }

    #[test]
    fn prop_mount_path_rejects_trailing_slash(s in "[a-z]{1,10}/") {
        prop_assert!(MountPath::new(s).is_err());
    }

    #[test]
    fn prop_mount_path_rejects_encoded_traversal(
        prefix in "[a-z]{1,5}",
        suffix in "[a-z]{1,5}",
    ) {
        let lower = format!("{}%2e%2e%2f{}", prefix, suffix);
        let upper = format!("{}%2E%2E%2F{}", prefix, suffix);
        prop_assert!(MountPath::new(lower).is_err());
        prop_assert!(MountPath::new(upper).is_err());
    }

    #[test]
    fn prop_mount_path_rejects_null_bytes(
        prefix in "[a-z]{1,10}",
        suffix in "[a-z]{1,10}",
    ) {
        let s = format!("{}\0{}", prefix, suffix);
        prop_assert!(MountPath::new(s).is_err());
    }

    #[test]
    fn prop_mount_path_rejects_control_chars(
        prefix in "[a-z]{1,5}",
        ctrl in prop::char::range('\x01', '\x1f'),
        suffix in "[a-z]{1,5}",
    ) {
        let s = format!("{}{}{}", prefix, ctrl, suffix);
        prop_assert!(MountPath::new(s).is_err());
    }

    #[test]
    fn prop_mount_path_preserves_valid(s in "[a-zA-Z][a-zA-Z0-9_-]{0,63}") {
        let mp = MountPath::new(&s).unwrap();
        prop_assert_eq!(mp.as_str(), s.as_str());
    }

    #[test]
    fn prop_secret_path_allows_nested(
        a in "[a-z]{1,10}",
        b in "[a-z]{1,10}",
        c in "[a-z]{1,10}",
    ) {
        let s = format!("{}/{}/{}", a, b, c);
        prop_assert!(SecretPath::new(s).is_ok());
    }

    #[test]
    fn prop_secret_path_rejects_traversal(s in ".*\\.\\./.*") {
        prop_assert!(SecretPath::new(s).is_err());
    }
}

#[test]
fn mount_path_rejects_empty() {
    assert!(MountPath::new("").is_err());
}

#[test]
fn mount_path_accepts_simple_name() {
    let mp = MountPath::new("secret").unwrap();
    assert_eq!(mp.as_str(), "secret");
    assert_eq!(mp.to_string(), "secret");
}

#[test]
fn mount_path_accepts_hyphenated() {
    assert!(MountPath::new("my-transit").is_ok());
}

#[test]
fn secret_path_rejects_empty() {
    assert!(SecretPath::new("").is_err());
}

#[test]
fn secret_path_rejects_leading_slash() {
    assert!(SecretPath::new("/apps/myapp").is_err());
}

// ---------------------------------------------------------------------------
// VaultError classification
// ---------------------------------------------------------------------------

#[test]
fn retryable_variants_are_retryable() {
    assert!(
        VaultError::Sealed {
            url: "http://vault:8200".into()
        }
        .is_retryable()
    );
    assert!(VaultError::RateLimited { retry_after: None }.is_retryable());
    assert!(
        VaultError::RateLimited {
            retry_after: Some(5)
        }
        .is_retryable()
    );
    assert!(VaultError::ConsistencyRetry.is_retryable());
}

proptest! {
    #[test]
    fn prop_retryable_api_status_codes(status in prop_oneof![
        Just(500u16), Just(502u16), Just(503u16), Just(504u16)
    ]) {
        let err = VaultError::Api { status, errors: vec![] };
        prop_assert!(err.is_retryable());
    }

    #[test]
    fn prop_non_retryable_status_codes(status in prop_oneof![
        Just(400u16), Just(401u16), Just(403u16),
        Just(404u16), Just(405u16), Just(422u16), Just(501u16)
    ]) {
        let err = VaultError::Api { status, errors: vec![] };
        prop_assert!(!err.is_retryable());
    }

    #[test]
    fn prop_status_code_correctness(status in 400u16..600) {
        let err = VaultError::Api { status, errors: vec![] };
        prop_assert_eq!(err.status_code(), Some(status));
    }
}

#[test]
fn non_retryable_variants() {
    assert!(!VaultError::PermissionDenied { errors: vec![] }.is_retryable());
    assert!(!VaultError::NotFound { path: "x".into() }.is_retryable());
    assert!(!VaultError::AuthRequired.is_retryable());
    assert!(!VaultError::Config("x".into()).is_retryable());
    assert!(!VaultError::EmptyResponse.is_retryable());
    assert!(!VaultError::LockPoisoned.is_retryable());
    assert!(!VaultError::CircuitOpen.is_retryable());
    assert!(
        !VaultError::FieldNotFound {
            mount: "s".into(),
            path: "p".into(),
            field: "f".into()
        }
        .is_retryable()
    );
}

#[test]
fn auth_error_classification() {
    assert!(VaultError::PermissionDenied { errors: vec![] }.is_auth_error());
    assert!(VaultError::AuthRequired.is_auth_error());
    assert!(
        !VaultError::Sealed {
            url: "http://vault:8200".into()
        }
        .is_auth_error()
    );
    // Api 403 is NOT an auth error — it goes through the dedicated variant
    assert!(
        !VaultError::Api {
            status: 403,
            errors: vec![]
        }
        .is_auth_error()
    );
}

#[test]
fn status_code_for_dedicated_variants() {
    assert_eq!(
        VaultError::Sealed {
            url: "http://vault:8200".into()
        }
        .status_code(),
        Some(503)
    );
    assert_eq!(
        VaultError::RateLimited { retry_after: None }.status_code(),
        Some(429)
    );
    assert_eq!(VaultError::ConsistencyRetry.status_code(), Some(412));
    assert_eq!(
        VaultError::NotFound { path: "x".into() }.status_code(),
        Some(404)
    );
    assert_eq!(
        VaultError::PermissionDenied { errors: vec![] }.status_code(),
        Some(403)
    );
    assert_eq!(VaultError::AuthRequired.status_code(), Some(401));
    assert_eq!(VaultError::EmptyResponse.status_code(), None);
    assert_eq!(VaultError::LockPoisoned.status_code(), None);
    assert_eq!(VaultError::CircuitOpen.status_code(), None);
    assert_eq!(
        VaultError::FieldNotFound {
            mount: "s".into(),
            path: "p".into(),
            field: "f".into()
        }
        .status_code(),
        None
    );
}

#[test]
fn error_display_includes_details() {
    let err = VaultError::Api {
        status: 400,
        errors: vec!["bad request".into()],
    };
    let msg = err.to_string();
    assert!(msg.contains("400"));
    assert!(msg.contains("bad request"));
}

// ---------------------------------------------------------------------------
// Retry backoff invariants
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_backoff_is_capped(initial_ms in 100u64..2000, attempt in 0u32..20) {
        let initial = Duration::from_millis(initial_ms);
        let base = initial.checked_mul(2u32.saturating_pow(attempt)).unwrap_or(Duration::MAX);
        let capped = base.min(Duration::from_secs(30));
        prop_assert!(capped <= Duration::from_secs(30));
    }

    #[test]
    fn prop_jitter_bounded_by_base(base_ms in 1u64..30_000, rand_val in 0u64..u64::MAX) {
        let jitter_ms = rand_val % base_ms.max(1);
        prop_assert!(jitter_ms < base_ms.max(1));
    }
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_kv_data_roundtrip(
        data in prop::collection::hash_map("[a-zA-Z_]{1,32}", "\\PC{0,64}", 0..20)
    ) {
        let json = serde_json::to_string(&data).unwrap();
        let parsed: HashMap<String, String> = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(data, parsed);
    }
}

#[test]
fn vault_response_deserialize_with_data() {
    let json = serde_json::json!({
        "request_id": "abc-123",
        "lease_id": "",
        "lease_duration": 0,
        "renewable": false,
        "data": { "key": "value" },
        "warnings": null,
    });
    let resp: VaultResponse<HashMap<String, String>> = serde_json::from_value(json).unwrap();
    assert_eq!(resp.request_id.as_deref(), Some("abc-123"));
    assert_eq!(resp.data.unwrap()["key"], "value");
}

#[test]
fn vault_response_deserialize_without_data() {
    let json = serde_json::json!({
        "request_id": "abc-123",
        "lease_id": "",
        "renewable": false,
    });
    let resp: VaultResponse<serde_json::Value> = serde_json::from_value(json).unwrap();
    assert!(resp.data.is_none());
}

#[test]
fn vault_response_debug_redacts_data() {
    set_redaction_level(RedactionLevel::Full);
    let json = serde_json::json!({
        "data": { "password": "hunter2" },
    });
    let resp: VaultResponse<HashMap<String, String>> = serde_json::from_value(json).unwrap();
    let debug = format!("{resp:?}");
    assert!(!debug.contains("hunter2"));
    assert!(debug.contains("[REDACTED]"));

    set_redaction_level(RedactionLevel::None);
    assert!(format!("{resp:?}").contains("hunter2"));
    set_redaction_level(RedactionLevel::Full);
}

#[test]
fn kv_read_response_debug_redacts_data() {
    set_redaction_level(RedactionLevel::Full);
    let json = serde_json::json!({
        "data": { "api_key": "topsecret" },
        "metadata": {
            "created_time": "2026-01-01T00:00:00Z",
            "version": 1,
        },
    });
    let resp: KvReadResponse<HashMap<String, String>> = serde_json::from_value(json).unwrap();
    let debug = format!("{resp:?}");
    assert!(!debug.contains("topsecret"));
    assert!(debug.contains("[REDACTED]"));

    set_redaction_level(RedactionLevel::None);
    assert!(format!("{resp:?}").contains("topsecret"));
    set_redaction_level(RedactionLevel::Full);
}

#[test]
fn auth_info_deserializes() {
    let json = serde_json::json!({
        "client_token": "s.mytoken",
        "accessor": "acc123",
        "policies": ["default"],
        "lease_duration": 3600,
        "renewable": true,
        "entity_id": "ent-1",
        "token_type": "service",
        "orphan": false,
    });
    let auth: AuthInfo = serde_json::from_value(json).unwrap();
    assert_eq!(auth.accessor, "acc123");
    assert_eq!(auth.lease_duration, 3600);
    assert!(auth.renewable);
}
