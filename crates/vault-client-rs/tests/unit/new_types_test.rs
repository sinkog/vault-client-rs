use proptest::prelude::*;
use secrecy::SecretString;

use vault_client_rs::types::auth::*;
use vault_client_rs::types::database::*;
use vault_client_rs::types::identity::*;
use vault_client_rs::types::pki::*;
use vault_client_rs::types::ssh::*;
use vault_client_rs::types::sys::*;
use vault_client_rs::types::transit::*;

#[test]
fn database_config_request_skip_serializing_optional_fields() {
    let req = DatabaseConfigRequest {
        plugin_name: "mysql-database-plugin".into(),
        connection_url: SecretString::from("{{username}}:{{password}}@tcp(127.0.0.1:3306)/"),
        allowed_roles: None,
        username: None,
        password: None,
        max_open_connections: None,
        max_idle_connections: None,
        max_connection_lifetime: None,
        username_template: None,
        verify_connection: None,
    };
    let json = serde_json::to_value(&req).unwrap();
    assert_eq!(json["plugin_name"], "mysql-database-plugin");
    assert_eq!(
        json["connection_url"],
        "{{username}}:{{password}}@tcp(127.0.0.1:3306)/"
    );
    // password has skip_serializing_if, so it should be absent when None
    assert!(json.get("password").is_none());
}

#[test]
fn database_credentials_debug_redacts_password() {
    let json = serde_json::json!({
        "username": "db-admin",
        "password": "s3cret-p@ssw0rd!"
    });
    let cred: DatabaseCredentials = serde_json::from_value(json).unwrap();
    let debug = format!("{:?}", cred);
    assert!(
        debug.contains("REDACTED"),
        "Debug output should contain REDACTED: {}",
        debug
    );
    assert!(
        !debug.contains("s3cret-p@ssw0rd!"),
        "Debug output must not leak the actual password: {}",
        debug
    );
    assert!(
        !debug.contains("db-admin"),
        "Debug output must not leak the username: {}",
        debug
    );
}

#[test]
fn database_static_credentials_debug_redacts() {
    let json = serde_json::json!({
        "username": "static-user",
        "password": "my-static-pass",
        "last_vault_rotation": "2024-01-01T00:00:00Z",
        "rotation_period": 86400,
        "ttl": 3600
    });
    let cred: DatabaseStaticCredentials = serde_json::from_value(json).unwrap();
    let debug = format!("{:?}", cred);
    assert!(
        debug.contains("REDACTED"),
        "Debug output should contain REDACTED: {}",
        debug
    );
    assert!(
        !debug.contains("my-static-pass"),
        "Debug output must not leak the password: {}",
        debug
    );
    assert!(
        !debug.contains("static-user"),
        "Debug output must not leak the username: {}",
        debug
    );
    // ttl should still be visible
    assert!(
        debug.contains("3600"),
        "Debug output should include ttl: {}",
        debug
    );
}

#[test]
fn ssh_signed_key_debug_redacts() {
    let json = serde_json::json!({
        "serial_number": "abc-123-serial",
        "signed_key": "ssh-rsa AAAA...super-secret-key-data"
    });
    let key: SshSignedKey = serde_json::from_value(json).unwrap();
    let debug = format!("{:?}", key);
    assert!(
        debug.contains("REDACTED"),
        "Debug output should contain REDACTED: {}",
        debug
    );
    assert!(
        !debug.contains("super-secret-key-data"),
        "Debug output must not leak the signed key: {}",
        debug
    );
    assert!(
        debug.contains("abc-123-serial"),
        "Debug output should include the serial number: {}",
        debug
    );
}

#[test]
fn ssh_role_request_serializes_correctly() {
    let req = SshRoleRequest {
        key_type: "ca".into(),
        default_user: Some("ubuntu".into()),
        allowed_users: Some("ubuntu,admin".into()),
        allow_user_certificates: Some(true),
        ttl: Some("30m".into()),
        ..Default::default()
    };
    let json = serde_json::to_value(&req).unwrap();
    assert_eq!(json["key_type"], "ca");
    assert_eq!(json["default_user"], "ubuntu");
    assert_eq!(json["allowed_users"], "ubuntu,admin");
    assert_eq!(json["allow_user_certificates"], true);
    assert_eq!(json["ttl"], "30m");
}

#[test]
fn group_create_request_serializes_type_field() {
    let req = GroupCreateRequest {
        name: "my-group".into(),
        group_type: Some("external".into()),
        policies: Some(vec!["default".into()]),
        ..Default::default()
    };
    let json = serde_json::to_value(&req).unwrap();
    // The serde rename should produce "type" in JSON, not "group_type"
    assert_eq!(json["type"], "external");
    assert!(
        json.get("group_type").is_none(),
        "JSON should not contain 'group_type' key"
    );
    assert_eq!(json["name"], "my-group");
}

#[test]
fn group_deserializes_type_field_as_group_type() {
    let json = serde_json::json!({
        "id": "group-id-123",
        "name": "my-group",
        "policies": ["default"],
        "metadata": null,
        "member_entity_ids": [],
        "member_group_ids": [],
        "type": "internal",
        "creation_time": "2024-01-01T00:00:00Z",
        "last_update_time": "2024-01-01T00:00:00Z",
        "alias": null
    });
    let group: Group = serde_json::from_value(json).unwrap();
    assert_eq!(group.group_type, "internal");
    assert_eq!(group.name, "my-group");
    assert_eq!(group.id, "group-id-123");
}

#[test]
fn userpass_user_request_omits_none_fields() {
    let req = UserpassUserRequest {
        password: Some(SecretString::from("hunter2")),
        token_policies: Some(vec!["dev".into(), "readonly".into()]),
        token_ttl: None,
        token_max_ttl: None,
        token_bound_cidrs: None,
        token_num_uses: None,
    };
    let json = serde_json::to_value(&req).unwrap();
    assert_eq!(json["password"], "hunter2");
    assert_eq!(
        json["token_policies"],
        serde_json::json!(["dev", "readonly"])
    );
    // All other optional fields should be absent
    assert!(json.get("token_ttl").is_none());
    assert!(json.get("token_max_ttl").is_none());
    assert!(json.get("token_bound_cidrs").is_none());
    assert!(json.get("token_num_uses").is_none());
}

#[test]
fn oidc_config_request_serializes_correctly() {
    let req = OidcConfigRequest {
        oidc_discovery_url: Some("https://accounts.google.com".into()),
        oidc_client_id: Some("my-client-id".into()),
        oidc_client_secret: Some(SecretString::from("my-client-secret")),
        default_role: Some("default".into()),
        jwt_validation_pubkeys: None,
        bound_issuer: None,
        jwt_supported_algs: None,
    };
    let json = serde_json::to_value(&req).unwrap();
    assert_eq!(json["oidc_discovery_url"], "https://accounts.google.com");
    assert_eq!(json["oidc_client_id"], "my-client-id");
    assert_eq!(json["oidc_client_secret"], "my-client-secret");
    assert_eq!(json["default_role"], "default");
    // Optional fields not set should be absent
    assert!(json.get("jwt_validation_pubkeys").is_none());
    assert!(json.get("bound_issuer").is_none());
    assert!(json.get("jwt_supported_algs").is_none());
}

#[test]
fn cert_role_request_serializes_correctly() {
    let req = CertRoleRequest {
        certificate: "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----".into(),
        allowed_common_names: Some(vec!["example.com".into()]),
        token_policies: Some(vec!["web".into()]),
        display_name: Some("web-cert".into()),
        ..Default::default()
    };
    let json = serde_json::to_value(&req).unwrap();
    assert!(
        json["certificate"]
            .as_str()
            .unwrap()
            .contains("BEGIN CERTIFICATE")
    );
    assert_eq!(
        json["allowed_common_names"],
        serde_json::json!(["example.com"])
    );
    assert_eq!(json["token_policies"], serde_json::json!(["web"]));
    assert_eq!(json["display_name"], "web-cert");
    assert!(json.get("allowed_dns_sans").is_none());
    assert!(json.get("allowed_uri_sans").is_none());
    assert!(json.get("token_ttl").is_none());
}

#[test]
fn github_team_mapping_serialize_then_deserialize_as_team_info() {
    let mapping = GithubTeamMapping {
        value: Some("dev-policy,staging-policy".into()),
    };
    let json = serde_json::to_value(&mapping).unwrap();
    assert_eq!(json["value"], "dev-policy,staging-policy");

    // Deserialize as GithubTeamInfo (the response counterpart)
    let info: GithubTeamInfo = serde_json::from_value(json).unwrap();
    assert_eq!(info.value, "dev-policy,staging-policy");
}

proptest! {
    #[test]
    fn prop_github_team_mapping_roundtrip(value in "[a-z_-]{0,64}") {
        let mapping = GithubTeamMapping {
            value: if value.is_empty() { None } else { Some(value.clone()) },
        };
        let json = serde_json::to_value(&mapping).unwrap();
        let info: GithubTeamInfo = serde_json::from_value(json).unwrap();
        if value.is_empty() {
            // GithubTeamInfo has #[serde(default)], so absent value -> ""
            prop_assert_eq!(info.value.as_str(), "");
        } else {
            prop_assert_eq!(info.value, value);
        }
    }
}

#[test]
fn pki_acme_config_roundtrip() {
    let config = PkiAcmeConfig {
        enabled: true,
        allowed_issuers: vec!["issuer-1".into(), "issuer-2".into()],
        allowed_roles: vec!["role-a".into()],
        default_directory_policy: Some("sign-verbatim".into()),
        dns_resolver: Some("8.8.8.8:53".into()),
        eab_policy: None,
    };
    let json = serde_json::to_value(&config).unwrap();
    let roundtripped: PkiAcmeConfig = serde_json::from_value(json).unwrap();
    assert!(roundtripped.enabled);
    assert_eq!(roundtripped.allowed_issuers, vec!["issuer-1", "issuer-2"]);
    assert_eq!(roundtripped.allowed_roles, vec!["role-a"]);
    assert_eq!(
        roundtripped.default_directory_policy.as_deref(),
        Some("sign-verbatim")
    );
    assert_eq!(roundtripped.dns_resolver.as_deref(), Some("8.8.8.8:53"));
    assert!(roundtripped.eab_policy.is_none());
}

#[test]
fn pki_acme_config_empty_vecs_omitted() {
    let config = PkiAcmeConfig {
        enabled: false,
        allowed_issuers: vec![],
        allowed_roles: vec![],
        default_directory_policy: None,
        dns_resolver: None,
        eab_policy: None,
    };
    let json = serde_json::to_value(&config).unwrap();
    // Empty vecs have skip_serializing_if = "Vec::is_empty"
    assert!(json.get("allowed_issuers").is_none());
    assert!(json.get("allowed_roles").is_none());
}

#[test]
fn pki_issuer_update_params_omits_optional_fields() {
    let params = PkiIssuerUpdateParams {
        issuer_name: Some("my-issuer".into()),
        ..Default::default()
    };
    let json = serde_json::to_value(&params).unwrap();
    assert_eq!(json["issuer_name"], "my-issuer");
    assert!(json.get("leaf_not_after_behavior").is_none());
    assert!(json.get("usage").is_none());
    assert!(json.get("manual_chain").is_none());
}

#[test]
fn transit_batch_sign_input_omits_context_when_none() {
    let input = TransitBatchSignInput {
        input: "dGVzdCBkYXRh".into(),
        context: None,
    };
    let json = serde_json::to_value(&input).unwrap();
    assert_eq!(json["input"], "dGVzdCBkYXRh");
    assert!(
        json.get("context").is_none(),
        "context should be omitted when None"
    );
}

#[test]
fn transit_batch_sign_input_includes_context_when_set() {
    let input = TransitBatchSignInput {
        input: "dGVzdCBkYXRh".into(),
        context: Some("bXkgY29udGV4dA==".into()),
    };
    let json = serde_json::to_value(&input).unwrap();
    assert_eq!(json["input"], "dGVzdCBkYXRh");
    assert_eq!(json["context"], "bXkgY29udGV4dA==");
}

#[test]
fn transit_batch_verify_input_serializes_correctly() {
    let input = TransitBatchVerifyInput {
        input: "dGVzdA==".into(),
        signature: "vault:v1:abc123".into(),
        context: None,
    };
    let json = serde_json::to_value(&input).unwrap();
    assert_eq!(json["input"], "dGVzdA==");
    assert_eq!(json["signature"], "vault:v1:abc123");
    assert!(json.get("context").is_none());
}

#[test]
fn transit_batch_verify_input_with_context() {
    let input = TransitBatchVerifyInput {
        input: "dGVzdA==".into(),
        signature: "vault:v1:xyz789".into(),
        context: Some("c29tZSBjb250ZXh0".into()),
    };
    let json = serde_json::to_value(&input).unwrap();
    assert_eq!(json["input"], "dGVzdA==");
    assert_eq!(json["signature"], "vault:v1:xyz789");
    assert_eq!(json["context"], "c29tZSBjb250ZXh0");
}

#[test]
fn rekey_init_request_serializes_correctly() {
    let req = RekeyInitRequest {
        secret_shares: 5,
        secret_threshold: 3,
        pgp_keys: None,
        backup: Some(true),
    };
    let json = serde_json::to_value(&req).unwrap();
    assert_eq!(json["secret_shares"], 5);
    assert_eq!(json["secret_threshold"], 3);
    assert!(json.get("pgp_keys").is_none());
    assert_eq!(json["backup"], true);
}

#[test]
fn rekey_init_request_with_pgp_keys() {
    let req = RekeyInitRequest {
        secret_shares: 3,
        secret_threshold: 2,
        pgp_keys: Some(vec!["key1".into(), "key2".into(), "key3".into()]),
        backup: None,
    };
    let json = serde_json::to_value(&req).unwrap();
    assert_eq!(json["secret_shares"], 3);
    assert_eq!(json["secret_threshold"], 2);
    assert_eq!(
        json["pgp_keys"],
        serde_json::json!(["key1", "key2", "key3"])
    );
    assert!(json.get("backup").is_none());
}

#[test]
fn generate_root_init_request_serializes_correctly() {
    let req = GenerateRootInitRequest {
        pgp_key: Some("mypgpkey".into()),
    };
    let json = serde_json::to_value(&req).unwrap();
    assert_eq!(json["pgp_key"], "mypgpkey");
}

#[test]
fn generate_root_init_request_omits_pgp_key_when_none() {
    let req = GenerateRootInitRequest::default();
    let json = serde_json::to_value(&req).unwrap();
    assert!(json.get("pgp_key").is_none());
}

#[test]
fn rate_limit_quota_request_serializes_with_required_fields() {
    let req = RateLimitQuotaRequest {
        name: "global-limiter".into(),
        rate: 100.0,
        burst: Some(200),
        path: Some("secret/".into()),
        ..Default::default()
    };
    let json = serde_json::to_value(&req).unwrap();
    assert_eq!(json["name"], "global-limiter");
    assert_eq!(json["rate"], 100.0);
    assert_eq!(json["burst"], 200);
    assert_eq!(json["path"], "secret/");
    assert!(json.get("interval").is_none());
    assert!(json.get("block_interval").is_none());
    assert!(json.get("role").is_none());
    assert!(json.get("inheritable").is_none());
}

proptest! {
    #[test]
    fn prop_rate_limit_quota_request_roundtrip(
        name in "[a-zA-Z][a-zA-Z0-9_-]{0,31}",
        rate in 0.1f64..10000.0,
        burst in proptest::option::of(1u64..10000),
    ) {
        let req = RateLimitQuotaRequest {
            name: name.clone(),
            rate,
            burst,
            ..Default::default()
        };
        let json_str = serde_json::to_string(&req).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        prop_assert_eq!(parsed["name"].as_str().unwrap(), name.as_str());
        // Verify rate roundtrips within floating-point tolerance
        let parsed_rate = parsed["rate"].as_f64().unwrap();
        prop_assert!((parsed_rate - rate).abs() < 1e-10);
        match burst {
            Some(b) => prop_assert_eq!(parsed["burst"].as_u64().unwrap(), b),
            None => prop_assert!(parsed.get("burst").is_none()),
        }
    }
}
