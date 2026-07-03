//! Serde / `Clone` / `Debug` / `From` coverage for the sys, database, ssh,
//! rabbitmq, secret-path, and error type modules. Same approach as the other
//! `*_types_test` modules: request types via construction + serialize, response
//! types via deserialize, then clone + debug so the hand-written impls run.

use secrecy::SecretString;
use serde_json::{from_value, json, to_value};

use vault_client_rs::types::database::*;
use vault_client_rs::types::error::VaultError;
use vault_client_rs::types::rabbitmq::*;
use vault_client_rs::types::secret::{MountPath, SecretPath};
use vault_client_rs::types::ssh::*;
use vault_client_rs::types::sys::*;

// ---------------------------------------------------------------------------
// sys — request types
// ---------------------------------------------------------------------------

#[test]
fn sys_request_types() {
    let init = InitParams {
        secret_shares: 5,
        secret_threshold: 3,
        pgp_keys: Some(vec!["key".into()]),
        root_token_pgp_key: Some("rk".into()),
        recovery_shares: Some(5),
        recovery_threshold: Some(3),
    };
    assert_eq!(to_value(&init).unwrap()["secret_shares"], 5);
    let _ = init.clone();
    assert!(format!("{init:?}").contains("InitParams"));

    let tune = MountTuneParams::default();
    let _ = to_value(&tune).unwrap();
    let _ = tune.clone();
    assert!(format!("{tune:?}").contains("MountTuneParams"));

    let mount = MountParams {
        mount_type: "kv".into(),
        description: Some("d".into()),
        config: Some(MountTuneParams::default()),
        options: Some(
            [("version".to_string(), "2".to_string())]
                .into_iter()
                .collect(),
        ),
    };
    assert_eq!(to_value(&mount).unwrap()["type"], "kv");
    let _ = mount.clone();
    assert!(format!("{mount:?}").contains("MountParams"));

    let auth_mount = AuthMountParams {
        mount_type: "approle".into(),
        description: Some("d".into()),
        config: Some(MountTuneParams::default()),
    };
    assert_eq!(to_value(&auth_mount).unwrap()["type"], "approle");
    let _ = auth_mount.clone();
    assert!(format!("{auth_mount:?}").contains("AuthMountParams"));

    let audit = AuditParams {
        audit_type: "file".into(),
        description: Some("d".into()),
        options: [("file_path".to_string(), "/tmp/a".to_string())]
            .into_iter()
            .collect(),
        local: Some(false),
    };
    assert_eq!(to_value(&audit).unwrap()["type"], "file");
    let _ = audit.clone();
    assert!(format!("{audit:?}").contains("AuditParams"));

    let plugin = RegisterPluginRequest {
        name: "p".into(),
        plugin_type: "secret".into(),
        command: "cmd".into(),
        sha256: "abc".into(),
        args: Some(vec!["--x".into()]),
        env: Some(vec!["K=V".into()]),
        version: Some("v1".into()),
    };
    assert_eq!(to_value(&plugin).unwrap()["type"], "secret");
    let _ = plugin.clone();
    assert!(format!("{plugin:?}").contains("RegisterPluginRequest"));

    let quota = RateLimitQuotaRequest {
        name: "q".into(),
        rate: 100.0,
        burst: Some(200),
        path: Some("secret".into()),
        interval: Some("1s".into()),
        block_interval: Some("5s".into()),
        role: Some("r".into()),
        inheritable: Some(true),
    };
    assert_eq!(to_value(&quota).unwrap()["name"], "q");
    let _ = quota.clone();
    assert!(format!("{quota:?}").contains("RateLimitQuotaRequest"));

    let rekey = RekeyInitRequest {
        secret_shares: 5,
        secret_threshold: 3,
        pgp_keys: Some(vec!["k".into()]),
        backup: Some(true),
    };
    assert_eq!(to_value(&rekey).unwrap()["secret_shares"], 5);
    let _ = rekey.clone();
    assert!(format!("{rekey:?}").contains("RekeyInitRequest"));

    let genroot = GenerateRootInitRequest {
        pgp_key: Some("k".into()),
    };
    let _ = to_value(&genroot).unwrap();
    let _ = genroot.clone();
    assert!(format!("{genroot:?}").contains("GenerateRootInitRequest"));
}

// ---------------------------------------------------------------------------
// sys — response types
// ---------------------------------------------------------------------------

#[test]
fn sys_response_types() {
    let health: HealthResponse = from_value(json!({
        "initialized": true, "sealed": false, "standby": false, "version": "1.18.0"
    }))
    .unwrap();
    assert!(health.initialized);
    let _ = health.clone();
    assert!(format!("{health:?}").contains("HealthResponse"));

    let leader: LeaderResponse = from_value(json!({"ha_enabled": true, "is_self": true})).unwrap();
    let _ = leader.clone();
    assert!(format!("{leader:?}").contains("LeaderResponse"));

    let seal: SealStatus = from_value(json!({
        "type": "shamir", "initialized": true, "sealed": false, "t": 3, "n": 5,
        "progress": 0, "nonce": "", "version": "1.18.0"
    }))
    .unwrap();
    let _ = seal.clone();
    assert!(format!("{seal:?}").contains("SealStatus"));

    let init: InitResponse = from_value(json!({
        "keys": ["k1", "k2"], "keys_base64": ["b1", "b2"], "root_token": "s.root"
    }))
    .unwrap();
    let _ = init.clone();
    assert!(format!("{init:?}").contains("InitResponse"));

    let mount_cfg = json!({"default_lease_ttl": 3600, "max_lease_ttl": 7200});
    let mi: MountInfo = from_value(json!({
        "type": "kv", "accessor": "kv_abc", "config": mount_cfg, "options": {"version": "2"}
    }))
    .unwrap();
    let _ = mi.clone();
    assert!(format!("{mi:?}").contains("MountInfo"));

    let mc: MountConfig =
        from_value(json!({"default_lease_ttl": 3600, "max_lease_ttl": 7200})).unwrap();
    let _ = mc.clone();
    assert!(format!("{mc:?}").contains("MountConfig"));

    let ami: AuthMountInfo = from_value(json!({
        "type": "approle", "accessor": "auth_abc",
        "config": {"default_lease_ttl": 0, "max_lease_ttl": 0}
    }))
    .unwrap();
    let _ = ami.clone();
    assert!(format!("{ami:?}").contains("AuthMountInfo"));

    let policy: PolicyInfo =
        from_value(json!({"name": "default", "policy": "path \"x\" {}"})).unwrap();
    let _ = policy.clone();
    assert!(format!("{policy:?}").contains("PolicyInfo"));

    let lease: LeaseInfo = from_value(json!({
        "id": "lease/x", "issue_time": "t", "renewable": true, "ttl": 3600
    }))
    .unwrap();
    let _ = lease.clone();
    assert!(format!("{lease:?}").contains("LeaseInfo"));

    let renewal: LeaseRenewal = from_value(json!({
        "lease_id": "lease/x", "lease_duration": 3600, "renewable": true
    }))
    .unwrap();
    let _ = renewal.clone();
    assert!(format!("{renewal:?}").contains("LeaseRenewal"));

    let audit: AuditDevice = from_value(json!({"type": "file", "path": "file/"})).unwrap();
    let _ = audit.clone();
    assert!(format!("{audit:?}").contains("AuditDevice"));

    let key_status: KeyStatus = from_value(json!({"term": 1, "install_time": "t"})).unwrap();
    let _ = key_status.clone();
    assert!(format!("{key_status:?}").contains("KeyStatus"));

    let plugin: PluginInfo = from_value(json!({
        "name": "p", "command": "c", "sha256": "abc", "builtin": true
    }))
    .unwrap();
    let _ = plugin.clone();
    assert!(format!("{plugin:?}").contains("PluginInfo"));

    let raft: RaftConfig = from_value(json!({
        "servers": [{"node_id": "n1", "address": "a", "leader": true, "voter": true}], "index": 5
    }))
    .unwrap();
    let _ = raft.clone();
    assert!(format!("{raft:?}").contains("RaftConfig"));
    let raft_server: RaftServer =
        from_value(json!({"node_id": "n1", "address": "a", "leader": true, "voter": true}))
            .unwrap();
    let _ = raft_server.clone();
    assert!(format!("{raft_server:?}").contains("RaftServer"));

    let autopilot: AutopilotState = from_value(json!({
        "healthy": true, "failure_tolerance": 1, "leader": "n1", "voters": ["n1"],
        "servers": {"n1": {
            "id": "n1", "name": "n1", "address": "a", "node_status": "alive",
            "status": "leader", "healthy": true, "last_contact": "0s",
            "last_index": 5, "last_term": 1, "voter": true, "leader": true
        }}
    }))
    .unwrap();
    let _ = autopilot.clone();
    assert!(format!("{autopilot:?}").contains("AutopilotState"));

    let ns: NamespaceInfo = from_value(json!({"id": "ns1", "path": "team/"})).unwrap();
    let _ = ns.clone();
    assert!(format!("{ns:?}").contains("NamespaceInfo"));

    let quota: RateLimitQuota = from_value(json!({
        "name": "q", "rate": 100.0, "burst": 200, "path": "secret", "type": "rate-limit"
    }))
    .unwrap();
    let _ = quota.clone();
    assert!(format!("{quota:?}").contains("RateLimitQuota"));

    let rekey: RekeyStatus = from_value(json!({
        "started": true, "nonce": "n", "t": 3, "n": 5, "progress": 1, "required": 3,
        "backup": false, "verification_required": false, "complete": false,
        "keys": ["k1"], "keys_base64": ["b1"]
    }))
    .unwrap();
    let _ = rekey.clone();
    assert!(format!("{rekey:?}").contains("RekeyStatus"));

    let genroot: GenerateRootStatus = from_value(json!({
        "started": true, "nonce": "n", "progress": 1, "required": 3, "complete": false,
        "encoded_token": "et", "encoded_root_token": "ert", "otp_length": 24, "otp": "otp"
    }))
    .unwrap();
    let _ = genroot.clone();
    assert!(format!("{genroot:?}").contains("GenerateRootStatus"));

    let remount: RemountStatus = from_value(json!({"migration_id": "m1"})).unwrap();
    let _ = remount.clone();
    assert!(format!("{remount:?}").contains("RemountStatus"));

    let host: HostInfo = from_value(json!({"timestamp": "t"})).unwrap();
    let _ = host.clone();
    assert!(format!("{host:?}").contains("HostInfo"));

    let inflight: InFlightRequest = from_value(json!({
        "request_id": "r1", "request_path": "sys/health", "client_address": "1.2.3.4", "start_time": "t"
    }))
    .unwrap();
    let _ = inflight.clone();
    assert!(format!("{inflight:?}").contains("InFlightRequest"));

    let vh: VersionHistoryEntry = from_value(json!({"timestamp_installed": "t"})).unwrap();
    let _ = vh.clone();
    assert!(format!("{vh:?}").contains("VersionHistoryEntry"));
}

// ---------------------------------------------------------------------------
// database
// ---------------------------------------------------------------------------

#[test]
fn database_types() {
    let cfg_req = DatabaseConfigRequest {
        plugin_name: "mysql-database-plugin".into(),
        connection_url: SecretString::from("user:pass@tcp(x)/"),
        allowed_roles: Some(vec!["r".into()]),
        username: Some("u".into()),
        password: Some(SecretString::from("p")),
        max_open_connections: Some(4),
        max_idle_connections: Some(2),
        max_connection_lifetime: Some("1h".into()),
        username_template: Some("{{.x}}".into()),
        verify_connection: Some(true),
    };
    assert_eq!(
        to_value(&cfg_req).unwrap()["connection_url"],
        "user:pass@tcp(x)/"
    );
    let _ = cfg_req.clone();
    assert!(format!("{cfg_req:?}").contains("DatabaseConfigRequest"));

    let role_req = DatabaseRoleRequest {
        db_name: "db".into(),
        creation_statements: Some(vec!["CREATE".into()]),
        ..Default::default()
    };
    assert_eq!(to_value(&role_req).unwrap()["db_name"], "db");
    let _ = role_req.clone();
    assert!(format!("{role_req:?}").contains("DatabaseRoleRequest"));

    let static_req = DatabaseStaticRoleRequest {
        db_name: "db".into(),
        username: "u".into(),
        rotation_statements: Some(vec!["ALTER".into()]),
        rotation_period: Some("24h".into()),
    };
    assert_eq!(to_value(&static_req).unwrap()["username"], "u");
    let _ = static_req.clone();
    assert!(format!("{static_req:?}").contains("DatabaseStaticRoleRequest"));

    let cfg: DatabaseConfig = from_value(json!({
        "plugin_name": "mysql-database-plugin", "connection_details": {}, "allowed_roles": ["r"]
    }))
    .unwrap();
    let _ = cfg.clone();
    assert!(format!("{cfg:?}").contains("DatabaseConfig"));

    let role: DatabaseRole = from_value(json!({
        "db_name": "db", "default_ttl": 3600, "max_ttl": 7200
    }))
    .unwrap();
    let _ = role.clone();
    assert!(format!("{role:?}").contains("DatabaseRole"));

    let static_role: DatabaseStaticRole = from_value(json!({
        "db_name": "db", "username": "u", "rotation_period": 86400
    }))
    .unwrap();
    let _ = static_role.clone();
    assert!(format!("{static_role:?}").contains("DatabaseStaticRole"));

    // Credentials + From impls (Debug redaction already tested elsewhere).
    let creds = DatabaseCredentials::from(("u", "p"));
    let _ = creds.clone();
    assert!(format!("{creds:?}").contains("DatabaseCredentials"));
    let creds2 = DatabaseCredentials::from((SecretString::from("u"), SecretString::from("p")));
    assert!(format!("{creds2:?}").contains("DatabaseCredentials"));
}

// ---------------------------------------------------------------------------
// ssh
// ---------------------------------------------------------------------------

#[test]
fn ssh_types() {
    let role_req = SshRoleRequest {
        key_type: "ca".into(),
        allow_user_certificates: Some(true),
        ..Default::default()
    };
    assert_eq!(to_value(&role_req).unwrap()["key_type"], "ca");
    let _ = role_req.clone();
    assert!(format!("{role_req:?}").contains("SshRoleRequest"));

    let sign_req = SshSignRequest {
        public_key: "ssh-rsa AAA".into(),
        valid_principals: Some("ubuntu".into()),
        cert_type: Some("user".into()),
        ttl: Some("1h".into()),
        ..Default::default()
    };
    assert!(to_value(&sign_req).unwrap()["public_key"].is_string());
    let _ = sign_req.clone();
    assert!(format!("{sign_req:?}").contains("SshSignRequest"));

    let ca_req = SshCaConfigRequest {
        generate_signing_key: Some(true),
        private_key: Some(SecretString::from("pk")),
        public_key: Some("pub".into()),
        key_type: Some("ssh-rsa".into()),
        key_bits: Some(2048),
    };
    assert_eq!(to_value(&ca_req).unwrap()["private_key"], "pk");
    let _ = ca_req.clone();
    assert!(format!("{ca_req:?}").contains("SshCaConfigRequest"));

    let verify_req = SshVerifyRequest {
        otp: SecretString::from("otp"),
    };
    assert_eq!(to_value(&verify_req).unwrap()["otp"], "otp");
    let _ = verify_req.clone();
    assert!(format!("{verify_req:?}").contains("SshVerifyRequest"));

    let role: SshRole = from_value(json!({
        "key_type": "ca", "default_user": "ubuntu", "allowed_users": "*", "ttl": "1h",
        "max_ttl": "2h", "allowed_critical_options": "", "allowed_extensions": "",
        "allow_user_certificates": true, "allow_host_certificates": false
    }))
    .unwrap();
    let _ = role.clone();
    assert!(format!("{role:?}").contains("SshRole"));

    let signed: SshSignedKey = from_value(json!({
        "serial_number": "01", "signed_key": "ssh-rsa-cert AAA"
    }))
    .unwrap();
    let _ = signed.clone();
    assert!(format!("{signed:?}").contains("SshSignedKey"));

    let ca_pub: SshCaPublicKey = from_value(json!({"public_key": "ssh-rsa AAA"})).unwrap();
    let _ = ca_pub.clone();
    assert!(format!("{ca_pub:?}").contains("SshCaPublicKey"));

    let verify: SshVerifyResponse =
        from_value(json!({"ip": "1.2.3.4", "username": "ubuntu"})).unwrap();
    let _ = verify.clone();
    assert!(format!("{verify:?}").contains("SshVerifyResponse"));
}

// ---------------------------------------------------------------------------
// rabbitmq
// ---------------------------------------------------------------------------

#[test]
fn rabbitmq_types() {
    let cfg_req = RabbitmqConfigRequest {
        connection_uri: "http://localhost:15672".into(),
        username: "admin".into(),
        password: Some(SecretString::from("pw")),
        verify_connection: Some(true),
    };
    assert_eq!(to_value(&cfg_req).unwrap()["password"], "pw");
    let _ = cfg_req.clone();
    assert!(format!("{cfg_req:?}").contains("RabbitmqConfigRequest"));

    let role_req = RabbitmqRoleRequest {
        vhosts: Some(json!({"/": {"configure": ".*"}})),
        vhost_topics: Some(json!({})),
        tags: Some("management".into()),
    };
    assert!(to_value(&role_req).unwrap()["vhosts"].is_object());
    let _ = role_req.clone();
    assert!(format!("{role_req:?}").contains("RabbitmqRoleRequest"));

    let role: RabbitmqRole = from_value(json!({
        "vhosts": {}, "vhost_topics": {}, "tags": "management"
    }))
    .unwrap();
    let _ = role.clone();
    assert!(format!("{role:?}").contains("RabbitmqRole"));

    let creds = RabbitmqCredentials::from(("u", "p"));
    let _ = creds.clone();
    assert!(format!("{creds:?}").contains("RabbitmqCredentials"));
    let creds2 = RabbitmqCredentials::from(("u".to_owned(), SecretString::from("p")));
    assert!(format!("{creds2:?}").contains("RabbitmqCredentials"));
}

// ---------------------------------------------------------------------------
// secret — MountPath / SecretPath trait impls
// ---------------------------------------------------------------------------

#[test]
fn secret_path_trait_impls() {
    use std::borrow::Borrow;

    let mp = MountPath::new("secret").unwrap();
    assert_eq!(mp.as_str(), "secret");
    assert_eq!(format!("{mp}"), "secret"); // Display
    let s: &str = mp.as_ref(); // AsRef
    assert_eq!(s, "secret");
    let b: &str = mp.borrow(); // Borrow
    assert_eq!(b, "secret");
    let owned: String = mp.clone().into(); // From<MountPath> for String
    assert_eq!(owned, "secret");
    let mp2 = MountPath::try_from("secret".to_string()).unwrap(); // TryFrom<String>
    assert_eq!(mp2, mp);
    let mp3: MountPath = "secret".try_into().unwrap(); // TryFrom<&str>
    assert_eq!(mp3, mp);
    assert!(MountPath::new("../bad").is_err());

    let sp = SecretPath::new("app/db").unwrap();
    assert_eq!(format!("{sp}"), "app/db");
    let sp_owned: String = sp.clone().into();
    assert_eq!(sp_owned, "app/db");
    // Deserialize impl (macro-generated)
    let de: SecretPath = serde_json::from_str("\"app/db\"").unwrap();
    assert_eq!(de, sp);
    assert!(serde_json::from_str::<SecretPath>("\"../evil\"").is_err());
}

// ---------------------------------------------------------------------------
// error — Display, From impls, predicates
// ---------------------------------------------------------------------------

#[test]
fn error_display_and_conversions() {
    let variants = vec![
        VaultError::Api {
            status: 500,
            errors: vec!["boom".into()],
        },
        VaultError::Sealed {
            url: "https://vault".into(),
        },
        VaultError::PermissionDenied {
            errors: vec!["denied".into()],
        },
        VaultError::NotFound {
            path: "secret/x".into(),
        },
        VaultError::RateLimited {
            retry_after: Some(5),
        },
        VaultError::RateLimited { retry_after: None },
        VaultError::ConsistencyRetry,
        VaultError::EmptyResponse,
        VaultError::AuthRequired,
        VaultError::Config("bad".into()),
        VaultError::LockPoisoned,
        VaultError::CircuitOpen,
        VaultError::FieldNotFound {
            mount: "secret".into(),
            path: "x".into(),
            field: "f".into(),
        },
    ];
    for v in &variants {
        // Display + Debug both run the generated formatting.
        assert!(!format!("{v}").is_empty());
        assert!(!format!("{v:?}").is_empty());
    }

    assert!(VaultError::ConsistencyRetry.is_retryable());
    assert!(VaultError::Sealed { url: "x".into() }.is_retryable());
    assert!(
        VaultError::Api {
            status: 503,
            errors: vec![]
        }
        .is_retryable()
    );
    assert!(
        !VaultError::Api {
            status: 400,
            errors: vec![]
        }
        .is_retryable()
    );
    assert!(VaultError::AuthRequired.is_auth_error());
    assert!(VaultError::PermissionDenied { errors: vec![] }.is_auth_error());
    assert!(!VaultError::EmptyResponse.is_auth_error());

    // From conversions.
    let de: VaultError = serde_json::from_str::<i32>("\"nope\"").unwrap_err().into();
    assert!(matches!(de, VaultError::Deserialize(_)));
    let utf8: VaultError = String::from_utf8(vec![0xff, 0xfe]).unwrap_err().into();
    assert!(matches!(utf8, VaultError::Config(_)));
    let int_err: VaultError = "x".parse::<i32>().unwrap_err().into();
    assert!(matches!(int_err, VaultError::Config(_)));
    let float_err: VaultError = "x".parse::<f64>().unwrap_err().into();
    assert!(matches!(float_err, VaultError::Config(_)));
}
