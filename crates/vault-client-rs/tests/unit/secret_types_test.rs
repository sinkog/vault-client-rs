//! Serde round-trip, `Clone`, `Debug`, and `From` coverage for the secrets-
//! engine and auth type modules that carry hand-written impls (aws, azure, gcp,
//! consul, nomad, terraform, totp). Each request type is serialized, each
//! response type is deserialized, and every custom `Clone`/`Debug`/`From` impl
//! is exercised. `Debug` assertions check for the struct name only (the global
//! redaction level can be flipped by other tests in this binary), which is
//! enough to cover the formatting code without flaking.

use secrecy::SecretString;
use serde_json::{from_value, json, to_value};

use vault_client_rs::types::aws::*;
use vault_client_rs::types::azure::*;
use vault_client_rs::types::consul::*;
use vault_client_rs::types::gcp::*;
use vault_client_rs::types::nomad::*;
use vault_client_rs::types::terraform::*;
use vault_client_rs::types::totp::*;

// ---------------------------------------------------------------------------
// AWS
// ---------------------------------------------------------------------------

#[test]
fn aws_types_roundtrip() {
    let root_req = AwsConfigRootRequest {
        access_key: Some("AKIA".into()),
        secret_key: Some(SecretString::from("shhh")),
        region: Some("us-east-1".into()),
        iam_endpoint: Some("https://iam".into()),
        sts_endpoint: Some("https://sts".into()),
        max_retries: Some(3),
    };
    let json = to_value(&root_req).unwrap();
    assert_eq!(json["access_key"], "AKIA");
    assert_eq!(json["secret_key"], "shhh");
    let _ = root_req.clone();
    assert!(format!("{root_req:?}").contains("AwsConfigRootRequest"));

    let root: AwsConfigRoot = from_value(json!({
        "access_key": "AKIA", "region": "us-east-1",
        "iam_endpoint": "https://iam", "sts_endpoint": "https://sts", "max_retries": 3
    }))
    .unwrap();
    assert_eq!(root.region, "us-east-1");
    let _ = root.clone();
    assert!(format!("{root:?}").contains("AwsConfigRoot"));

    let role_req = AwsRoleRequest {
        credential_type: Some("iam_user".into()),
        role_arns: Some(vec!["arn:x".into()]),
        policy_arns: Some(vec!["arn:p".into()]),
        policy_document: Some("{}".into()),
        iam_groups: Some(vec!["g".into()]),
        iam_tags: Some(json!({"k": "v"})),
        default_sts_ttl: Some("1h".into()),
        max_sts_ttl: Some("2h".into()),
        user_path: Some("/".into()),
        permissions_boundary_arn: Some("arn:b".into()),
    };
    assert_eq!(to_value(&role_req).unwrap()["credential_type"], "iam_user");
    let _ = role_req.clone();
    assert!(format!("{role_req:?}").contains("AwsRoleRequest"));

    let role: AwsRole = from_value(json!({
        "credential_type": "iam_user", "role_arns": ["arn:x"], "policy_arns": [],
        "policy_document": "{}", "iam_groups": [], "default_sts_ttl": 3600, "max_sts_ttl": 7200
    }))
    .unwrap();
    assert_eq!(role.default_sts_ttl, 3600);
    let _ = role.clone();
    assert!(format!("{role:?}").contains("AwsRole"));

    let creds: AwsCredentials = from_value(json!({
        "access_key": "AKIA", "secret_key": "sk", "security_token": "tok", "arn": "arn:x"
    }))
    .unwrap();
    let _ = creds.clone();
    assert!(format!("{creds:?}").contains("AwsCredentials"));

    let sts = AwsStsRequest {
        role_arn: Some("arn:r".into()),
        ttl: Some("15m".into()),
    };
    assert_eq!(to_value(&sts).unwrap()["ttl"], "15m");
    let _ = sts.clone();
    assert!(format!("{sts:?}").contains("AwsStsRequest"));

    let auth_cfg_req = AwsAuthConfigRequest {
        access_key: Some("AKIA".into()),
        secret_key: Some(SecretString::from("sk")),
        endpoint: Some("https://ec2".into()),
        iam_endpoint: Some("https://iam".into()),
        sts_endpoint: Some("https://sts".into()),
        sts_region: Some("us-east-1".into()),
        max_retries: Some(1),
    };
    assert_eq!(to_value(&auth_cfg_req).unwrap()["secret_key"], "sk");
    let _ = auth_cfg_req.clone();
    assert!(format!("{auth_cfg_req:?}").contains("AwsAuthConfigRequest"));

    let auth_cfg: AwsAuthConfig = from_value(json!({"access_key": "AKIA"})).unwrap();
    assert_eq!(auth_cfg.access_key, "AKIA");
    let _ = auth_cfg.clone();
    assert!(format!("{auth_cfg:?}").contains("AwsAuthConfig"));

    let auth_role_req = AwsAuthRoleRequest {
        auth_type: Some("iam".into()),
        bound_iam_principal_arn: Some(vec!["arn:x".into()]),
        token_policies: Some(vec!["p".into()]),
        ..Default::default()
    };
    assert_eq!(to_value(&auth_role_req).unwrap()["auth_type"], "iam");
    let _ = auth_role_req.clone();
    assert!(format!("{auth_role_req:?}").contains("AwsAuthRoleRequest"));

    let auth_role: AwsAuthRoleInfo = from_value(json!({"auth_type": "iam"})).unwrap();
    assert_eq!(auth_role.auth_type, "iam");
    let _ = auth_role.clone();
    assert!(format!("{auth_role:?}").contains("AwsAuthRoleInfo"));

    let login = AwsAuthLoginRequest {
        role: Some("dev".into()),
        identity: Some(SecretString::from("id")),
        signature: Some(SecretString::from("sig")),
        pkcs7: Some(SecretString::from("p7")),
        nonce: Some("n".into()),
        iam_http_request_method: Some("POST".into()),
        iam_request_url: Some("https://sts".into()),
        iam_request_body: Some("body".into()),
        iam_request_headers: Some("{}".into()),
    };
    assert_eq!(to_value(&login).unwrap()["identity"], "id");
    let _ = login.clone();
    assert!(format!("{login:?}").contains("AwsAuthLoginRequest"));
}

// ---------------------------------------------------------------------------
// Azure
// ---------------------------------------------------------------------------

#[test]
fn azure_types_roundtrip() {
    let cfg_req = AzureConfigRequest {
        subscription_id: Some("sub".into()),
        tenant_id: Some("ten".into()),
        client_id: Some("cid".into()),
        client_secret: Some(SecretString::from("cs")),
        environment: Some("AzurePublicCloud".into()),
    };
    assert_eq!(to_value(&cfg_req).unwrap()["client_secret"], "cs");
    let _ = cfg_req.clone();
    assert!(format!("{cfg_req:?}").contains("AzureConfigRequest"));

    let cfg: AzureConfig =
        from_value(json!({"subscription_id": "sub", "tenant_id": "ten"})).unwrap();
    assert_eq!(cfg.subscription_id, "sub");
    let _ = cfg.clone();
    assert!(format!("{cfg:?}").contains("AzureConfig"));

    let role_req = AzureRoleRequest {
        azure_roles: Some(json!([{"role_name": "r"}])),
        azure_groups: Some(json!([])),
        application_object_id: Some("obj".into()),
        ttl: Some("1h".into()),
        max_ttl: Some("2h".into()),
    };
    assert_eq!(to_value(&role_req).unwrap()["application_object_id"], "obj");
    let _ = role_req.clone();
    assert!(format!("{role_req:?}").contains("AzureRoleRequest"));

    let role: AzureRole = from_value(json!({
        "azure_roles": [], "azure_groups": [], "application_object_id": "obj",
        "ttl": 3600, "max_ttl": 7200
    }))
    .unwrap();
    assert_eq!(role.ttl, 3600);
    let _ = role.clone();
    assert!(format!("{role:?}").contains("AzureRole"));

    let creds: AzureCredentials =
        from_value(json!({"client_id": "cid", "client_secret": "cs"})).unwrap();
    let _ = creds.clone();
    assert!(format!("{creds:?}").contains("AzureCredentials"));
    // From impls
    let from_tuple = AzureCredentials::from(("cid".to_owned(), SecretString::from("cs")));
    assert!(format!("{from_tuple:?}").contains("AzureCredentials"));
    let from_strs = AzureCredentials::from(("cid", "cs"));
    assert!(format!("{from_strs:?}").contains("AzureCredentials"));

    let auth_cfg_req = AzureAuthConfigRequest {
        tenant_id: Some("ten".into()),
        resource: Some("res".into()),
        environment: Some("env".into()),
        client_id: Some("cid".into()),
        client_secret: Some(SecretString::from("cs")),
    };
    assert_eq!(to_value(&auth_cfg_req).unwrap()["client_secret"], "cs");
    let _ = auth_cfg_req.clone();
    assert!(format!("{auth_cfg_req:?}").contains("AzureAuthConfigRequest"));

    let auth_cfg: AzureAuthConfig = from_value(json!({"tenant_id": "ten"})).unwrap();
    assert_eq!(auth_cfg.tenant_id, "ten");
    let _ = auth_cfg.clone();
    assert!(format!("{auth_cfg:?}").contains("AzureAuthConfig"));

    let auth_role_req = AzureAuthRoleRequest {
        bound_service_principal_ids: Some(vec!["sp".into()]),
        token_policies: Some(vec!["p".into()]),
        ..Default::default()
    };
    assert!(to_value(&auth_role_req).unwrap()["bound_service_principal_ids"].is_array());
    let _ = auth_role_req.clone();
    assert!(format!("{auth_role_req:?}").contains("AzureAuthRoleRequest"));

    let auth_role: AzureAuthRoleInfo = from_value(json!({"token_ttl": 60})).unwrap();
    assert_eq!(auth_role.token_ttl, 60);
    let _ = auth_role.clone();
    assert!(format!("{auth_role:?}").contains("AzureAuthRoleInfo"));

    let login = AzureAuthLoginRequest {
        role: "dev".into(),
        jwt: SecretString::from("jwt"),
        subscription_id: Some("sub".into()),
        resource_group_name: Some("rg".into()),
        vm_name: Some("vm".into()),
        vmss_name: Some("vmss".into()),
    };
    assert_eq!(to_value(&login).unwrap()["jwt"], "jwt");
    let _ = login.clone();
    assert!(format!("{login:?}").contains("AzureAuthLoginRequest"));
}

// ---------------------------------------------------------------------------
// GCP
// ---------------------------------------------------------------------------

#[test]
fn gcp_types_roundtrip() {
    let cfg_req = GcpConfigRequest {
        credentials: Some(SecretString::from("{json}")),
        ttl: Some("1h".into()),
        max_ttl: Some("2h".into()),
    };
    assert_eq!(to_value(&cfg_req).unwrap()["credentials"], "{json}");
    let _ = cfg_req.clone();
    assert!(format!("{cfg_req:?}").contains("GcpConfigRequest"));

    let cfg: GcpConfig = from_value(json!({"ttl": 3600, "max_ttl": 7200})).unwrap();
    assert_eq!(cfg.ttl, 3600);
    let _ = cfg.clone();
    assert!(format!("{cfg:?}").contains("GcpConfig"));

    let rs_req = GcpRolesetRequest {
        project: Some("proj".into()),
        bindings: Some("resource \"x\" {}".into()),
        secret_type: Some("access_token".into()),
        token_scopes: Some(vec!["scope".into()]),
    };
    assert_eq!(to_value(&rs_req).unwrap()["project"], "proj");
    let _ = rs_req.clone();
    assert!(format!("{rs_req:?}").contains("GcpRolesetRequest"));

    let rs: GcpRoleset = from_value(json!({
        "project": "proj", "bindings": {}, "secret_type": "access_token",
        "token_scopes": [], "service_account_email": "sa@x"
    }))
    .unwrap();
    assert_eq!(rs.project, "proj");
    let _ = rs.clone();
    assert!(format!("{rs:?}").contains("GcpRoleset"));

    let sa_key: GcpServiceAccountKey = from_value(json!({
        "private_key_data": "pk", "key_algorithm": "RSA", "key_type": "json"
    }))
    .unwrap();
    let _ = sa_key.clone();
    assert!(format!("{sa_key:?}").contains("GcpServiceAccountKey"));

    let oauth: GcpOAuthToken = from_value(json!({
        "token": "tok", "expires_at_seconds": 100, "token_ttl": 60
    }))
    .unwrap();
    let _ = oauth.clone();
    assert!(format!("{oauth:?}").contains("GcpOAuthToken"));

    let auth_cfg_req = GcpAuthConfigRequest {
        credentials: Some(SecretString::from("{json}")),
        iam_alias: Some("role_id".into()),
        gce_alias: Some("instance_id".into()),
    };
    assert_eq!(to_value(&auth_cfg_req).unwrap()["credentials"], "{json}");
    let _ = auth_cfg_req.clone();
    assert!(format!("{auth_cfg_req:?}").contains("GcpAuthConfigRequest"));

    let auth_cfg: GcpAuthConfig = from_value(json!({"iam_alias": "role_id"})).unwrap();
    assert_eq!(auth_cfg.iam_alias, "role_id");
    let _ = auth_cfg.clone();
    assert!(format!("{auth_cfg:?}").contains("GcpAuthConfig"));

    let auth_role_req = GcpAuthRoleRequest {
        role_type: "iam".into(),
        bound_service_accounts: Some(vec!["sa@x".into()]),
        token_policies: Some(vec!["p".into()]),
        ..Default::default()
    };
    assert_eq!(to_value(&auth_role_req).unwrap()["type"], "iam");
    let _ = auth_role_req.clone();
    assert!(format!("{auth_role_req:?}").contains("GcpAuthRoleRequest"));

    let auth_role: GcpAuthRoleInfo = from_value(json!({"type": "iam", "token_ttl": 60})).unwrap();
    assert_eq!(auth_role.role_type, "iam");
    let _ = auth_role.clone();
    assert!(format!("{auth_role:?}").contains("GcpAuthRoleInfo"));
}

// ---------------------------------------------------------------------------
// Consul
// ---------------------------------------------------------------------------

#[test]
fn consul_types_roundtrip() {
    let cfg_req = ConsulConfigRequest {
        address: "127.0.0.1:8500".into(),
        scheme: Some("https".into()),
        token: Some(SecretString::from("tok")),
    };
    assert_eq!(to_value(&cfg_req).unwrap()["token"], "tok");
    let _ = cfg_req.clone();
    assert!(format!("{cfg_req:?}").contains("ConsulConfigRequest"));

    let cfg: ConsulConfig =
        from_value(json!({"address": "127.0.0.1:8500", "scheme": "https"})).unwrap();
    assert_eq!(cfg.scheme, "https");
    let _ = cfg.clone();
    assert!(format!("{cfg:?}").contains("ConsulConfig"));

    let role_req = ConsulRoleRequest {
        consul_policies: Some(vec!["p".into()]),
        local: Some(true),
        ttl: Some("1h".into()),
        ..Default::default()
    };
    assert_eq!(to_value(&role_req).unwrap()["local"], true);
    let _ = role_req.clone();
    assert!(format!("{role_req:?}").contains("ConsulRoleRequest"));

    let role: ConsulRole = from_value(json!({
        "consul_policies": ["p"], "ttl": 3600, "max_ttl": 7200, "local": true
    }))
    .unwrap();
    assert!(role.local);
    let _ = role.clone();
    assert!(format!("{role:?}").contains("ConsulRole"));

    let creds: ConsulCredentials = from_value(json!({"token": "tok"})).unwrap();
    let _ = creds.clone();
    assert!(format!("{creds:?}").contains("ConsulCredentials"));
    let from_secret = ConsulCredentials::from(SecretString::from("tok"));
    assert!(format!("{from_secret:?}").contains("ConsulCredentials"));
    let from_str = ConsulCredentials::from("tok");
    assert!(format!("{from_str:?}").contains("ConsulCredentials"));
}

// ---------------------------------------------------------------------------
// Nomad
// ---------------------------------------------------------------------------

#[test]
fn nomad_types_roundtrip() {
    let cfg_req = NomadConfigRequest {
        address: "http://127.0.0.1:4646".into(),
        token: Some(SecretString::from("tok")),
        max_token_name_length: Some(64),
    };
    assert_eq!(to_value(&cfg_req).unwrap()["token"], "tok");
    let _ = cfg_req.clone();
    assert!(format!("{cfg_req:?}").contains("NomadConfigRequest"));

    let cfg: NomadConfig =
        from_value(json!({"address": "http://127.0.0.1:4646", "max_token_name_length": 64}))
            .unwrap();
    assert_eq!(cfg.max_token_name_length, 64);
    let _ = cfg.clone();
    assert!(format!("{cfg:?}").contains("NomadConfig"));

    let role_req = NomadRoleRequest {
        policies: Some(vec!["p".into()]),
        token_type: Some("client".into()),
        global: Some(false),
    };
    assert_eq!(to_value(&role_req).unwrap()["type"], "client");
    let _ = role_req.clone();
    assert!(format!("{role_req:?}").contains("NomadRoleRequest"));

    let role: NomadRole =
        from_value(json!({"policies": ["p"], "type": "client", "global": false})).unwrap();
    assert_eq!(role.token_type, "client");
    let _ = role.clone();
    assert!(format!("{role:?}").contains("NomadRole"));

    let creds: NomadCredentials =
        from_value(json!({"secret_id": "sid", "accessor_id": "aid"})).unwrap();
    let _ = creds.clone();
    assert!(format!("{creds:?}").contains("NomadCredentials"));
    let from_tuple = NomadCredentials::from(("aid".to_owned(), SecretString::from("sid")));
    assert_eq!(from_tuple.accessor_id, "aid");
    let from_strs = NomadCredentials::from(("aid", "sid"));
    assert_eq!(from_strs.accessor_id, "aid");
}

// ---------------------------------------------------------------------------
// Terraform Cloud
// ---------------------------------------------------------------------------

#[test]
fn terraform_types_roundtrip() {
    let cfg_req = TerraformCloudConfigRequest {
        token: SecretString::from("tok"),
        address: Some("https://app.terraform.io".into()),
    };
    assert_eq!(to_value(&cfg_req).unwrap()["token"], "tok");
    let _ = cfg_req.clone();
    assert!(format!("{cfg_req:?}").contains("TerraformCloudConfigRequest"));

    let cfg: TerraformCloudConfig =
        from_value(json!({"address": "https://app.terraform.io"})).unwrap();
    assert_eq!(cfg.address, "https://app.terraform.io");
    let _ = cfg.clone();
    assert!(format!("{cfg:?}").contains("TerraformCloudConfig"));

    let role_req = TerraformCloudRoleRequest {
        organization: Some("org".into()),
        team_id: Some("team".into()),
        user_id: Some("user".into()),
        ttl: Some("1h".into()),
        max_ttl: Some("2h".into()),
    };
    assert_eq!(to_value(&role_req).unwrap()["organization"], "org");
    let _ = role_req.clone();
    assert!(format!("{role_req:?}").contains("TerraformCloudRoleRequest"));

    let role: TerraformCloudRole = from_value(json!({
        "organization": "org", "team_id": "team", "user_id": "user", "ttl": 3600, "max_ttl": 7200
    }))
    .unwrap();
    assert_eq!(role.organization, "org");
    let _ = role.clone();
    assert!(format!("{role:?}").contains("TerraformCloudRole"));

    let token: TerraformCloudToken =
        from_value(json!({"token": "tok", "token_id": "tid"})).unwrap();
    let _ = token.clone();
    assert!(format!("{token:?}").contains("TerraformCloudToken"));
    let from_secret = TerraformCloudToken::from(SecretString::from("tok"));
    assert!(format!("{from_secret:?}").contains("TerraformCloudToken"));
}

// ---------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------

#[test]
fn totp_types_roundtrip() {
    let key_req = TotpKeyRequest {
        generate: true,
        exported: Some(true),
        key_size: Some(20),
        url: Some("otpauth://".into()),
        key: Some(SecretString::from("secretkey")),
        issuer: Some("Vault".into()),
        account_name: Some("user@x".into()),
        period: Some(30),
        algorithm: Some("SHA1".into()),
        digits: Some(6),
        skew: Some(1),
        qr_size: Some(200),
    };
    let json = to_value(&key_req).unwrap();
    assert_eq!(json["generate"], true);
    assert_eq!(json["key"], "secretkey");
    let _ = key_req.clone();
    assert!(format!("{key_req:?}").contains("TotpKeyRequest"));

    let key_info: TotpKeyInfo = from_value(json!({
        "account_name": "user@x", "algorithm": "SHA1", "digits": 6, "issuer": "Vault", "period": 30
    }))
    .unwrap();
    assert_eq!(key_info.digits, 6);
    let _ = key_info.clone();
    assert!(format!("{key_info:?}").contains("TotpKeyInfo"));

    let gen_resp: TotpGenerateResponse =
        from_value(json!({"barcode": "data:image", "url": "otpauth://"})).unwrap();
    let _ = gen_resp.clone();
    assert!(format!("{gen_resp:?}").contains("TotpGenerateResponse"));

    let code: TotpCode = from_value(json!({"code": "123456"})).unwrap();
    let _ = code.clone();
    assert!(format!("{code:?}").contains("TotpCode"));
    let from_secret = TotpCode::from(SecretString::from("123456"));
    assert!(format!("{from_secret:?}").contains("TotpCode"));
    let from_str = TotpCode::from("123456");
    assert!(format!("{from_str:?}").contains("TotpCode"));

    let validation: TotpValidation = from_value(json!({"valid": true})).unwrap();
    assert!(validation.valid);
    let _ = validation.clone();
    assert!(format!("{validation:?}").contains("TotpValidation"));
}
