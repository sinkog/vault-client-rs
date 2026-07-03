//! Serde / `Clone` / `Debug` coverage for the auth and PKI type modules. Request
//! types are exercised via `Default` + serialize + clone + debug; response types
//! are deserialized from representative JSON, then cloned and debug-formatted so
//! the hand-written `Clone`/`Debug` (redaction) impls run. `Debug` assertions
//! check the struct name only — the global redaction level is shared across this
//! test binary, so asserting on `[REDACTED]` would be racy.

use secrecy::SecretString;
use serde_json::{from_value, json, to_value};

use vault_client_rs::types::auth::*;
use vault_client_rs::types::pki::*;

/// Exercise a `Default + Serialize + Clone + Debug` request type.
macro_rules! check_request {
    ($ty:ty, $name:literal) => {{
        let v = <$ty>::default();
        let _ = to_value(&v).unwrap();
        let c = v.clone();
        assert!(format!("{c:?}").contains($name));
    }};
}

// ---------------------------------------------------------------------------
// Auth — request types (Default-constructible)
// ---------------------------------------------------------------------------

#[test]
fn auth_request_types() {
    check_request!(TokenCreateRequest, "TokenCreateRequest");
    check_request!(AppRoleCreateRequest, "AppRoleCreateRequest");
    check_request!(K8sAuthConfigRequest, "K8sAuthConfigRequest");
    check_request!(K8sAuthRoleRequest, "K8sAuthRoleRequest");
    check_request!(UserpassUserRequest, "UserpassUserRequest");
    check_request!(LdapConfigRequest, "LdapConfigRequest");
    check_request!(LdapGroupRequest, "LdapGroupRequest");
    check_request!(LdapUserRequest, "LdapUserRequest");
    check_request!(CertRoleRequest, "CertRoleRequest");
    check_request!(GithubConfigRequest, "GithubConfigRequest");
    check_request!(GithubTeamMapping, "GithubTeamMapping");
    check_request!(OidcConfigRequest, "OidcConfigRequest");
    check_request!(OidcRoleRequest, "OidcRoleRequest");
    check_request!(RadiusUserRequest, "RadiusUserRequest");
    check_request!(KerberosConfigRequest, "KerberosConfigRequest");
    check_request!(KerberosLdapConfigRequest, "KerberosLdapConfigRequest");
    check_request!(KerberosGroupRequest, "KerberosGroupRequest");

    // RadiusConfigRequest has required fields (no Default).
    let radius = RadiusConfigRequest {
        host: "radius.example".into(),
        secret: SecretString::from("shared"),
        port: Some(1812),
        unregistered_user_policies: Some("default".into()),
        dial_timeout: Some(10),
        read_timeout: Some(10),
        nas_port: Some(10),
        token_policies: Some(vec!["p".into()]),
        token_ttl: Some("1h".into()),
        token_max_ttl: Some("2h".into()),
    };
    assert_eq!(to_value(&radius).unwrap()["secret"], "shared");
    let _ = radius.clone();
    assert!(format!("{radius:?}").contains("RadiusConfigRequest"));

    // Populated request to exercise the serialize_with secret helpers.
    let k8s = K8sAuthConfigRequest {
        kubernetes_host: "https://k8s".into(),
        kubernetes_ca_cert: Some("ca".into()),
        token_reviewer_jwt: Some(SecretString::from("jwt")),
        disable_local_ca_jwt: Some(true),
    };
    assert_eq!(to_value(&k8s).unwrap()["token_reviewer_jwt"], "jwt");
    let _ = k8s.clone();
}

// ---------------------------------------------------------------------------
// Auth — response types (deserialized)
// ---------------------------------------------------------------------------

#[test]
fn auth_response_types() {
    let lookup: TokenLookupResponse = from_value(json!({
        "accessor": "acc", "creation_time": 1, "creation_ttl": 3600,
        "display_name": "token", "entity_id": "eid", "explicit_max_ttl": 0,
        "id": "s.tok", "issue_time": "2024-01-01T00:00:00Z", "num_uses": 0,
        "orphan": false, "path": "auth/token/create", "policies": ["default"],
        "renewable": true, "ttl": 3600, "type": "service"
    }))
    .unwrap();
    assert_eq!(lookup.accessor, "acc");
    let _ = lookup.clone();
    assert!(format!("{lookup:?}").contains("TokenLookupResponse"));

    let approle: AppRoleInfo = from_value(json!({
        "bind_secret_id": true, "secret_id_bound_cidrs": null, "token_bound_cidrs": null,
        "token_policies": null, "token_ttl": 60, "token_max_ttl": 120,
        "token_num_uses": 0, "token_type": "service"
    }))
    .unwrap();
    assert!(approle.bind_secret_id);
    let _ = approle.clone();
    assert!(format!("{approle:?}").contains("AppRoleInfo"));

    let secret_id: AppRoleSecretIdResponse = from_value(json!({
        "secret_id": "sid", "secret_id_accessor": "sacc",
        "secret_id_num_uses": 0, "secret_id_ttl": 60
    }))
    .unwrap();
    let _ = secret_id.clone();
    assert!(format!("{secret_id:?}").contains("AppRoleSecretIdResponse"));

    let k8s_role: K8sAuthRoleInfo = from_value(json!({})).unwrap();
    let _ = k8s_role.clone();
    assert!(format!("{k8s_role:?}").contains("K8sAuthRoleInfo"));

    let userpass: UserpassUserInfo = from_value(json!({
        "token_ttl": 60, "token_max_ttl": 120, "token_num_uses": 0
    }))
    .unwrap();
    let _ = userpass.clone();
    assert!(format!("{userpass:?}").contains("UserpassUserInfo"));

    let ldap_cfg: LdapConfig = from_value(json!({
        "url": "ldap://x", "userdn": "dc=x", "userattr": "uid", "groupdn": "ou=g",
        "groupattr": "cn", "groupfilter": "(x)", "starttls": true, "insecure_tls": false
    }))
    .unwrap();
    let _ = ldap_cfg.clone();
    assert!(format!("{ldap_cfg:?}").contains("LdapConfig"));

    let ldap_group: LdapGroup = from_value(json!({})).unwrap();
    let _ = ldap_group.clone();
    assert!(format!("{ldap_group:?}").contains("LdapGroup"));
    let ldap_user: LdapUser = from_value(json!({})).unwrap();
    let _ = ldap_user.clone();
    assert!(format!("{ldap_user:?}").contains("LdapUser"));

    let cert_role: CertRoleInfo = from_value(json!({
        "certificate": "cert", "token_ttl": 60, "token_max_ttl": 120, "display_name": "dn"
    }))
    .unwrap();
    let _ = cert_role.clone();
    assert!(format!("{cert_role:?}").contains("CertRoleInfo"));

    let gh_cfg: GithubConfig = from_value(json!({
        "organization": "org", "base_url": "https://api.github.com",
        "token_ttl": 60, "token_max_ttl": 120
    }))
    .unwrap();
    let _ = gh_cfg.clone();
    assert!(format!("{gh_cfg:?}").contains("GithubConfig"));
    let gh_team: GithubTeamInfo = from_value(json!({})).unwrap();
    let _ = gh_team.clone();
    assert!(format!("{gh_team:?}").contains("GithubTeamInfo"));

    let oidc_cfg: OidcConfig = from_value(json!({})).unwrap();
    let _ = oidc_cfg.clone();
    assert!(format!("{oidc_cfg:?}").contains("OidcConfig"));
    let oidc_role: OidcRoleInfo = from_value(json!({
        "role_type": "oidc", "user_claim": "sub", "token_ttl": 60, "token_max_ttl": 120
    }))
    .unwrap();
    let _ = oidc_role.clone();
    assert!(format!("{oidc_role:?}").contains("OidcRoleInfo"));

    let radius_cfg: RadiusConfig = from_value(json!({"host": "radius.example"})).unwrap();
    let _ = radius_cfg.clone();
    assert!(format!("{radius_cfg:?}").contains("RadiusConfig"));
    let radius_user: RadiusUser = from_value(json!({})).unwrap();
    let _ = radius_user.clone();
    assert!(format!("{radius_user:?}").contains("RadiusUser"));

    let krb_cfg: KerberosConfig = from_value(json!({})).unwrap();
    let _ = krb_cfg.clone();
    assert!(format!("{krb_cfg:?}").contains("KerberosConfig"));
    let krb_ldap: KerberosLdapConfig = from_value(json!({
        "url": "ldap://x", "starttls": true, "insecure_tls": false
    }))
    .unwrap();
    let _ = krb_ldap.clone();
    assert!(format!("{krb_ldap:?}").contains("KerberosLdapConfig"));
    let krb_group: KerberosGroup = from_value(json!({})).unwrap();
    let _ = krb_group.clone();
    assert!(format!("{krb_group:?}").contains("KerberosGroup"));
}

// ---------------------------------------------------------------------------
// PKI — request types (Default-constructible)
// ---------------------------------------------------------------------------

#[test]
fn pki_request_types() {
    check_request!(PkiRootParams, "PkiRootParams");
    check_request!(PkiIntermediateParams, "PkiIntermediateParams");
    check_request!(PkiRoleParams, "PkiRoleParams");
    check_request!(PkiIssueParams, "PkiIssueParams");
    check_request!(PkiSignParams, "PkiSignParams");
    check_request!(PkiTidyParams, "PkiTidyParams");
    check_request!(PkiIssuerUpdateParams, "PkiIssuerUpdateParams");
    check_request!(PkiCrossSignRequest, "PkiCrossSignRequest");
    check_request!(PkiUrlsConfig, "PkiUrlsConfig");
    check_request!(PkiAcmeConfig, "PkiAcmeConfig");
}

// ---------------------------------------------------------------------------
// PKI — response types (deserialized)
// ---------------------------------------------------------------------------

#[test]
fn pki_response_types() {
    let cert: PkiCertificate = from_value(json!({
        "certificate": "-----CERT-----", "issuing_ca": "-----CA-----",
        "ca_chain": ["-----CA-----"], "serial_number": "01:02", "expiration": 100,
        "private_key": "-----KEY-----", "private_key_type": "rsa"
    }))
    .unwrap();
    let _ = cert.clone();
    assert!(format!("{cert:?}").contains("PkiCertificate"));

    let csr: PkiCsr = from_value(json!({
        "csr": "-----CSR-----", "private_key": "-----KEY-----", "private_key_type": "rsa"
    }))
    .unwrap();
    let _ = csr.clone();
    assert!(format!("{csr:?}").contains("PkiCsr"));

    let issued: PkiIssuedCert = from_value(json!({
        "certificate": "-----CERT-----", "issuing_ca": "-----CA-----", "ca_chain": [],
        "private_key": "-----KEY-----", "private_key_type": "rsa",
        "serial_number": "01:02", "expiration": 100
    }))
    .unwrap();
    let _ = issued.clone();
    assert!(format!("{issued:?}").contains("PkiIssuedCert"));

    let import: PkiImportResult = from_value(json!({})).unwrap();
    let _ = import.clone();
    assert!(format!("{import:?}").contains("PkiImportResult"));

    let issuer: PkiIssuerInfo = from_value(json!({
        "issuer_id": "iid", "certificate": "-----CERT-----"
    }))
    .unwrap();
    let _ = issuer.clone();
    assert!(format!("{issuer:?}").contains("PkiIssuerInfo"));

    let role: PkiRole = from_value(json!({
        "ttl": 3600, "max_ttl": 7200, "allow_localhost": true, "allowed_domains": ["x.com"],
        "allow_bare_domains": false, "allow_subdomains": true, "allow_any_name": false,
        "enforce_hostnames": true, "allow_ip_sans": true, "server_flag": true,
        "client_flag": true, "key_type": "rsa", "key_bits": 2048
    }))
    .unwrap();
    let _ = role.clone();
    assert!(format!("{role:?}").contains("PkiRole"));

    let signed: PkiSignedCert = from_value(json!({
        "certificate": "-----CERT-----", "issuing_ca": "-----CA-----",
        "serial_number": "01:02", "expiration": 100
    }))
    .unwrap();
    let _ = signed.clone();
    assert!(format!("{signed:?}").contains("PkiSignedCert"));

    let revocation: PkiRevocationInfo = from_value(json!({"revocation_time": 100})).unwrap();
    let _ = revocation.clone();
    assert!(format!("{revocation:?}").contains("PkiRevocationInfo"));

    let entry: PkiCertificateEntry = from_value(json!({"certificate": "-----CERT-----"})).unwrap();
    let _ = entry.clone();
    assert!(format!("{entry:?}").contains("PkiCertificateEntry"));

    let tidy: PkiTidyStatus = from_value(json!({})).unwrap();
    let _ = tidy.clone();
    assert!(format!("{tidy:?}").contains("PkiTidyStatus"));

    let urls: PkiUrlsConfig = from_value(json!({
        "issuing_certificates": ["https://x/ca"], "crl_distribution_points": [],
        "ocsp_servers": []
    }))
    .unwrap();
    let _ = urls.clone();
    assert!(format!("{urls:?}").contains("PkiUrlsConfig"));

    let acme: PkiAcmeConfig = from_value(json!({"enabled": true})).unwrap();
    assert!(acme.enabled);
    let _ = acme.clone();
    assert!(format!("{acme:?}").contains("PkiAcmeConfig"));
}
