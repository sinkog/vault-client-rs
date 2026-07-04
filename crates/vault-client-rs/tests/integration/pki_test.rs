use std::time::Duration;

use vault_client_rs::types::pki::*;
use vault_client_rs::{PkiOperations, VaultClient, VaultError};

use crate::common::*;

fn client() -> VaultClient {
    build_client(&vault_addr(), vault_token())
}

/// Fixture for PKI tests: a mounted PKI engine with a root CA and a role
struct PkiFixture {
    mount: String,
    role_name: String,
}

async fn setup_pki(client: &VaultClient) -> PkiFixture {
    let mount = mount_pki(client).await;
    let role_name = unique_name("role");

    // Generate internal root CA
    client
        .pki(&mount)
        .generate_root(&PkiRootParams {
            generate_type: "internal".into(),
            common_name: "Test Root CA".into(),
            ttl: Some("87600h".into()),
            ..Default::default()
        })
        .await
        .unwrap();

    // Create a role
    client
        .pki(&mount)
        .create_role(
            &role_name,
            &PkiRoleParams {
                allowed_domains: Some(vec!["example.com".into()]),
                allow_subdomains: Some(true),
                allow_any_name: Some(true),
                max_ttl: Some("72h".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    PkiFixture { mount, role_name }
}

async fn teardown_pki(client: &VaultClient, fixture: &PkiFixture) {
    let _ = client.sys().unmount(&fixture.mount).await;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn generate_root_and_read_issuer() {
    let client = client();
    let mount = mount_pki(&client).await;

    let cert = client
        .pki(&mount)
        .generate_root(&PkiRootParams {
            generate_type: "internal".into(),
            common_name: "Root CA".into(),
            ttl: Some("87600h".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!cert.certificate.is_empty());
    assert!(!cert.serial_number.is_empty());

    let issuers = client.pki(&mount).list_issuers().await.unwrap();
    assert!(!issuers.is_empty());

    let issuer_info = client.pki(&mount).read_issuer(&issuers[0]).await.unwrap();
    assert!(!issuer_info.certificate.is_empty());

    client.sys().unmount(&mount).await.unwrap();
}

#[tokio::test]
async fn role_crud() {
    let client = client();
    let fixture = setup_pki(&client).await;
    let pki = client.pki(&fixture.mount);

    // Read the role we created in setup
    let role = pki.read_role(&fixture.role_name).await.unwrap();
    assert!(role.allow_any_name);

    // List roles
    let roles = pki.list_roles().await.unwrap();
    assert!(roles.contains(&fixture.role_name));

    // Create another role, then delete it
    let extra = unique_name("xrole");
    pki.create_role(
        &extra,
        &PkiRoleParams {
            allow_any_name: Some(true),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    pki.delete_role(&extra).await.unwrap();
    let roles_after = pki.list_roles().await.unwrap();
    assert!(!roles_after.contains(&extra));

    teardown_pki(&client, &fixture).await;
}

#[tokio::test]
async fn issue_cert() {
    let client = client();
    let fixture = setup_pki(&client).await;

    let issued = client
        .pki(&fixture.mount)
        .issue(
            &fixture.role_name,
            &PkiIssueParams {
                common_name: "test.example.com".into(),
                ttl: Some("24h".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert!(!issued.certificate.is_empty());
    assert!(!issued.serial_number.is_empty());
    assert!(!issued.issuing_ca.is_empty());

    teardown_pki(&client, &fixture).await;
}

#[tokio::test]
async fn list_read_cert() {
    let client = client();
    let fixture = setup_pki(&client).await;
    let pki = client.pki(&fixture.mount);

    let issued = pki
        .issue(
            &fixture.role_name,
            &PkiIssueParams {
                common_name: "cert.example.com".into(),
                ttl: Some("1h".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let certs = pki.list_certs().await.unwrap();
    assert!(!certs.is_empty());

    let entry = pki.read_cert(&issued.serial_number).await.unwrap();
    assert!(!entry.certificate.is_empty());

    teardown_pki(&client, &fixture).await;
}

#[tokio::test]
async fn revoke_cert() {
    let client = client();
    let fixture = setup_pki(&client).await;
    let pki = client.pki(&fixture.mount);

    let issued = pki
        .issue(
            &fixture.role_name,
            &PkiIssueParams {
                common_name: "revoke.example.com".into(),
                ttl: Some("1h".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let revocation = pki.revoke(&issued.serial_number).await.unwrap();
    assert!(revocation.revocation_time > 0);

    teardown_pki(&client, &fixture).await;
}

#[tokio::test]
async fn rotate_crl() {
    let client = client();
    let fixture = setup_pki(&client).await;

    // Some Vault versions (e.g. dev server) return 405 for CRL rotation
    let result = client.pki(&fixture.mount).rotate_crl().await;
    match &result {
        Ok(()) => {}
        Err(VaultError::Api { status: 405, .. }) => {}
        Err(e) => panic!("unexpected error: {e}"),
    }

    teardown_pki(&client, &fixture).await;
}

#[tokio::test]
async fn set_read_urls() {
    let client = client();
    let fixture = setup_pki(&client).await;
    let pki = client.pki(&fixture.mount);

    pki.set_urls(&PkiUrlsConfig {
        issuing_certificates: vec!["https://vault.example.com/v1/pki/ca".into()],
        crl_distribution_points: vec!["https://vault.example.com/v1/pki/crl".into()],
        ocsp_servers: vec![],
    })
    .await
    .unwrap();

    let urls = pki.read_urls().await.unwrap();
    assert_eq!(urls.issuing_certificates.len(), 1);
    assert!(urls.issuing_certificates[0].contains("vault.example.com"));
    assert_eq!(urls.crl_distribution_points.len(), 1);

    teardown_pki(&client, &fixture).await;
}

#[tokio::test]
async fn tidy_and_status() {
    let client = client();
    let fixture = setup_pki(&client).await;
    let pki = client.pki(&fixture.mount);

    pki.tidy(&PkiTidyParams {
        tidy_cert_store: Some(true),
        tidy_revoked_certs: Some(true),
        safety_buffer: Some("72h".into()),
    })
    .await
    .unwrap();

    // Give tidy a moment to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    let status = pki.tidy_status().await.unwrap();
    // State should be one of: Inactive, Running, Finished, Error
    assert!(!status.state.is_empty());

    teardown_pki(&client, &fixture).await;
}

#[tokio::test]
async fn delete_root() {
    let client = client();
    let mount = mount_pki(&client).await;
    let pki = client.pki(&mount);

    pki.generate_root(&PkiRootParams {
        generate_type: "internal".into(),
        common_name: "Delete Root CA".into(),
        ttl: Some("87600h".into()),
        ..Default::default()
    })
    .await
    .unwrap();

    // Verify issuer exists
    let issuers = pki.list_issuers().await.unwrap();
    assert!(!issuers.is_empty());

    // Delete root
    pki.delete_root().await.unwrap();

    // After deleting root, issuers should be empty (or listing should fail)
    // NotFound is also acceptable, so only the Ok case is asserted
    let result = pki.list_issuers().await;
    if let Ok(list) = result {
        assert!(list.is_empty());
    }

    client.sys().unmount(&mount).await.unwrap();
}

#[tokio::test]
async fn intermediate_csr() {
    let client = client();
    let mount = mount_pki(&client).await;

    let csr = client
        .pki(&mount)
        .generate_intermediate_csr(&PkiIntermediateParams {
            generate_type: "internal".into(),
            common_name: "Intermediate CA".into(),
            ..Default::default()
        })
        .await
        .unwrap();

    assert!(!csr.csr.is_empty());
    assert!(csr.csr.contains("BEGIN CERTIFICATE REQUEST"));

    client.sys().unmount(&mount).await.unwrap();
}
