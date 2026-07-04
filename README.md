# A Rust Client for the HashiCorp Vault HTTP API

> ### 🙏 Original author & upstream
>
> `vault-client-rs` was created and is maintained by **[Michael S. Klishin](https://github.com/michaelklishin)**.
> All credit for the library belongs to the original author and its contributors.
>
> **Upstream repository:** **<https://github.com/michaelklishin/vault-client-rs>**
>
> This repository is a respectful fork that only adds local quality-assurance
> tooling (build/CI gates, test coverage, mutation testing); please prefer and
> support the upstream project. Licensed under Apache-2.0 OR MIT.

Dual async and blocking Rust client for the [HashiCorp Vault](https://www.vaultproject.io/) HTTP API.

Covers KV v1/v2, Transit, PKI, Database, SSH, Identity, TOTP, Cubbyhole,
sys operations (seal/unseal, mounts, policies, leases, audit, Raft, rekey, namespaces, quotas),
and authentication via Token, AppRole, Userpass, LDAP, Kubernetes, TLS certificates,
GitHub, OIDC/JWT, AWS, Azure, GCP, Kerberos, and RADIUS.

Every API handler implements a trait (`Kv2Operations`, `TransitOperations`, `PkiOperations`, ...)
so you can swap in a mock for tests without a running Vault server.

## Project Maturity

This library is young. Before `1.0`, breaking API changes likely, including major changes.


## Requirements

 * Rust 1.93+
 * Tokio

Tested against HashiCorp Vault **1.18** and **2.0.3** (the full integration
suite passes against both). PKI ACME support requires Vault 1.14+.


## Dependency

```toml
vault-client-rs = "0.7"
```

### With Blocking Client

```toml
vault-client-rs = { version = "0.7", features = ["blocking"] }
```

### With Automatic Token Renewal

```toml
vault-client-rs = { version = "0.7", features = ["auto-renew"] }
```


## Async Client

### Create a Client

```rust
use vault_client_rs::VaultClient;

let client = VaultClient::new("https://vault.example.com:8200", "hvs.EXAMPLE")?;
```

### Using ClientBuilder

```rust
use vault_client_rs::VaultClient;

let client = VaultClient::builder()
    .address("https://vault.example.com:8200")
    .token_str("hvs.EXAMPLE")
    .max_retries(3)
    .build()?;
```

### Circuit Breaker

Circuit Breaking is a feature that monitors consecutive failures and short-circuits (avoids)
subsequent requests until a certain period of time passes:

```rust
use vault_client_rs::{VaultClient, CircuitBreakerConfig};

let client = VaultClient::builder()
    .address("https://vault.example.com:8200")
    .token_str("hvs.EXAMPLE")
    .circuit_breaker(CircuitBreakerConfig::default())
    .build()?;
```

### CLI Mode

For short-lived sessions in CLI tools, `cli_mode` disables retries and sealed-Vault retry loops:

```rust
use vault_client_rs::VaultClient;

let client = VaultClient::builder()
    .address("https://vault.example.com:8200")
    .token_str("hvs.EXAMPLE")
    .cli_mode(true)
    .build()?;
```

### From Environment Variables

Reads `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE`, and other `VAULT_*` variables.
When `VAULT_TOKEN` is not set, falls back to `~/.vault-token` (written by `vault login`):

```rust
use vault_client_rs::VaultClient;

let client = VaultClient::from_env()?;
```

### KV v2 Secrets

```rust
let kv = client.kv2("secret");

// Write a secret
kv.write("myapp/config", &serde_json::json!({
    "db_host": "db.internal",
    "db_port": "5432"
})).await?;

// Read into a typed struct or a HashMap
let data: HashMap<String, String> = kv.read_data("myapp/config").await?;

// Read a single field
let host: String = kv.read_field("myapp/config", "db_host").await?;

// List keys
let keys: Vec<String> = kv.list("myapp/").await?;

// Delete
kv.delete("myapp/config").await?;
```

### KV v2 Version Management

```rust
let kv = client.kv2("secret");

// Read a specific version
let v1: KvReadResponse<MyStruct> = kv.read_version("myapp/config", 1).await?;

// Soft-delete versions
kv.delete_versions("myapp/config", &[1, 2]).await?;

// Undelete
kv.undelete_versions("myapp/config", &[1]).await?;

// Permanently destroy versions
kv.destroy_versions("myapp/config", &[2]).await?;

// Check-and-set write (optimistic locking)
kv.write_cas("myapp/config", &new_data, 3).await?;

// Patch (merge fields into existing secret)
kv.patch("myapp/config", &serde_json::json!({"new_field": "value"})).await?;
```

### KV v1 Secrets

```rust
let kv = client.kv1("secret");

// Read into a typed struct or a HashMap
let data: HashMap<String, String> = kv.read_data("myapp/config").await?;

// Read a single field
let host: String = kv.read_field("myapp/config", "db_host").await?;

// Write, list, delete work the same way as in the KV v2 interface
kv.write("myapp/config", &serde_json::json!({"db_host": "db.internal"})).await?;
```

### Transit Encryption

```rust
use secrecy::SecretString;

let transit = client.transit("transit");

// Encrypt, decrypt
let ciphertext = transit.encrypt("my-key", &SecretString::from("sensitive data")).await?;
let plaintext = transit.decrypt("my-key", &ciphertext).await?;

// Sign, verify
let signature = transit.sign("my-key", b"message", &Default::default()).await?;
let valid = transit.verify("my-key", b"message", &signature).await?;

// Key management
transit.create_key("my-key", &TransitKeyParams::default()).await?;
transit.rotate_key("my-key").await?;
let keys = transit.list_keys().await?;
```

### PKI Certificates

```rust
use vault_client_rs::PkiIssueParams;

let pki = client.pki("pki");

// Issue a certificate
let cert = pki.issue("web-server", &PkiIssueParams {
    common_name: "app.example.com".into(),
    ttl: Some("24h".into()),
    ..Default::default()
}).await?;

// Sign a CSR
let signed = pki.sign("web-server", &PkiSignParams {
    common_name: "app.example.com".into(),
    csr: csr_pem.into(),
    ..Default::default()
}).await?;

// Revoke by serial
pki.revoke(&cert.serial_number).await?;
```

### Database Dynamic Credentials

```rust
let db = client.database("database");

// Get dynamic credentials for a role
let creds = db.get_credentials("my-role").await?;
println!("username: {}", creds.username.expose_secret());
```

### SSH Certificate Signing

```rust
use vault_client_rs::SshSignRequest;

let ssh = client.ssh("ssh");

let signed = ssh.sign_key("my-role", &SshSignRequest {
    public_key: public_key_string.into(),
    ..Default::default()
}).await?;
```

### TOTP (Time-Based One-Time Passwords)

```rust
use vault_client_rs::TotpKeyRequest;

let totp = client.totp("totp");

// Create a key (Vault generates the secret)
totp.create_key("my-app", &TotpKeyRequest {
    generate: true,
    issuer: Some("MyApp".into()),
    account_name: Some("alice@example.com".into()),
    ..Default::default()
}).await?;

// Generate a code
let code = totp.generate_code("my-app").await?;

// Validate a code from a user
let result = totp.validate_code("my-app", "123456").await?;
assert!(result.valid);
```

### Lease Management

```rust
let sys = client.sys();

// Look up a lease
let info = sys.read_lease("database/creds/my-role/abc123").await?;

// Renew a lease with an optional increment
sys.renew_lease("database/creds/my-role/abc123", Some("1h")).await?;

// Revoke a specific lease
sys.revoke_lease("database/creds/my-role/abc123").await?;

// Revoke all leases under a prefix
sys.revoke_prefix("database/creds/my-role").await?;
```

### Automatic Token and Lease Renewal

Requires the `auto-renew` feature. The daemon renews the client token at ~2/3 of its
remaining TTL and falls back to re-authentication if renewal fails:

```rust
// Renew the client token in the background
let daemon = client.start_token_renewal();

// Watch a dynamic lease (e.g. database credentials)
use std::time::Duration;
let watcher = client.watch_lease(lease_id, Duration::from_secs(3600));

// Or get programmatic events on each renewal or failure
let mut watcher = client.watch_lease_events(lease_id, Duration::from_secs(3600));
while let Some(event) = watcher.recv().await {
    match event {
        LeaseEvent::Renewed { ttl, .. } => println!("renewed, new TTL: {ttl:?}"),
        LeaseEvent::Expired { lease_id, .. } => {
            eprintln!("lease {lease_id} expired");
            break;
        }
        _ => {}
    }
}

// Both handles cancel their background task on drop
```

### Authentication

```rust
use secrecy::SecretString;
use vault_client_rs::VaultClient;

let client = VaultClient::builder()
    .address("https://vault.example.com:8200")
    .build()?;

// Userpass
let auth = client.auth().userpass().login("alice", &SecretString::from("password")).await?;

// AppRole
let auth = client.auth().approle().login("role-id", &SecretString::from("secret-id")).await?;

// Kubernetes (in-cluster)
let auth = client.auth().kubernetes().login("my-role", &jwt).await?;

// LDAP
let auth = client.auth().ldap().login("alice", &SecretString::from("password")).await?;

// GitHub
let auth = client.auth().github().login(&SecretString::from("ghp_TOKEN")).await?;

// OIDC/JWT
let auth = client.auth().oidc().login_jwt("my-role", &jwt).await?;
```

### Token Management

```rust
let token = client.auth().token();

let info = token.lookup_self().await?;
token.renew_self(Some("1h")).await?;

let child = token.create(&TokenCreateRequest {
    policies: Some(vec!["my-policy".into()]),
    ttl: Some("4h".into()),
    ..Default::default()
}).await?;
```

### System Operations

```rust
let sys = client.sys();

let health = sys.health().await?;
let status = sys.seal_status().await?;
let policies = sys.list_policies().await?;

// Mounts
let mounts = sys.list_mounts().await?;
sys.mount("my-kv", &MountParams {
    mount_type: "kv".into(),
    options: Some([("version".into(), "2".into())].into()),
    ..Default::default()
}).await?;

// Policies
sys.write_policy("my-policy", r#"path "secret/*" { capabilities = ["read"] }"#).await?;

// Response wrapping
let wrapped: MyStruct = sys.unwrap(&wrap_token).await?;
```

### Namespaces (Enterprise)

```rust
// Work in a specific namespace
let ns_client = client.with_namespace("my-team");
let kv = ns_client.kv2("secret");
```

### Response Wrapping

```rust
// Wrap the next response with a TTL
let wrapping_client = client.with_wrap_ttl("5m");
```


## Blocking Client

The blocking client has the same API as the async client but without `async`/`await`.

### Create a Client

```rust
use vault_client_rs::blocking::BlockingVaultClient;

let client = BlockingVaultClient::new("https://vault.example.com:8200", "hvs.EXAMPLE")?;
```

### Read a Secret

```rust
let data: std::collections::HashMap<String, String> =
    client.kv2("secret").read_data("myapp/config")?;
```

### System Operations

```rust
let health = client.sys().health()?;
let policies = client.sys().list_policies()?;
```


## Mocking in Tests

Every handler implements a trait (`Kv2Operations`, `TransitOperations`, `PkiOperations`, ...)
that can be used for mocking in tests:

```rust
use vault_client_rs::{Kv2Operations, VaultError};
use vault_client_rs::types::kv::KvReadResponse;

struct MockKv2;

impl Kv2Operations for MockKv2 {
    async fn read<T: serde::de::DeserializeOwned + Send>(
        &self,
        _path: &str,
    ) -> Result<KvReadResponse<T>, VaultError> {
        todo!("return test data")
    }
    // ...
}
```


## Copyright

(c) 2025-2026 Michael S. Klishin and Contributors.


## License

This crate, `vault-client-rs`, is dual-licensed under
the Apache Software License 2.0 and the MIT license.

SPDX-License-Identifier: Apache-2.0 OR MIT
