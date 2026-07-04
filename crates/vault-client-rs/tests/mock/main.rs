mod common;

mod auth_test;
mod aws_test;
mod azure_gcp_test;
mod circuit_breaker_test;
mod client_test;
mod convenience_test;
mod cubbyhole_test;
mod database_test;
mod ergonomics_test;
mod identity_test;
mod kv1_test;
mod kv2_test;
mod lifecycle_test;
mod new_auth_test;
mod new_sys_test;
mod pki_test;
mod rabbitmq_mongo_terraform_test;
mod radius_kerberos_test;
mod redaction_test;
mod response_redaction_test;
mod retry_semantics_test;
mod ssh_test;
mod sys_test;
mod totp_consul_nomad_test;
mod tracing_test;
mod transit_test;
mod wrapping_test;

#[cfg(feature = "blocking")]
mod blocking_test;

#[cfg(feature = "blocking")]
mod blocking_review_test;

#[cfg(feature = "auto-renew")]
mod lease_watcher_test;
