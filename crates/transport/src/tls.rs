use thiserror::Error;
use tonic::transport::{Certificate, ClientTlsConfig, Identity, ServerTlsConfig};

#[derive(Debug, Error)]
pub enum TlsError {
    // Placeholder for future validation; PEM parsing errors surface from tonic
    // when the config is applied to a server/channel.
    #[error("tls config error: {0}")]
    Config(String),
}

/// Build a server-side mTLS config: present `cert_pem`/`key_pem` and require
/// client certs signed by `ca_pem`.
pub fn server_tls(cert_pem: &[u8], key_pem: &[u8], ca_pem: &[u8]) -> ServerTlsConfig {
    ServerTlsConfig::new()
        .identity(Identity::from_pem(cert_pem, key_pem))
        .client_ca_root(Certificate::from_pem(ca_pem))
}

/// Build a client-side mTLS config: present the agent identity, trust the CA,
/// and verify the server cert against `domain`.
pub fn client_tls(cert_pem: &[u8], key_pem: &[u8], ca_pem: &[u8], domain: &str) -> ClientTlsConfig {
    ClientTlsConfig::new()
        .identity(Identity::from_pem(cert_pem, key_pem))
        .ca_certificate(Certificate::from_pem(ca_pem))
        .domain_name(domain)
}
