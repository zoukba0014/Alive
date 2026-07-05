use alive_core::Result;
use async_trait::async_trait;

/// Certificate facts extracted from a TLS handshake, used by `ssl` templates.
#[derive(Debug, Clone, Default)]
pub struct TlsCertInfo {
    pub subject: String,
    pub issuer: String,
    pub dns_names: Vec<String>,
    pub not_before: String,
    pub not_after: String,
}

impl TlsCertInfo {
    /// Render the cert fields into a single text blob for word/regex matching.
    pub fn rendered(&self) -> String {
        format!(
            "subject: {}\nissuer: {}\ndns_names: {}\nnot_before: {}\nnot_after: {}",
            self.subject,
            self.issuer,
            self.dns_names.join(", "),
            self.not_before,
            self.not_after,
        )
    }
}

/// Transport for SSL/TLS templates: connect and return certificate facts.
#[async_trait]
pub trait TlsClient: Send + Sync {
    async fn connect(&self, addr: &str) -> Result<TlsCertInfo>;
}
