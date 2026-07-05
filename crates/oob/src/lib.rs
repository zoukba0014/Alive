//! Out-of-band (OOB) interaction detection.
//!
//! Many high-value POCs (blind SSRF/RCE, DNS exfiltration) confirm a hit only
//! when the target calls back to an attacker-controlled host. This crate mints
//! unique correlation payloads and polls an OOB server for interactions keyed
//! by that correlation id.
//!
//! Scope note: this ships the correlation-id + HTTP-poll model against a
//! configurable OOB server. Full interactsh RSA-encrypted registration/polling
//! parity is **deferred** — the [`OobClient`] trait lets a crypto-backed client
//! drop in later without changing callers.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use alive_core::{Error, Result};
use async_trait::async_trait;
use serde::Deserialize;

/// A minted OOB payload to embed in a probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OobPayload {
    /// Unique id correlating a callback to the probe that caused it.
    pub correlation_id: String,
    /// The host/URL to embed (e.g. `<id>.oob.example.com`).
    pub domain: String,
}

/// A recorded callback to the OOB server.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OobInteraction {
    pub protocol: String,
    #[serde(default)]
    pub remote_addr: String,
    #[serde(default)]
    pub timestamp: String,
    #[serde(default)]
    pub raw: String,
}

#[derive(Debug, Deserialize)]
struct PollResponse {
    #[serde(default)]
    interactions: Vec<OobInteraction>,
}

/// A source of OOB payloads and the interactions they capture.
#[async_trait]
pub trait OobClient: Send + Sync {
    fn generate_payload(&self) -> OobPayload;
    async fn poll(&self) -> Result<Vec<OobInteraction>>;
}

/// HTTP-poll OOB client: registers nothing server-side beyond the correlation
/// id embedded in the payload, and polls `{base_url}/poll?id=<id>`.
pub struct HttpOobClient {
    base_url: String,
    domain_root: String,
    correlation_id: String,
    http: reqwest::Client,
}

impl HttpOobClient {
    pub fn new(base_url: impl Into<String>, domain_root: impl Into<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| Error::Other(format!("oob http client: {e}")))?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            domain_root: domain_root.into(),
            correlation_id: new_correlation_id(),
            http,
        })
    }

    /// The correlation id this client polls for.
    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }
}

#[async_trait]
impl OobClient for HttpOobClient {
    fn generate_payload(&self) -> OobPayload {
        OobPayload {
            correlation_id: self.correlation_id.clone(),
            domain: format!("{}.{}", self.correlation_id, self.domain_root),
        }
    }

    async fn poll(&self) -> Result<Vec<OobInteraction>> {
        let url = format!("{}/poll?id={}", self.base_url, self.correlation_id);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Other(format!("oob poll failed: {e}")))?;
        let body = resp
            .text()
            .await
            .map_err(|e| Error::Other(format!("oob poll body: {e}")))?;
        parse_poll(&body)
    }
}

fn parse_poll(body: &str) -> Result<Vec<OobInteraction>> {
    let parsed: PollResponse =
        serde_json::from_str(body).map_err(|e| Error::Other(format!("oob poll parse: {e}")))?;
    Ok(parsed.interactions)
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A process-unique, lowercase-hex correlation id (time nanos + counter).
/// Not cryptographically random — sufficient for correlating our own probes.
fn new_correlation_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{nanos:016x}{seq:08x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_are_unique() {
        let a = HttpOobClient::new("http://oob.test", "oob.test").unwrap();
        let b = HttpOobClient::new("http://oob.test", "oob.test").unwrap();
        let pa = a.generate_payload();
        let pb = b.generate_payload();
        assert_ne!(pa.correlation_id, pb.correlation_id);
        assert!(pa.domain.ends_with(".oob.test"));
        assert!(pa.domain.starts_with(&pa.correlation_id));
    }

    #[test]
    fn parses_poll_fixture() {
        let fixture = r#"{"interactions":[
            {"protocol":"dns","remote_addr":"203.0.113.7","timestamp":"2026-07-06T00:00:00Z","raw":"A? x.oob.test"},
            {"protocol":"http","remote_addr":"203.0.113.8"}
        ]}"#;
        let got = parse_poll(fixture).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].protocol, "dns");
        assert_eq!(got[0].remote_addr, "203.0.113.7");
        assert_eq!(got[1].protocol, "http");
        assert_eq!(got[1].raw, ""); // defaulted missing field
    }

    #[test]
    fn empty_poll_is_ok() {
        assert!(parse_poll("{}").unwrap().is_empty());
    }
}
