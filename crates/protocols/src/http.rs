use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use alive_core::{Error, Result};
use alive_engine::{HttpClient, HttpResponse};
use async_trait::async_trait;
use reqwest::redirect::Policy;
use reqwest::{Client, Method};

use crate::rate::{build_limiter, DirectLimiter};

/// reqwest-backed HTTP runner.
///
/// Accepts invalid/self-signed certificates by default: scanning internal
/// hosts with private-CA or self-signed certs is the norm, and nuclei behaves
/// the same. This is a scanner, not a browser.
pub struct HttpRunner {
    client: Client,
    /// Optional global rate limiter awaited before each request.
    limiter: Option<Arc<DirectLimiter>>,
}

impl HttpRunner {
    pub fn new(timeout: Duration, follow_redirects: bool) -> Result<Self> {
        Self::with_rate(timeout, follow_redirects, 0)
    }

    /// Build a runner capped at `rate_per_sec` outbound requests/second
    /// (0 = unlimited).
    pub fn with_rate(timeout: Duration, follow_redirects: bool, rate_per_sec: u32) -> Result<Self> {
        let redirect = if follow_redirects {
            Policy::limited(5)
        } else {
            Policy::none()
        };
        let client = Client::builder()
            .timeout(timeout)
            .redirect(redirect)
            .danger_accept_invalid_certs(true)
            .user_agent("alive-scanner/0.1")
            .build()
            .map_err(|e| Error::Other(format!("http client build failed: {e}")))?;
        Ok(Self {
            client,
            limiter: build_limiter(rate_per_sec),
        })
    }
}

#[async_trait]
impl HttpClient for HttpRunner {
    async fn send(
        &self,
        method: &str,
        url: &str,
        headers: &BTreeMap<String, String>,
        body: Option<&str>,
    ) -> Result<HttpResponse> {
        // Await a rate-limit token before firing (no-op when unlimited).
        if let Some(limiter) = &self.limiter {
            limiter.until_ready().await;
        }
        let method = Method::from_bytes(method.as_bytes())
            .map_err(|_| Error::Other(format!("invalid http method: {method}")))?;
        let mut builder = self.client.request(method, url);
        for (k, v) in headers {
            builder = builder.header(k, v);
        }
        if let Some(b) = body {
            builder = builder.body(b.to_string());
        }

        let resp = builder
            .send()
            .await
            .map_err(|e| Error::Other(format!("request to {url} failed: {e}")))?;

        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
            .collect();
        let body = resp.text().await.unwrap_or_default();

        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}
