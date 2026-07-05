use std::collections::BTreeMap;

use alive_core::Result;
use async_trait::async_trait;

/// A normalized HTTP response the engine can match against.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl HttpResponse {
    /// Header block rendered as `Name: value` lines (for `part: header`).
    pub fn header_text(&self) -> String {
        let mut s = String::new();
        for (k, v) in &self.headers {
            s.push_str(k);
            s.push_str(": ");
            s.push_str(v);
            s.push('\n');
        }
        s
    }

    /// Status line + headers + body (for `part: all`).
    pub fn all_text(&self) -> String {
        format!(
            "HTTP {}\n{}\n{}",
            self.status,
            self.header_text(),
            self.body
        )
    }
}

/// Transport abstraction the engine executes against.
///
/// Implemented for real by `alive-protocols` (reqwest) and by fakes in tests.
#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn send(
        &self,
        method: &str,
        url: &str,
        headers: &BTreeMap<String, String>,
        body: Option<&str>,
    ) -> Result<HttpResponse>;
}
