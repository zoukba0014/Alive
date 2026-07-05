//! Local provider: any OpenAI-compatible chat endpoint (Ollama, vLLM, …).
//!
//! Data stays on-prem. Structured output is requested via
//! `response_format: {type: "json_object"}` plus a schema embedded in the
//! system prompt; the verdict JSON is parsed from the assistant message. An
//! optional bearer token is read from `ALIVE_LOCAL_LLM_TOKEN`.

use std::time::Duration;

use alive_core::{Error, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde_json::{json, Value};

use crate::{prompt, LlmProvider, TriageRequest, TriageVerdict};

/// Local, OpenAI-compatible triage provider.
pub struct LocalProvider {
    client: Client,
    endpoint: String,
    model: String,
    token: Option<String>,
    label: String,
}

impl LocalProvider {
    /// Build a provider posting to `{base_url}/chat/completions`.
    pub fn new(base_url: impl Into<String>, model: impl Into<String>) -> Result<Self> {
        let base = base_url.into();
        let endpoint = format!("{}/chat/completions", base.trim_end_matches('/'));
        let model = model.into();
        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| Error::Other(format!("local http client build failed: {e}")))?;
        let label = format!("local:{model}");
        Ok(Self {
            client,
            endpoint,
            model,
            token: std::env::var("ALIVE_LOCAL_LLM_TOKEN").ok(),
            label,
        })
    }
}

/// Strip a leading/trailing markdown code fence some models add despite the
/// json_object request.
fn strip_fences(s: &str) -> &str {
    let t = s.trim();
    let t = t
        .strip_prefix("```json")
        .or_else(|| t.strip_prefix("```"))
        .unwrap_or(t);
    t.strip_suffix("```").unwrap_or(t).trim()
}

#[async_trait]
impl LlmProvider for LocalProvider {
    async fn triage(&self, req: &TriageRequest) -> Result<TriageVerdict> {
        let body = json!({
            "model": self.model,
            "messages": [
                { "role": "system", "content": prompt::local_system_prompt() },
                { "role": "user", "content": prompt::user_content(req) }
            ],
            "response_format": { "type": "json_object" },
            "stream": false
        });

        let mut builder = self.client.post(&self.endpoint).json(&body);
        if let Some(token) = &self.token {
            builder = builder.bearer_auth(token);
        }

        let resp = builder
            .send()
            .await
            .map_err(|e| Error::Other(format!("local request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::Other(format!("local api error {status}: {text}")));
        }

        let payload: Value = resp
            .json()
            .await
            .map_err(|e| Error::Other(format!("local response decode failed: {e}")))?;

        let content = payload
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|c| c.first())
            .and_then(|c| c.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Other("local: no message content in response".into()))?;

        serde_json::from_str(strip_fences(content))
            .map_err(|e| Error::Other(format!("local verdict parse failed: {e}")))
    }

    fn is_local(&self) -> bool {
        true
    }

    fn label(&self) -> &str {
        &self.label
    }
}

#[cfg(test)]
mod tests {
    use super::strip_fences;

    #[test]
    fn strips_json_fences() {
        assert_eq!(strip_fences("```json\n{\"a\":1}\n```"), "{\"a\":1}");
        assert_eq!(strip_fences("{\"a\":1}"), "{\"a\":1}");
    }
}
