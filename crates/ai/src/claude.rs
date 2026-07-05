//! Cloud provider: Anthropic Claude via the Messages API.
//!
//! Structured output is guaranteed by forcing a single `record_triage` tool
//! whose `input_schema` is the [`crate::TriageVerdict`] schema — the verdict is
//! read from the returned `tool_use` block's `input`. No sampling parameters
//! are sent (they 400 on current Opus models).

use std::time::Duration;

use alive_core::{Error, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde_json::{json, Value};

use crate::{prompt, LlmProvider, TriageRequest, TriageVerdict};

const API_URL: &str = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Claude-backed triage provider. The API key is read once from
/// `ANTHROPIC_API_KEY` at construction.
pub struct ClaudeProvider {
    client: Client,
    api_key: String,
    model: String,
    label: String,
}

impl ClaudeProvider {
    /// Build a provider for `model` (e.g. `claude-opus-4-8`, `claude-sonnet-4-6`,
    /// `claude-haiku-4-5`). Fails if `ANTHROPIC_API_KEY` is unset.
    pub fn new(model: impl Into<String>) -> Result<Self> {
        let api_key = std::env::var("ANTHROPIC_API_KEY")
            .map_err(|_| Error::Other("ANTHROPIC_API_KEY is not set".into()))?;
        let model = model.into();
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| Error::Other(format!("claude http client build failed: {e}")))?;
        let label = format!("claude:{model}");
        Ok(Self {
            client,
            api_key,
            model,
            label,
        })
    }

    /// Whether a cloud provider can be constructed (i.e. the key is present).
    pub fn available() -> bool {
        std::env::var("ANTHROPIC_API_KEY").is_ok()
    }
}

#[async_trait]
impl LlmProvider for ClaudeProvider {
    async fn triage(&self, req: &TriageRequest) -> Result<TriageVerdict> {
        let body = json!({
            "model": self.model,
            "max_tokens": 1024,
            "system": prompt::system_prompt(),
            "messages": [{ "role": "user", "content": prompt::user_content(req) }],
            "tools": [{
                "name": "record_triage",
                "description": "Record the triage verdict for the candidate finding.",
                "input_schema": prompt::verdict_schema(),
            }],
            "tool_choice": { "type": "tool", "name": "record_triage" }
        });

        let resp = self
            .client
            .post(API_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Other(format!("claude request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::Other(format!("claude api error {status}: {text}")));
        }

        let payload: Value = resp
            .json()
            .await
            .map_err(|e| Error::Other(format!("claude response decode failed: {e}")))?;

        let input = payload
            .get("content")
            .and_then(Value::as_array)
            .and_then(|blocks| {
                blocks.iter().find(|b| {
                    b.get("type").and_then(Value::as_str) == Some("tool_use")
                        && b.get("name").and_then(Value::as_str) == Some("record_triage")
                })
            })
            .and_then(|b| b.get("input"))
            .ok_or_else(|| Error::Other("claude: no record_triage tool_use in response".into()))?;

        serde_json::from_value(input.clone())
            .map_err(|e| Error::Other(format!("claude verdict parse failed: {e}")))
    }

    fn is_local(&self) -> bool {
        false
    }

    fn label(&self) -> &str {
        &self.label
    }
}
