//! AI analysis layer: LLM-backed triage of scanner findings.
//!
//! The deterministic engine emits candidate [`Finding`]s; this crate asks an
//! LLM whether each one is a true positive, using ONLY the request/response
//! evidence attached to the finding (the primary hallucination control).
//!
//! Providers are pluggable behind [`LlmProvider`]. A [`ProviderRouter`] picks
//! between a local model ([`LocalProvider`], e.g. Ollama/vLLM) and a cloud
//! model ([`ClaudeProvider`]) per the workspace's data-governance rule:
//! findings containing internal identifiers stay local, and anything sent to
//! the cloud can be redacted first. See `WORKSPACE_SPEC.md` — the
//! sensitive-data → local-provider rule is a security boundary, not just config.

mod claude;
mod local;
mod prompt;
mod redact;
mod router;

pub use claude::ClaudeProvider;
pub use local::LocalProvider;
pub use redact::{contains_sensitive, redact};
pub use router::{ProviderKind, ProviderRouter, RoutingPolicy};

use alive_core::{Finding, Result, Severity};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Everything an LLM needs to triage a single finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageRequest {
    /// The candidate finding produced by the engine (carries evidence).
    pub finding: Finding,
    /// The request the engine sent (best-effort description).
    pub request: String,
    /// A truncated excerpt of the response backing the match.
    pub response_excerpt: String,
    /// Human-readable template name.
    pub template_name: String,
    /// Template tags (protocol/product classifiers).
    #[serde(default)]
    pub template_tags: Vec<String>,
}

/// The LLM's structured judgement of a finding.
///
/// Serialization must stay stable: it is the schema forced on the model
/// (Claude via a `record_triage` tool, local via `json_object`), stored in
/// reports, and shipped across the fleet.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TriageVerdict {
    /// Whether the finding is judged a real, valid detection.
    pub is_true_positive: bool,
    /// Model confidence in `[0.0, 1.0]`.
    pub confidence: f32,
    /// Severity re-assessed in context (may differ from the engine's).
    pub severity: Severity,
    /// Concise justification.
    pub reasoning: String,
    /// Specific evidence snippets the verdict rests on (hallucination control).
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    /// Short remediation guidance.
    pub remediation: String,
}

/// A backend that can triage a finding. Implemented by the local and cloud
/// providers, and by test fakes.
#[async_trait]
pub trait LlmProvider: Send + Sync {
    /// Judge a single finding.
    async fn triage(&self, req: &TriageRequest) -> Result<TriageVerdict>;
    /// True when this provider runs on-prem (data does not leave the network).
    fn is_local(&self) -> bool;
    /// Short display label, e.g. `claude:claude-opus-4-8` or `local:qwen2.5:14b`.
    fn label(&self) -> &str;
}
