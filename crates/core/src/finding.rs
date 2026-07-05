use serde::{Deserialize, Serialize};

use crate::{Severity, Target};

/// A single result produced by the engine: "template X matched target Y".
///
/// Findings are the currency of the whole system — the engine emits them,
/// the AI layer triages them, reports render them, and agents ship them to
/// the server. Keep this serialization-stable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Template id that matched (e.g. `redis-unauthorized`).
    pub template_id: String,
    /// Human-readable template name.
    pub name: String,
    pub severity: Severity,
    pub target: Target,
    /// Supporting evidence for the match, used for reporting and AI triage.
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    /// Values pulled out by extractors (e.g. version strings), keyed by name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extracted: Vec<String>,
}

impl Finding {
    pub fn new(
        template_id: impl Into<String>,
        name: impl Into<String>,
        severity: Severity,
        target: Target,
    ) -> Self {
        Self {
            template_id: template_id.into(),
            name: name.into(),
            severity,
            target,
            evidence: Vec::new(),
            extracted: Vec::new(),
        }
    }
}

/// A snippet of request/response context justifying a finding.
///
/// The AI triage layer is instructed to cite these, which is the primary
/// hallucination control: no evidence => no confirmed finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Where the snippet came from, e.g. `response.header`, `response.body`.
    pub part: String,
    /// The matched/relevant content (callers are responsible for truncation).
    pub snippet: String,
}
