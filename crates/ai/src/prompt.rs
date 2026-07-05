//! Shared prompt + JSON schema for both providers, so Claude and a local model
//! are asked the exact same question and held to the same output shape.

use serde_json::{json, Value};

use crate::TriageRequest;

/// System prompt used verbatim by the Claude provider (which enforces the
/// schema via a forced tool call).
pub fn system_prompt() -> &'static str {
    "You are a security triage assistant for an authorized internal vulnerability scanner. \
Given a candidate finding and the exact request/response evidence, decide whether it is a \
TRUE POSITIVE (a real, valid detection) or a FALSE POSITIVE. \
Judge ONLY from the evidence provided — never assume facts, versions, or behavior not present in it. \
Cite the specific response snippets that justify your verdict in `evidence_refs`. \
If the evidence is insufficient to confirm the finding, set `is_true_positive` to false and lower `confidence`. \
Re-assess severity in context, and give a concise `reasoning` and a short, actionable `remediation`."
}

/// System prompt for OpenAI-compatible local models: the base instructions plus
/// the schema and a JSON-only directive (no forced-tool mechanism there).
pub fn local_system_prompt() -> String {
    format!(
        "{}\n\nRespond with ONLY a single JSON object (no prose, no markdown code fences) \
matching this JSON schema:\n{}",
        system_prompt(),
        serde_json::to_string_pretty(&verdict_schema()).unwrap_or_default()
    )
}

/// JSON schema for [`crate::TriageVerdict`], used as the Claude tool
/// `input_schema` and embedded in the local system prompt.
pub fn verdict_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "is_true_positive": { "type": "boolean", "description": "Whether the finding is a real, valid detection." },
            "confidence": { "type": "number", "description": "Confidence from 0.0 to 1.0." },
            "severity": { "type": "string", "enum": ["info", "low", "medium", "high", "critical"] },
            "reasoning": { "type": "string", "description": "Concise justification grounded in the evidence." },
            "evidence_refs": { "type": "array", "items": { "type": "string" }, "description": "Specific response snippets supporting the verdict." },
            "remediation": { "type": "string", "description": "Short remediation guidance." }
        },
        "required": ["is_true_positive", "confidence", "severity", "reasoning", "remediation"]
    })
}

/// Render the finding + evidence into the user turn shared by both providers.
pub fn user_content(req: &TriageRequest) -> String {
    let evidence = req
        .finding
        .evidence
        .iter()
        .map(|e| format!("- [{}] {}", e.part, e.snippet))
        .collect::<Vec<_>>()
        .join("\n");
    let response_block = if evidence.is_empty() {
        req.response_excerpt.clone()
    } else if req.response_excerpt.is_empty() {
        evidence
    } else {
        format!("{evidence}\n{}", req.response_excerpt)
    };
    format!(
        "Finding: {name}\n\
Template: {tmpl} (id: {id})\n\
Tags: {tags}\n\
Engine severity: {sev}\n\
Target: {target}\n\
Extracted values: {extracted}\n\n\
Request sent:\n{request}\n\n\
Response evidence:\n{response_block}\n",
        name = req.finding.name,
        tmpl = req.template_name,
        id = req.finding.template_id,
        tags = req.template_tags.join(", "),
        sev = req.finding.severity,
        target = req.finding.target,
        extracted = req.finding.extracted.join(", "),
        request = req.request,
    )
}
