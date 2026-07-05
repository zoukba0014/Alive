//! Template execution engine.
//!
//! The engine is transport-agnostic: it depends on the [`HttpClient`] trait
//! rather than a concrete HTTP library, so the `protocols` crate provides the
//! real implementation and tests provide fakes. Given a [`Template`] and a
//! [`Target`], it sends requests, evaluates matchers, runs extractors, and
//! emits a [`Finding`] on a match.

mod http;
mod matcher;

pub use http::{HttpClient, HttpResponse};

use alive_core::{Finding, Result, Target};
use alive_template::Template;

/// Run a template's http block against a target, returning a finding on the
/// first matching request (nuclei's default `stop-at-first-match` semantics).
pub async fn run_http_template<C: HttpClient>(
    template: &Template,
    target: &Target,
    base_url: &str,
    client: &C,
) -> Result<Option<Finding>> {
    for req in &template.http {
        // Requests we cannot execute yet (e.g. raw) are skipped here; the
        // `template-check` command is the place that reports this to users.
        if !req.raw.is_empty() {
            continue;
        }
        let paths: Vec<String> = if req.path.is_empty() {
            vec![base_url.to_string()]
        } else {
            req.path
                .iter()
                .map(|p| p.replace("{{BaseURL}}", base_url))
                .collect()
        };

        for url in paths {
            let resp = client
                .send(&req.method, &url, &req.headers, req.body.as_deref())
                .await?;

            if let Some((evidence, extracted)) = matcher::evaluate(req, &resp) {
                let mut finding = Finding::new(
                    template.id.clone(),
                    template.info.name.clone(),
                    template.info.severity,
                    target.clone(),
                );
                finding.evidence = evidence;
                finding.extracted = extracted;
                return Ok(Some(finding));
            }
        }
    }
    Ok(None)
}
