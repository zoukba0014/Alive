//! Template execution engine.
//!
//! The engine is transport-agnostic: it depends on the [`HttpClient`],
//! [`TcpClient`], and [`TlsClient`] traits rather than concrete network
//! libraries, so the `protocols` crate provides the real implementations and
//! tests provide fakes. Given a [`Template`] and a [`Target`], it sends
//! requests, evaluates matchers (including `dsl:`), runs extractors, and emits
//! a [`Finding`] on a match.

mod http;
mod matcher;
mod tcp;
mod tls;

pub use http::{HttpClient, HttpResponse};
pub use tcp::{TcpClient, TcpResponse};
pub use tls::{TlsCertInfo, TlsClient};

use alive_core::{Finding, Result, Target};
use alive_template::Template;

use matcher::MatchInput;

fn build_finding(template: &Template, target: &Target) -> Finding {
    Finding::new(
        template.id.clone(),
        template.info.name.clone(),
        template.info.severity,
        target.clone(),
    )
}

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
        // `template-check` command reports this to users.
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

            if let Some((evidence, extracted)) = matcher::evaluate_http(req, &resp) {
                let mut finding = build_finding(template, target);
                finding.evidence = evidence;
                finding.extracted = extracted;
                return Ok(Some(finding));
            }
        }
    }
    Ok(None)
}

/// Run a template's tcp block against `addr` (`host:port`).
pub async fn run_tcp_template<C: TcpClient>(
    template: &Template,
    target: &Target,
    addr: &str,
    client: &C,
) -> Result<Option<Finding>> {
    for req in &template.tcp {
        let inputs: Vec<String> = req.inputs.iter().filter_map(|i| i.data.clone()).collect();
        let read_size = req.read_size.unwrap_or(2048);
        let resp = match client.send(addr, &inputs, read_size).await {
            Ok(r) => r,
            Err(_) => continue,
        };
        let input = MatchInput::from_data(&resp.data);
        if let Some((evidence, extracted)) = matcher::evaluate(
            &req.matchers,
            req.matchers_condition,
            &req.extractors,
            &input,
        ) {
            let mut finding = build_finding(template, target);
            finding.evidence = evidence;
            finding.extracted = extracted;
            return Ok(Some(finding));
        }
    }
    Ok(None)
}

/// Run a template's ssl block against `addr` (`host:port`): matchers evaluate
/// over the rendered certificate fields.
pub async fn run_tls_template<C: TlsClient>(
    template: &Template,
    target: &Target,
    addr: &str,
    client: &C,
) -> Result<Option<Finding>> {
    for req in &template.ssl {
        let cert = match client.connect(addr).await {
            Ok(c) => c,
            Err(_) => continue,
        };
        let input = MatchInput::from_data(&cert.rendered());
        if let Some((evidence, extracted)) = matcher::evaluate(
            &req.matchers,
            req.matchers_condition,
            &req.extractors,
            &input,
        ) {
            let mut finding = build_finding(template, target);
            finding.evidence = evidence;
            finding.extracted = extracted;
            return Ok(Some(finding));
        }
    }
    Ok(None)
}
