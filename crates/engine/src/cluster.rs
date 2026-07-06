//! Template clustering (M8): when several HTTP templates issue a byte-identical
//! request (same method + paths + headers + body), the engine sends that request
//! **once** and evaluates every clustered template's matchers against the single
//! response. This mirrors nuclei's request clustering and cuts network traffic on
//! large template sets. Per-template findings are preserved — one shared response
//! can satisfy multiple templates.

use std::collections::BTreeMap;

use alive_core::{Finding, Result, Target};
use alive_template::Template;

use crate::http::HttpClient;
use crate::{build_finding, matcher};

/// A group of templates to execute together.
///
/// `shares_request == true` means every template in `template_indices` issues
/// the same single HTTP request, so the caller runs the group via
/// [`run_http_cluster`] (one wire request). `shares_request == false` marks a
/// template the engine must run on its own (multi-request, `raw`, or non-HTTP) —
/// the caller falls back to `run_http_template` / the tcp/tls paths for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cluster {
    pub template_indices: Vec<usize>,
    pub shares_request: bool,
}

/// Only single-request, non-`raw` HTTP templates can share a wire request.
fn cluster_key(t: &Template) -> Option<String> {
    if t.http.len() != 1 {
        return None;
    }
    let req = &t.http[0];
    if !req.raw.is_empty() {
        return None;
    }
    // Canonical key over the wire-affecting fields. Headers are a BTreeMap so
    // their ordering is already deterministic.
    let headers: BTreeMap<&String, &String> = req.headers.iter().collect();
    Some(format!(
        "{}\u{1}{}\u{1}{:?}\u{1}{}",
        req.method,
        req.path.join("\u{2}"),
        headers,
        req.body.as_deref().unwrap_or(""),
    ))
}

/// Group templates so identical HTTP requests are issued once. Clusterable
/// templates are grouped by their request key (input order preserved);
/// everything else becomes a standalone (`shares_request: false`) singleton.
pub fn cluster_templates(templates: &[Template]) -> Vec<Cluster> {
    let mut clusters: Vec<Cluster> = Vec::new();
    // key -> index into `clusters`
    let mut by_key: BTreeMap<String, usize> = BTreeMap::new();

    for (i, t) in templates.iter().enumerate() {
        match cluster_key(t) {
            Some(key) => {
                if let Some(&ci) = by_key.get(&key) {
                    clusters[ci].template_indices.push(i);
                } else {
                    by_key.insert(key, clusters.len());
                    clusters.push(Cluster {
                        template_indices: vec![i],
                        shares_request: true,
                    });
                }
            }
            None => clusters.push(Cluster {
                template_indices: vec![i],
                shares_request: false,
            }),
        }
    }
    clusters
}

/// Execute a set of clustered templates that share one HTTP request: send the
/// request once per path and evaluate each template's matchers against the
/// response. Returns one finding per matching template (first matching path
/// wins per template, preserving `stop-at-first-match`).
///
/// Callers must only pass templates that share a request (see [`cluster_templates`]).
pub async fn run_http_cluster<C: HttpClient>(
    templates: &[&Template],
    target: &Target,
    base_url: &str,
    client: &C,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let Some(lead) = templates.first() else {
        return Ok(findings);
    };
    let req = &lead.http[0];

    let paths: Vec<String> = if req.path.is_empty() {
        vec![base_url.to_string()]
    } else {
        req.path
            .iter()
            .map(|p| p.replace("{{BaseURL}}", base_url))
            .collect()
    };

    let mut done = vec![false; templates.len()];
    for url in paths {
        if done.iter().all(|&d| d) {
            break;
        }
        let resp = client
            .send(&req.method, &url, &req.headers, req.body.as_deref())
            .await?;
        for (idx, t) in templates.iter().enumerate() {
            if done[idx] {
                continue;
            }
            if let Some((evidence, extracted)) = matcher::evaluate_http(&t.http[0], &resp) {
                let mut finding = build_finding(t, target);
                finding.evidence = evidence;
                finding.extracted = extracted;
                findings.push(finding);
                done[idx] = true;
            }
        }
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{HttpClient, HttpResponse};
    use alive_core::Severity;
    use alive_template::{Condition, HttpRequest, Info, Matcher, Part};
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Counts wire requests so tests can prove clustering sends once.
    struct CountingClient {
        sends: AtomicUsize,
        body: String,
    }

    #[async_trait]
    impl HttpClient for CountingClient {
        async fn send(
            &self,
            _method: &str,
            _url: &str,
            _headers: &BTreeMap<String, String>,
            _body: Option<&str>,
        ) -> Result<HttpResponse> {
            self.sends.fetch_add(1, Ordering::SeqCst);
            Ok(HttpResponse {
                status: 200,
                headers: vec![],
                body: self.body.clone(),
            })
        }
    }

    fn tmpl(id: &str, word: &str) -> Template {
        Template {
            id: id.to_string(),
            info: Info {
                name: id.to_string(),
                author: None,
                severity: Severity::Info,
                tags: vec![],
                description: None,
            },
            http: vec![HttpRequest {
                method: "GET".into(),
                path: vec!["{{BaseURL}}/".into()],
                raw: vec![],
                headers: BTreeMap::new(),
                body: None,
                matchers_condition: Condition::And,
                matchers: vec![Matcher::Word {
                    words: vec![word.to_string()],
                    part: Part::Body,
                    condition: Condition::And,
                    negative: false,
                }],
                extractors: vec![],
            }],
            tcp: vec![],
            dns: vec![],
            ssl: vec![],
            extra: Default::default(),
        }
    }

    #[test]
    fn identical_requests_form_one_cluster() {
        let ts = vec![tmpl("a", "alpha"), tmpl("b", "beta"), tmpl("c", "gamma")];
        let clusters = cluster_templates(&ts);
        assert_eq!(clusters.len(), 1);
        assert!(clusters[0].shares_request);
        assert_eq!(clusters[0].template_indices, vec![0, 1, 2]);
    }

    #[tokio::test]
    async fn cluster_sends_once_but_matches_per_template() {
        let ts = [tmpl("a", "alpha"), tmpl("b", "beta"), tmpl("c", "zzz")];
        let refs: Vec<&Template> = ts.iter().collect();
        let client = CountingClient {
            sends: AtomicUsize::new(0),
            body: "alpha beta only".into(),
        };
        let target = Target::new("10.0.0.1", Some(80));
        let findings = run_http_cluster(&refs, &target, "http://10.0.0.1", &client)
            .await
            .unwrap();
        // One wire request for three templates...
        assert_eq!(client.sends.load(Ordering::SeqCst), 1);
        // ...but per-template matches: "alpha" and "beta" hit, "zzz" doesn't.
        let ids: Vec<&str> = findings.iter().map(|f| f.template_id.as_str()).collect();
        assert_eq!(ids, vec!["a", "b"]);
    }

    #[test]
    fn different_requests_are_not_clustered() {
        let mut t2 = tmpl("b", "beta");
        t2.http[0].path = vec!["{{BaseURL}}/other".into()];
        let ts = vec![tmpl("a", "alpha"), t2];
        let clusters = cluster_templates(&ts);
        assert_eq!(clusters.len(), 2);
    }
}
