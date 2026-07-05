//! Provider selection + the data-governance boundary.
//!
//! The router decides whether a finding is triaged locally or in the cloud.
//! The rule (from `WORKSPACE_SPEC.md`) is a security boundary: a finding that
//! contains internal identifiers must stay local when the policy says so, and
//! anything sent to the cloud may be redacted first.

use std::sync::Arc;

use alive_core::Result;

use crate::{redact, LlmProvider, TriageRequest, TriageVerdict};

/// Which tier a provider runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    Local,
    Cloud,
}

/// How the router chooses and how it treats cloud egress.
#[derive(Debug, Clone, Copy)]
pub struct RoutingPolicy {
    /// Provider used when nothing forces a choice.
    pub default_provider: ProviderKind,
    /// Where sensitive findings must go (typically `Local`).
    pub sensitive_data: ProviderKind,
    /// Mask internal IPs/hostnames before sending to the cloud.
    pub redact_before_cloud: bool,
}

impl Default for RoutingPolicy {
    fn default() -> Self {
        Self {
            default_provider: ProviderKind::Local,
            sensitive_data: ProviderKind::Local,
            redact_before_cloud: true,
        }
    }
}

/// Routes each triage request to the local or cloud provider.
pub struct ProviderRouter {
    local: Arc<dyn LlmProvider>,
    cloud: Option<Arc<dyn LlmProvider>>,
    policy: RoutingPolicy,
}

impl ProviderRouter {
    pub fn new(
        local: Arc<dyn LlmProvider>,
        cloud: Option<Arc<dyn LlmProvider>>,
        policy: RoutingPolicy,
    ) -> Self {
        Self {
            local,
            cloud,
            policy,
        }
    }

    /// Decide which tier a request goes to (pure; the security boundary lives here).
    pub fn route(&self, req: &TriageRequest) -> ProviderKind {
        // No cloud provider configured/available → everything is local.
        if self.cloud.is_none() {
            return ProviderKind::Local;
        }
        // Sensitive findings are pinned local when policy demands it.
        if self.policy.sensitive_data == ProviderKind::Local && is_sensitive(req) {
            return ProviderKind::Local;
        }
        self.policy.default_provider
    }

    /// Triage a finding, returning the verdict and the provider label used.
    pub async fn triage(&self, req: &TriageRequest) -> Result<(TriageVerdict, String)> {
        match self.route(req) {
            ProviderKind::Local => {
                let verdict = self.local.triage(req).await?;
                Ok((verdict, self.local.label().to_string()))
            }
            ProviderKind::Cloud => {
                // route() only returns Cloud when a cloud provider exists.
                let cloud = self
                    .cloud
                    .as_ref()
                    .expect("route() returns Cloud only when a cloud provider is present");
                if self.policy.redact_before_cloud {
                    let redacted = redact_request(req);
                    let verdict = cloud.triage(&redacted).await?;
                    Ok((verdict, cloud.label().to_string()))
                } else {
                    let verdict = cloud.triage(req).await?;
                    Ok((verdict, cloud.label().to_string()))
                }
            }
        }
    }
}

/// A finding is sensitive when its target, request, or response references an
/// internal IP or hostname.
fn is_sensitive(req: &TriageRequest) -> bool {
    redact::contains_sensitive(&req.finding.target.host)
        || redact::contains_sensitive(&req.request)
        || redact::contains_sensitive(&req.response_excerpt)
        || req
            .finding
            .evidence
            .iter()
            .any(|e| redact::contains_sensitive(&e.snippet))
}

/// Copy a request with internal identifiers masked out of every text field.
fn redact_request(req: &TriageRequest) -> TriageRequest {
    let mut r = req.clone();
    r.request = redact::redact(&r.request);
    r.response_excerpt = redact::redact(&r.response_excerpt);
    r.finding.target.host = redact::redact(&r.finding.target.host);
    for e in &mut r.finding.evidence {
        e.snippet = redact::redact(&e.snippet);
    }
    r
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use alive_core::{Finding, Severity, Target};
    use async_trait::async_trait;

    use super::*;

    /// Records the request it received and echoes a fixed verdict.
    struct FakeProvider {
        local: bool,
        label: String,
        seen: Mutex<Option<TriageRequest>>,
    }

    impl FakeProvider {
        fn new(local: bool, label: &str) -> Arc<Self> {
            Arc::new(Self {
                local,
                label: label.to_string(),
                seen: Mutex::new(None),
            })
        }
    }

    #[async_trait]
    impl LlmProvider for FakeProvider {
        async fn triage(&self, req: &TriageRequest) -> Result<TriageVerdict> {
            *self.seen.lock().unwrap() = Some(req.clone());
            Ok(TriageVerdict {
                is_true_positive: true,
                confidence: 0.9,
                severity: Severity::High,
                reasoning: "fake".into(),
                evidence_refs: vec![],
                remediation: "fake".into(),
            })
        }
        fn is_local(&self) -> bool {
            self.local
        }
        fn label(&self) -> &str {
            &self.label
        }
    }

    fn req_with_target(host: &str, response: &str) -> TriageRequest {
        TriageRequest {
            finding: Finding::new("t", "T", Severity::Medium, Target::new(host, Some(80))),
            request: String::new(),
            response_excerpt: response.into(),
            template_name: "T".into(),
            template_tags: vec![],
        }
    }

    fn policy(default: ProviderKind) -> RoutingPolicy {
        RoutingPolicy {
            default_provider: default,
            sensitive_data: ProviderKind::Local,
            redact_before_cloud: true,
        }
    }

    #[test]
    fn sensitive_finding_pins_to_local() {
        let router = ProviderRouter::new(
            FakeProvider::new(true, "local"),
            Some(FakeProvider::new(false, "cloud")),
            policy(ProviderKind::Cloud),
        );
        // internal IP in the target ⇒ local even though default is cloud
        assert_eq!(
            router.route(&req_with_target("10.0.0.9", "")),
            ProviderKind::Local
        );
    }

    #[test]
    fn non_sensitive_uses_default_cloud() {
        let router = ProviderRouter::new(
            FakeProvider::new(true, "local"),
            Some(FakeProvider::new(false, "cloud")),
            policy(ProviderKind::Cloud),
        );
        assert_eq!(
            router.route(&req_with_target("example.com", "hello")),
            ProviderKind::Cloud
        );
    }

    #[test]
    fn missing_cloud_falls_back_to_local() {
        let router = ProviderRouter::new(
            FakeProvider::new(true, "local"),
            None,
            policy(ProviderKind::Cloud),
        );
        assert_eq!(
            router.route(&req_with_target("example.com", "hello")),
            ProviderKind::Local
        );
    }

    #[tokio::test]
    async fn cloud_path_redacts_before_send() {
        let cloud = FakeProvider::new(false, "cloud");
        // sensitive_data == Cloud means internal content is NOT pinned local, so
        // it reaches the cloud provider — and must be redacted on the way out.
        let router = ProviderRouter::new(
            FakeProvider::new(true, "local"),
            Some(cloud.clone()),
            RoutingPolicy {
                default_provider: ProviderKind::Cloud,
                sensitive_data: ProviderKind::Cloud,
                redact_before_cloud: true,
            },
        );
        let req = req_with_target("example.com", "leaked 192.168.1.50 here");
        let (verdict, label) = router.triage(&req).await.unwrap();
        assert_eq!(label, "cloud");
        assert!(verdict.is_true_positive);
        let seen = cloud.seen.lock().unwrap().clone().unwrap();
        assert!(!seen.response_excerpt.contains("192.168.1.50"));
        assert!(seen.response_excerpt.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn local_path_does_not_redact() {
        let local = FakeProvider::new(true, "local");
        let router = ProviderRouter::new(
            local.clone(),
            Some(FakeProvider::new(false, "cloud")),
            policy(ProviderKind::Local),
        );
        let req = req_with_target("host", "keeps 192.168.1.50 raw");
        let (_v, label) = router.triage(&req).await.unwrap();
        assert_eq!(label, "local");
        let seen = local.seen.lock().unwrap().clone().unwrap();
        assert!(seen.response_excerpt.contains("192.168.1.50"));
    }
}
