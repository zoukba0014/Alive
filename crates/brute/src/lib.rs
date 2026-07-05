//! Safety-bounded credential checks.
//!
//! This module deliberately does NOT ship a large built-in password list and
//! does NOT discover its own targets — see `WORKSPACE_SPEC.md`. Callers supply
//! the authorized target scope and an explicit credential list (a file, or the
//! small clearly-labeled [`wellknown_defaults`] set which is opt-in). Every run
//! is bounded by [`BruteConfig`] (max attempts, concurrency cap, per-attempt
//! delay) so it behaves like an authorized audit, not a spray.

mod cred;
mod service;

pub use cred::{load_creds_file, wellknown_defaults, Credential};
pub use service::{BruteService, FtpService, RedisService};

use std::sync::Arc;
use std::time::Duration;

use alive_core::{Finding, Severity, Target};
use tokio::sync::Semaphore;

/// Bounds on a brute run. Defaults are conservative to avoid account lockouts.
#[derive(Debug, Clone)]
pub struct BruteConfig {
    /// Max credentials tried per (target, service). 0 means "all supplied".
    pub max_attempts: usize,
    /// Max targets probed concurrently.
    pub concurrency: usize,
    /// Delay between attempts against the same target (rate limit).
    pub delay: Duration,
    /// Per-connection timeout.
    pub timeout: Duration,
}

impl Default for BruteConfig {
    fn default() -> Self {
        Self {
            max_attempts: 50,
            concurrency: 8,
            delay: Duration::from_millis(200),
            timeout: Duration::from_secs(5),
        }
    }
}

/// Try credentials against each `(host, port)` target for one service, stopping
/// at the first success per target. Returns a High-severity [`Finding`] per hit.
pub async fn run_brute(
    targets: Vec<(String, u16)>,
    service: Arc<dyn BruteService>,
    creds: Arc<Vec<Credential>>,
    config: BruteConfig,
) -> Vec<Finding> {
    let sem = Arc::new(Semaphore::new(config.concurrency.max(1)));
    let mut set = tokio::task::JoinSet::new();

    for (host, port) in targets {
        let sem = sem.clone();
        let service = service.clone();
        let creds = creds.clone();
        let config = config.clone();
        set.spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            try_target(&host, port, service.as_ref(), &creds, &config).await
        });
    }

    let mut findings = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(Some(f)) = joined {
            findings.push(f);
        }
    }
    findings
}

async fn try_target(
    host: &str,
    port: u16,
    service: &dyn BruteService,
    creds: &[Credential],
    config: &BruteConfig,
) -> Option<Finding> {
    let limit = if config.max_attempts == 0 {
        creds.len()
    } else {
        config.max_attempts.min(creds.len())
    };

    for (i, cred) in creds.iter().take(limit).enumerate() {
        if i > 0 && !config.delay.is_zero() {
            tokio::time::sleep(config.delay).await;
        }
        match service.try_login(host, port, cred, config.timeout).await {
            Ok(true) => return Some(hit_finding(service.name(), host, port, cred)),
            Ok(false) => {}
            // Connection/protocol errors: treat as non-match and keep going,
            // but a first-attempt failure usually means the port isn't the
            // service — the bounded loop still caps total work.
            Err(_) => {}
        }
    }
    None
}

fn hit_finding(service: &str, host: &str, port: u16, cred: &Credential) -> Finding {
    let mut f = Finding::new(
        format!("weak-cred-{service}"),
        format!("Weak {service} credential"),
        Severity::High,
        Target::new(host.to_string(), Some(port)),
    );
    f.evidence = vec![alive_core::Evidence {
        part: "credential".into(),
        snippet: format!("{}:{}", cred.username, cred.password),
    }];
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// In-memory service: succeeds only for `winner`, counts every attempt.
    struct FakeService {
        winner: Credential,
        attempts: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl BruteService for FakeService {
        fn name(&self) -> &'static str {
            "fake"
        }
        async fn try_login(
            &self,
            _host: &str,
            _port: u16,
            cred: &Credential,
            _to: Duration,
        ) -> alive_core::Result<bool> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            Ok(*cred == self.winner)
        }
    }

    fn no_delay() -> BruteConfig {
        BruteConfig {
            delay: Duration::ZERO,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn stops_at_first_success_per_target() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let service = Arc::new(FakeService {
            winner: Credential::new("admin", "admin"),
            attempts: attempts.clone(),
        });
        let creds = Arc::new(vec![
            Credential::new("root", "root"),
            Credential::new("admin", "admin"), // 2nd cred wins
            Credential::new("guest", "guest"), // must NOT be tried
        ]);
        let findings = run_brute(vec![("host".into(), 6379)], service, creds, no_delay()).await;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].template_id, "weak-cred-fake");
        assert_eq!(attempts.load(Ordering::SeqCst), 2, "must short-circuit");
    }

    #[tokio::test]
    async fn no_success_yields_no_finding() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let service = Arc::new(FakeService {
            winner: Credential::new("nope", "nope"),
            attempts: attempts.clone(),
        });
        let creds = Arc::new(vec![Credential::new("a", "b"), Credential::new("c", "d")]);
        let findings = run_brute(vec![("h".into(), 21)], service, creds, no_delay()).await;
        assert!(findings.is_empty());
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }
}
