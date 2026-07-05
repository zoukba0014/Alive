use std::path::PathBuf;
use std::time::Duration;

use alive_core::{Finding, Severity, Target};
use alive_discovery::{detect, expand, parse_ports, scan_ports};
use alive_engine::run_http_template;
use alive_proto::{task, Task};
use alive_protocols::HttpRunner;
use alive_template::{check_template, load_dir};
use alive_transport::{targets_in_scope, verify_task};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExecError {
    #[error("task signature invalid — refusing to execute")]
    BadSignature,
    #[error("target(s) outside authorized scope — refusing to execute")]
    OutOfScope,
    #[error("empty task body")]
    EmptyBody,
}

/// Runtime knobs for task execution (e.g. where POC templates live).
#[derive(Debug, Clone, Default)]
pub struct ExecContext {
    pub template_dir: Option<PathBuf>,
    pub concurrency: usize,
    pub timeout_secs: u64,
}

impl ExecContext {
    fn conc(&self) -> usize {
        if self.concurrency == 0 {
            200
        } else {
            self.concurrency
        }
    }
    fn timeout(&self) -> Duration {
        Duration::from_secs(if self.timeout_secs == 0 {
            3
        } else {
            self.timeout_secs
        })
    }
}

/// Verify a task's signature and authorized scope, then execute it. This is the
/// only entry point the agent uses to act on a server-pushed task.
pub async fn verify_and_execute(
    task: &Task,
    server_verify_key: &[u8],
    ctx: &ExecContext,
) -> Result<Vec<Finding>, ExecError> {
    if !verify_task(server_verify_key, task) {
        return Err(ExecError::BadSignature);
    }
    match &task.body {
        Some(task::Body::Discover(d)) => {
            if !targets_in_scope(&d.targets, &task.authorized_scope) {
                return Err(ExecError::OutOfScope);
            }
            Ok(run_discover(&d.targets, &d.ports, ctx).await)
        }
        Some(task::Body::Scan(s)) => {
            if !targets_in_scope(&s.targets, &task.authorized_scope) {
                return Err(ExecError::OutOfScope);
            }
            Ok(run_scan(&s.targets, ctx).await)
        }
        Some(task::Body::CollectInventory(_)) => Ok(run_inventory()),
        None => Err(ExecError::EmptyBody),
    }
}

async fn run_discover(targets: &[String], ports: &str, ctx: &ExecContext) -> Vec<Finding> {
    let mut ips = Vec::new();
    for t in targets {
        if let Ok(expanded) = expand(t) {
            ips.extend(expanded);
        }
    }
    let ports = parse_ports(ports).unwrap_or_default();
    if ips.is_empty() || ports.is_empty() {
        return Vec::new();
    }
    let open = scan_ports(&ips, &ports, ctx.conc(), ctx.timeout()).await;
    let mut findings = Vec::new();
    for (ip, port) in open {
        let svc = detect(ip, port, ctx.timeout()).await;
        let mut f = Finding::new(
            "discovery",
            format!("{} service", svc.name),
            Severity::Info,
            Target::new(ip.to_string(), Some(port)),
        );
        if let Some(banner) = svc.banner {
            f.extracted.push(banner);
        }
        findings.push(f);
    }
    findings
}

/// Minimal HTTP-template scan against the given targets. Requires a template
/// directory in the context; without one it returns nothing.
async fn run_scan(targets: &[String], ctx: &ExecContext) -> Vec<Finding> {
    let Some(dir) = &ctx.template_dir else {
        return Vec::new();
    };
    let templates: Vec<_> = load_dir(dir)
        .into_iter()
        .filter_map(|(_, r)| r.ok())
        .filter(|t| check_template(t).runnable && !t.http.is_empty())
        .collect();
    let runner = match HttpRunner::new(ctx.timeout(), true) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let mut findings = Vec::new();
    for raw in targets {
        let base = if raw.starts_with("http") {
            raw.trim_end_matches('/').to_string()
        } else {
            format!("http://{raw}")
        };
        let target = raw
            .parse()
            .unwrap_or_else(|_| Target::new(raw.clone(), None));
        for t in &templates {
            if let Ok(Some(f)) = run_http_template(t, &target, &base, &runner).await {
                findings.push(f);
            }
        }
    }
    findings
}

fn run_inventory() -> Vec<Finding> {
    let mut f = Finding::new(
        "inventory",
        "host inventory",
        Severity::Info,
        Target::new("localhost", None),
    );
    f.extracted.push(format!("os={}", std::env::consts::OS));
    f.extracted.push(format!("arch={}", std::env::consts::ARCH));
    vec![f]
}

#[cfg(test)]
mod tests {
    use super::*;
    use alive_proto::DiscoverTask;
    use alive_transport::{sign_task, SigningIdentity};

    fn signed_discover(id: &SigningIdentity, targets: Vec<String>, scope: Vec<String>) -> Task {
        let mut t = Task {
            task_id: "t1".into(),
            authorized_scope: scope,
            issued_at: 0,
            signature: vec![],
            body: Some(task::Body::Discover(DiscoverTask {
                targets,
                ports: "1".into(),
            })),
        };
        sign_task(id, &mut t);
        t
    }

    #[tokio::test]
    async fn refuses_bad_signature() {
        let id = SigningIdentity::generate();
        let other = SigningIdentity::generate();
        let t = signed_discover(&id, vec!["127.0.0.1".into()], vec!["127.0.0.1/32".into()]);
        let ctx = ExecContext::default();
        let r = verify_and_execute(&t, &other.verify_key_bytes(), &ctx).await;
        assert!(matches!(r, Err(ExecError::BadSignature)));
    }

    #[tokio::test]
    async fn refuses_out_of_scope() {
        let id = SigningIdentity::generate();
        // scope authorizes only 127.0.0.1, but target is 8.8.8.8
        let t = signed_discover(&id, vec!["8.8.8.8".into()], vec!["127.0.0.1/32".into()]);
        let ctx = ExecContext::default();
        let r = verify_and_execute(&t, &id.verify_key_bytes(), &ctx).await;
        assert!(matches!(r, Err(ExecError::OutOfScope)));
    }

    #[tokio::test]
    async fn valid_discover_runs() {
        let id = SigningIdentity::generate();
        // 127.0.0.1 port 1 (closed) — returns quickly with no findings.
        let t = signed_discover(&id, vec!["127.0.0.1".into()], vec!["127.0.0.1/32".into()]);
        let ctx = ExecContext::default();
        let r = verify_and_execute(&t, &id.verify_key_bytes(), &ctx).await;
        assert!(r.is_ok());
    }
}
