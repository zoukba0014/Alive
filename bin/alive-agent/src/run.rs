use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use alive_buffer::{Buffer, BufferedResult};
use alive_mesh::GossipMembership;
use alive_proto::fleet::fleet_client::FleetClient;
use alive_proto::{
    agent_message, server_message, AgentMessage, EnrollRequest, EnrollResponse, Hello, Task,
    TaskResult,
};
use alive_transport::client_tls;
use prost::Message;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;

use crate::exec::{verify_and_execute, ExecContext};

/// Configuration for the reference agent.
pub struct AgentConfig {
    /// `http://host:port` (insecure) or `https://host:port` (mTLS).
    pub server_url: String,
    pub agent_name: String,
    pub template_dir: Option<PathBuf>,
    /// When false, use mTLS: enroll over server-authenticated TLS trusting
    /// `ca_pem`, then reconnect with the issued client identity.
    pub insecure: bool,
    /// CA PEM (operator-distributed) required for the mTLS enroll bootstrap.
    pub ca_pem: Option<Vec<u8>>,
    /// Shared bootstrap client cert/key (CA-signed, operator-distributed) used
    /// only for the enroll handshake — mTLS needs a client cert before the
    /// agent has its own. After enrolling, the individually-issued cert is used.
    pub bootstrap_cert_pem: Option<Vec<u8>>,
    pub bootstrap_key_pem: Option<Vec<u8>>,
    pub tls_domain: String,
    /// Persistent offline buffer path. When set, results are buffered while the
    /// server is unreachable and flushed on reconnect.
    pub buffer_path: Option<PathBuf>,
    /// Mesh bind address (`ip:port`) for peer failure detection + leader
    /// election. When set, the agent joins the decentralized mesh.
    pub mesh_bind: Option<String>,
    /// Seed peer mesh addresses to join an existing mesh.
    pub mesh_seeds: Vec<String>,
    /// Reconnect backoff ceiling (seconds); also the offline re-execution cadence.
    pub max_backoff_secs: u64,
}

/// Enroll (retrying until the server is reachable), then hold a long-lived
/// stream — reconnecting with backoff, buffering results while offline, and
/// re-running cached signed tasks so scheduled work survives a server outage.
pub async fn run_agent(cfg: AgentConfig) -> Result<(), Box<dyn std::error::Error>> {
    let buffer = match &cfg.buffer_path {
        Some(p) => Some(Buffer::open(p)?),
        None => None,
    };

    let mesh = match &cfg.mesh_bind {
        Some(bind) => {
            let m = GossipMembership::start(bind, cfg.mesh_seeds.clone(), 1000, 5000).await?;
            eprintln!(
                "[agent] mesh joined at {} (leader={})",
                m.self_id(),
                m.leader()
            );
            Some(m)
        }
        None => None,
    };

    let enroll = enroll_with_retry(&cfg).await;
    let verify_key = enroll.server_verify_key.clone();
    eprintln!("[agent] enrolled as {}", enroll.agent_id);

    let ctx = ExecContext {
        template_dir: cfg.template_dir.clone(),
        concurrency: 200,
        timeout_secs: 3,
    };

    // Signed tasks the server has sent, kept so they can re-run while offline.
    // The prost bytes preserve the signature + scope → re-verified before each run.
    let mut task_cache: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut backoff = 1u64;

    loop {
        match serve_once(&cfg, &enroll, &verify_key, &ctx, &buffer, &mut task_cache).await {
            Ok(()) => {
                // Clean stream close (e.g. server restart): reconnect promptly.
                backoff = 1;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(e) => {
                eprintln!("[agent] server unreachable ({e}) — running cached tasks offline");
                run_cached_offline(&verify_key, &ctx, &task_cache, &buffer, mesh.as_ref()).await;
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(cfg.max_backoff_secs.max(1));
            }
        }
    }
}

/// Enroll, retrying with capped backoff until the control plane answers.
async fn enroll_with_retry(cfg: &AgentConfig) -> EnrollResponse {
    let mut backoff = 1u64;
    loop {
        match enroll_once(cfg).await {
            Ok(resp) => return resp,
            Err(e) => {
                eprintln!("[agent] enroll failed ({e}); retrying in {backoff}s");
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(cfg.max_backoff_secs.max(1));
            }
        }
    }
}

async fn enroll_once(cfg: &AgentConfig) -> Result<EnrollResponse, Box<dyn std::error::Error>> {
    let channel = if cfg.insecure {
        Channel::from_shared(cfg.server_url.clone())?
            .connect()
            .await?
    } else {
        let ca = cfg
            .ca_pem
            .clone()
            .ok_or("mTLS mode requires a CA PEM (--ca-file)")?;
        // The enroll handshake is full mTLS, so present the shared bootstrap
        // client cert (the agent has no individual cert yet).
        let cert = cfg
            .bootstrap_cert_pem
            .clone()
            .ok_or("mTLS enroll requires a bootstrap client cert (--bootstrap-cert)")?;
        let key = cfg
            .bootstrap_key_pem
            .clone()
            .ok_or("mTLS enroll requires a bootstrap client key (--bootstrap-key)")?;
        Channel::from_shared(cfg.server_url.clone())?
            .tls_config(client_tls(&cert, &key, &ca, &cfg.tls_domain))?
            .connect()
            .await?
    };
    let resp = FleetClient::new(channel)
        .enroll(EnrollRequest {
            agent_name: cfg.agent_name.clone(),
        })
        .await?
        .into_inner();
    Ok(resp)
}

/// Build a stream client using the enrolled identity (mTLS) or plaintext.
async fn connect_stream(
    cfg: &AgentConfig,
    enroll: &EnrollResponse,
) -> Result<FleetClient<Channel>, Box<dyn std::error::Error>> {
    let channel = if cfg.insecure {
        Channel::from_shared(cfg.server_url.clone())?
            .connect()
            .await?
    } else {
        Channel::from_shared(cfg.server_url.clone())?
            .tls_config(client_tls(
                &enroll.client_cert_pem,
                &enroll.client_key_pem,
                &enroll.ca_cert_pem,
                &cfg.tls_domain,
            ))?
            .connect()
            .await?
    };
    Ok(FleetClient::new(channel))
}

/// Open the bidi stream, flush any buffered results, then serve pushed tasks
/// until the stream closes or a send fails. Returns `Err` on connect failure.
async fn serve_once(
    cfg: &AgentConfig,
    enroll: &EnrollResponse,
    verify_key: &[u8],
    ctx: &ExecContext,
    buffer: &Option<Buffer>,
    task_cache: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = connect_stream(cfg, enroll).await?;

    let (tx, rx) = mpsc::channel::<AgentMessage>(64);
    tx.send(AgentMessage {
        kind: Some(agent_message::Kind::Hello(Hello {
            agent_id: enroll.agent_id.clone(),
        })),
    })
    .await?;
    let mut inbound = client.stream(ReceiverStream::new(rx)).await?.into_inner();

    // Flush-on-reconnect: deliver results buffered during the outage.
    if let Some(buf) = buffer {
        if let Ok(pending) = buf.drain() {
            if !pending.is_empty() {
                eprintln!("[agent] flushing {} buffered result(s)", pending.len());
            }
            for r in pending {
                let _ = tx
                    .send(AgentMessage {
                        kind: Some(agent_message::Kind::Result(TaskResult {
                            task_id: r.task_id,
                            findings_json: r.findings_json,
                            status: r.status,
                        })),
                    })
                    .await;
            }
        }
    }

    while let Some(msg) = inbound.message().await? {
        let Some(server_message::Kind::Task(task)) = msg.kind else {
            continue;
        };
        // Cache the signed task (prost bytes retain the signature + scope).
        task_cache.insert(task.task_id.clone(), task.encode_to_vec());
        let result = execute_to_result(&task, verify_key, ctx).await;
        if tx
            .send(AgentMessage {
                kind: Some(agent_message::Kind::Result(result.clone())),
            })
            .await
            .is_err()
        {
            // Stream gone mid-flight: preserve the result and reconnect.
            if let Some(buf) = buffer {
                let _ = buf.enqueue(&to_buffered(result));
            }
            break;
        }
    }
    Ok(())
}

/// While the server is unreachable, re-run every cached task once and buffer the
/// results. Each task is re-verified (signature + scope) before it runs.
async fn run_cached_offline(
    verify_key: &[u8],
    ctx: &ExecContext,
    task_cache: &BTreeMap<String, Vec<u8>>,
    buffer: &Option<Buffer>,
    mesh: Option<&GossipMembership>,
) {
    if task_cache.is_empty() {
        return;
    }
    if let Some(m) = mesh {
        // The elected leader is the designated relay when the server returns.
        eprintln!(
            "[agent] offline: {} peer(s), leader={} (self_relay={})",
            m.live_members().len(),
            m.leader(),
            m.is_leader()
        );
    }
    for bytes in task_cache.values() {
        let Ok(task) = Task::decode(bytes.as_slice()) else {
            continue;
        };
        let result = execute_to_result(&task, verify_key, ctx).await;
        if let Some(buf) = buffer {
            let _ = buf.enqueue(&to_buffered(result));
        }
    }
}

/// Verify + execute a task into a wire result (refusals become a status, never a panic).
async fn execute_to_result(task: &Task, verify_key: &[u8], ctx: &ExecContext) -> TaskResult {
    let task_id = task.task_id.clone();
    match verify_and_execute(task, verify_key, ctx).await {
        Ok(findings) => TaskResult {
            task_id,
            findings_json: serde_json::to_string(&findings).unwrap_or_else(|_| "[]".into()),
            status: "ok".into(),
        },
        Err(e) => {
            eprintln!("[agent] task {task_id} refused: {e}");
            TaskResult {
                task_id,
                findings_json: "[]".into(),
                status: format!("refused: {e}"),
            }
        }
    }
}

fn to_buffered(r: TaskResult) -> BufferedResult {
    BufferedResult {
        task_id: r.task_id,
        findings_json: r.findings_json,
        status: r.status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alive_proto::{task, DiscoverTask};
    use alive_transport::{sign_task, SigningIdentity};

    fn signed_discover_bytes(id: &SigningIdentity, task_id: &str) -> Vec<u8> {
        let mut t = Task {
            task_id: task_id.into(),
            authorized_scope: vec!["127.0.0.1/32".into()],
            issued_at: 0,
            signature: vec![],
            body: Some(task::Body::Discover(DiscoverTask {
                targets: vec!["127.0.0.1".into()],
                ports: "1".into(), // closed port → resolves fast, no findings
            })),
        };
        sign_task(id, &mut t);
        t.encode_to_vec()
    }

    #[tokio::test]
    async fn offline_execution_buffers_results_for_flush() {
        let id = SigningIdentity::generate();
        let dir = std::env::temp_dir().join("alive-agent-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("offline.redb");
        let _ = std::fs::remove_file(&path);
        // `.ok()` keeps the type `Option<Buffer>` the helper expects without
        // giving clippy a literal `Some(_)` to flag the later unwrap on.
        let buffer = Buffer::open(&path).ok();

        let mut cache = BTreeMap::new();
        cache.insert("t1".to_string(), signed_discover_bytes(&id, "t1"));
        cache.insert("t2".to_string(), signed_discover_bytes(&id, "t2"));

        let ctx = ExecContext::default();
        run_cached_offline(&id.verify_key_bytes(), &ctx, &cache, &buffer, None).await;

        // Both cached tasks executed offline and their results were buffered,
        // FIFO, ready to flush when the server returns.
        let buf = buffer.unwrap();
        assert_eq!(buf.len().unwrap(), 2);
        let drained = buf.drain().unwrap();
        let ids: Vec<_> = drained.iter().map(|r| r.task_id.as_str()).collect();
        assert_eq!(ids, vec!["t1", "t2"]);
        assert!(drained.iter().all(|r| r.status == "ok"));
    }

    #[tokio::test]
    async fn offline_rerun_reverifies_and_refuses_tampered_task() {
        let id = SigningIdentity::generate();
        let attacker = SigningIdentity::generate();
        let dir = std::env::temp_dir().join("alive-agent-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("offline-tamper.redb");
        let _ = std::fs::remove_file(&path);
        // `.ok()` keeps the type `Option<Buffer>` the helper expects without
        // giving clippy a literal `Some(_)` to flag the later unwrap on.
        let buffer = Buffer::open(&path).ok();

        let mut cache = BTreeMap::new();
        cache.insert("t1".to_string(), signed_discover_bytes(&id, "t1"));
        let ctx = ExecContext::default();

        // Verify against the WRONG key → offline re-run must refuse, not execute.
        run_cached_offline(&attacker.verify_key_bytes(), &ctx, &cache, &buffer, None).await;
        let drained = buffer.unwrap().drain().unwrap();
        assert_eq!(drained.len(), 1);
        assert!(drained[0].status.starts_with("refused"));
    }
}
