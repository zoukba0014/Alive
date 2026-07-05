use std::path::PathBuf;

use alive_proto::fleet::fleet_client::FleetClient;
use alive_proto::{agent_message, server_message, AgentMessage, EnrollRequest, Hello, TaskResult};
use alive_transport::client_tls;
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
    pub tls_domain: String,
}

/// Enroll, open the long-lived stream, and execute pushed tasks until the
/// stream closes. Reconnection/backoff and offline buffering land in M7.
pub async fn run_agent(cfg: AgentConfig) -> Result<(), Box<dyn std::error::Error>> {
    // --- Enroll -------------------------------------------------------------
    let enroll_channel = if cfg.insecure {
        Channel::from_shared(cfg.server_url.clone())?
            .connect()
            .await?
    } else {
        let ca = cfg
            .ca_pem
            .clone()
            .ok_or("mTLS mode requires a CA PEM (--ca-file)")?;
        Channel::from_shared(cfg.server_url.clone())?
            .tls_config(
                tonic::transport::ClientTlsConfig::new()
                    .ca_certificate(tonic::transport::Certificate::from_pem(ca))
                    .domain_name(&cfg.tls_domain),
            )?
            .connect()
            .await?
    };
    let mut client = FleetClient::new(enroll_channel);
    let enroll = client
        .enroll(EnrollRequest {
            agent_name: cfg.agent_name.clone(),
        })
        .await?
        .into_inner();
    let agent_id = enroll.agent_id.clone();
    let verify_key = enroll.server_verify_key.clone();
    eprintln!("[agent] enrolled as {agent_id}");

    // --- Reconnect with mTLS for the stream (secure mode) -------------------
    let mut client = if cfg.insecure {
        client
    } else {
        let channel = Channel::from_shared(cfg.server_url.clone())?
            .tls_config(client_tls(
                &enroll.client_cert_pem,
                &enroll.client_key_pem,
                &enroll.ca_cert_pem,
                &cfg.tls_domain,
            ))?
            .connect()
            .await?;
        FleetClient::new(channel)
    };

    // --- Open the bidi stream, say Hello ------------------------------------
    let (tx, rx) = mpsc::channel::<AgentMessage>(64);
    tx.send(AgentMessage {
        kind: Some(agent_message::Kind::Hello(Hello {
            agent_id: agent_id.clone(),
        })),
    })
    .await?;

    let mut inbound = client.stream(ReceiverStream::new(rx)).await?.into_inner();
    let ctx = ExecContext {
        template_dir: cfg.template_dir.clone(),
        concurrency: 200,
        timeout_secs: 3,
    };

    while let Some(msg) = inbound.message().await? {
        let Some(server_message::Kind::Task(task)) = msg.kind else {
            continue;
        };
        let task_id = task.task_id.clone();
        let result = match verify_and_execute(&task, &verify_key, &ctx).await {
            Ok(findings) => {
                eprintln!("[agent] task {task_id}: {} finding(s)", findings.len());
                TaskResult {
                    task_id,
                    findings_json: serde_json::to_string(&findings).unwrap_or_else(|_| "[]".into()),
                    status: "ok".into(),
                }
            }
            Err(e) => {
                eprintln!("[agent] task {task_id} refused: {e}");
                TaskResult {
                    task_id,
                    findings_json: "[]".into(),
                    status: format!("refused: {e}"),
                }
            }
        };
        tx.send(AgentMessage {
            kind: Some(agent_message::Kind::Result(result)),
        })
        .await?;
    }
    Ok(())
}
