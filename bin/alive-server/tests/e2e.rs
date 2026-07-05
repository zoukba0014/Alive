//! End-to-end fleet test: a server dispatches a signed DiscoverTask to a
//! connected agent, the agent verifies + executes it and streams a result
//! back, and the dispatch + result are recorded in the audit log.
//!
//! Uses a plaintext localhost channel FOR THE TEST ONLY (wiring mTLS certs
//! into an in-process test adds nothing to what the transport unit tests
//! already cover). The real binaries default to mTLS.

use std::time::Duration;

use alive_agent::exec::{verify_and_execute, ExecContext};
use alive_proto::fleet::fleet_client::FleetClient;
use alive_proto::fleet::fleet_server::FleetServer;
use alive_proto::{
    agent_message, server_message, task, AgentMessage, DiscoverTask, EnrollRequest, Hello,
    TaskResult,
};
use alive_server::FleetService;
use tokio::sync::mpsc;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::transport::{Channel, Server};

async fn wait_for<F: Fn() -> bool>(cond: F, tries: u32) -> bool {
    for _ in 0..tries {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    cond()
}

#[tokio::test]
async fn dispatch_verify_execute_audit() {
    let dir = std::env::temp_dir().join(format!("alive-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let audit_path = dir.join("audit.jsonl");
    let reports = dir.join("reports");

    let service = FleetService::new(audit_path.clone(), reports).unwrap();
    let handle = service.clone(); // registry + make_task for the test driver

    // Start the server on an ephemeral localhost port (plaintext).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        Server::builder()
            .add_service(FleetServer::new(service))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // --- Client (acting as the agent) --------------------------------------
    let channel = Channel::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = FleetClient::new(channel);
    let enroll = client
        .enroll(EnrollRequest {
            agent_name: "e2e".into(),
        })
        .await
        .unwrap()
        .into_inner();
    let agent_id = enroll.agent_id.clone();
    let verify_key = enroll.server_verify_key.clone();

    let (tx, rx) = mpsc::channel::<AgentMessage>(16);
    tx.send(AgentMessage {
        kind: Some(agent_message::Kind::Hello(Hello {
            agent_id: agent_id.clone(),
        })),
    })
    .await
    .unwrap();

    let mut inbound = client
        .stream(ReceiverStream::new(rx))
        .await
        .unwrap()
        .into_inner();

    // Agent-side task handler: verify + execute, stream result back.
    let tx_result = tx.clone();
    tokio::spawn(async move {
        let ctx = ExecContext::default();
        while let Ok(Some(msg)) = inbound.message().await {
            if let Some(server_message::Kind::Task(t)) = msg.kind {
                let task_id = t.task_id.clone();
                let findings = verify_and_execute(&t, &verify_key, &ctx)
                    .await
                    .unwrap_or_default();
                let _ = tx_result
                    .send(AgentMessage {
                        kind: Some(agent_message::Kind::Result(TaskResult {
                            task_id,
                            findings_json: serde_json::to_string(&findings).unwrap(),
                            status: "ok".into(),
                        })),
                    })
                    .await;
            }
        }
    });

    // Wait for the agent to register.
    let registry = handle.registry();
    assert!(
        wait_for(|| registry.connected() > 0, 40).await,
        "agent never registered"
    );

    // Dispatch a signed DiscoverTask scoped to loopback.
    let body = task::Body::Discover(DiscoverTask {
        targets: vec!["127.0.0.1".into()],
        ports: "1".into(), // closed port → fast, deterministic empty result
    });
    let task = handle.make_task("e2e-task-1", vec!["127.0.0.1/32".into()], body);
    assert!(
        registry.dispatch(&agent_id, task),
        "dispatch to connected agent failed"
    );

    // Wait until the result is ingested (audit records a "result" line).
    let audit_ok = wait_for(
        || {
            std::fs::read_to_string(&audit_path)
                .map(|s| s.contains("\"result\"") && s.contains("e2e-task-1"))
                .unwrap_or(false)
        },
        60,
    )
    .await;

    let audit = std::fs::read_to_string(&audit_path).unwrap_or_default();
    assert!(audit_ok, "result not audited; audit log:\n{audit}");
    assert!(audit.contains("\"dispatch\""), "dispatch not audited");
    assert!(audit.contains("\"enroll\""), "enroll not audited");

    let _ = std::fs::remove_dir_all(&dir);
}
