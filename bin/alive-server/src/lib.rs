//! Fleet control-plane library: the gRPC service, agent registry, audit log,
//! and signed-task construction. The binary (`main.rs`) wires this to mTLS +
//! a scheduler; integration tests drive it over plaintext localhost.

use std::collections::HashMap;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use alive_proto::fleet::fleet_server::Fleet;
use alive_proto::{
    agent_message, server_message, task, AgentMessage, EnrollResponse, ServerMessage, Task,
    TaskResult,
};
use alive_transport::{issue_leaf, load_signing_key, sign_task, Ca, SigningIdentity};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};

mod audit;
pub use audit::{verify_audit_chain, AuditLog};

/// PEM triple `(server_cert, server_key, ca_cert)` for building mTLS config.
pub type ServerIdentityPems = (Vec<u8>, Vec<u8>, Vec<u8>);

/// Tracks connected agents (agent_id → outbound sender) and audits dispatches.
pub struct Registry {
    agents: Mutex<HashMap<String, mpsc::Sender<Result<ServerMessage, Status>>>>,
    audit: Arc<AuditLog>,
}

impl Registry {
    fn new(audit: Arc<AuditLog>) -> Self {
        Self {
            agents: Mutex::new(HashMap::new()),
            audit,
        }
    }

    fn register(&self, agent_id: &str, tx: mpsc::Sender<Result<ServerMessage, Status>>) {
        self.agents.lock().unwrap().insert(agent_id.to_string(), tx);
    }

    fn unregister(&self, agent_id: &str) {
        self.agents.lock().unwrap().remove(agent_id);
    }

    /// Number of currently connected agents.
    pub fn connected(&self) -> usize {
        self.agents.lock().unwrap().len()
    }

    /// IDs of currently connected agents.
    pub fn agent_ids(&self) -> Vec<String> {
        self.agents.lock().unwrap().keys().cloned().collect()
    }

    /// Push a (already-signed) task to a connected agent. Returns false if the
    /// agent is not connected. Every dispatch is audit-logged.
    pub fn dispatch(&self, agent_id: &str, task: Task) -> bool {
        let tx = self.agents.lock().unwrap().get(agent_id).cloned();
        match tx {
            Some(tx) => {
                self.audit
                    .record("dispatch", agent_id, &task.task_id, task_kind(&task));
                let msg = ServerMessage {
                    kind: Some(server_message::Kind::Task(task)),
                };
                tx.try_send(Ok(msg)).is_ok()
            }
            None => false,
        }
    }
}

/// The gRPC service implementation.
#[derive(Clone)]
pub struct FleetService {
    registry: Arc<Registry>,
    identity: Arc<SigningIdentity>,
    ca: Arc<Mutex<Ca>>,
    audit: Arc<AuditLog>,
    report_dir: PathBuf,
    agent_seq: Arc<Mutex<u64>>,
}

impl FleetService {
    /// Build a service with an ephemeral CA + signing identity (in-memory,
    /// nothing persisted). Used by tests. Production servers use
    /// [`FleetService::with_state`] so the CA and signing key survive restarts
    /// and the CA PEM is written to disk for agents to trust.
    pub fn new(audit_path: PathBuf, report_dir: PathBuf) -> Result<Self, String> {
        let ca = alive_transport::generate_ca().map_err(|e| e.to_string())?;
        Ok(Self::from_parts(
            ca,
            SigningIdentity::generate(),
            audit_path,
            report_dir,
        ))
    }

    /// Build a service backed by a persistent state directory.
    ///
    /// On first run the CA (cert+key) and the ed25519 signing seed are generated
    /// and written under `state_dir`; on restart they are reloaded so previously
    /// enrolled agent certs and previously issued task signatures stay valid.
    /// The CA certificate is always (re)written to `state_dir/ca.pem` — that is
    /// the file operators distribute to agents as `--ca-file`.
    pub fn with_state(
        state_dir: PathBuf,
        audit_path: PathBuf,
        report_dir: PathBuf,
    ) -> Result<Self, String> {
        std::fs::create_dir_all(&state_dir).map_err(|e| format!("state dir: {e}"))?;
        let ca_cert_path = state_dir.join("ca.pem");
        let ca_key_path = state_dir.join("ca.key");
        let seed_path = state_dir.join("server.seed");

        let (ca, identity) = if ca_cert_path.exists() && ca_key_path.exists() && seed_path.exists()
        {
            let cert_pem =
                std::fs::read_to_string(&ca_cert_path).map_err(|e| format!("read ca.pem: {e}"))?;
            let key_pem =
                std::fs::read_to_string(&ca_key_path).map_err(|e| format!("read ca.key: {e}"))?;
            let ca = Ca::from_pem(&cert_pem, &key_pem).map_err(|e| e.to_string())?;
            let seed = std::fs::read(&seed_path).map_err(|e| format!("read server.seed: {e}"))?;
            let identity = load_signing_key(&seed).map_err(|e| e.to_string())?;
            (ca, identity)
        } else {
            let ca = alive_transport::generate_ca().map_err(|e| e.to_string())?;
            let identity = SigningIdentity::generate();
            std::fs::write(&ca_cert_path, ca.ca_cert_pem.as_bytes())
                .map_err(|e| format!("write ca.pem: {e}"))?;
            write_secret(&ca_key_path, ca.ca_key_pem.as_bytes())?;
            write_secret(&seed_path, &identity.secret_bytes())?;
            (ca, identity)
        };

        // (Re)issue the shared bootstrap client cert. mTLS requires a client
        // cert on every connection, but an agent has none until it enrolls —
        // so agents use this CA-signed bootstrap cert *only* for the enroll
        // handshake, then switch to their individually-issued cert for the
        // task stream. It is signed by the same CA, so it always chains cleanly.
        let (boot_cert, boot_key) = issue_leaf(
            &ca,
            "alive-bootstrap",
            &["localhost".into(), "127.0.0.1".into()],
        )
        .map_err(|e| e.to_string())?;
        let (boot_cert_path, boot_key_path) = Self::bootstrap_files(&state_dir);
        std::fs::write(&boot_cert_path, boot_cert.as_bytes())
            .map_err(|e| format!("write bootstrap.pem: {e}"))?;
        write_secret(&boot_key_path, boot_key.as_bytes())?;

        Ok(Self::from_parts(ca, identity, audit_path, report_dir))
    }

    /// Path to the CA cert an operator hands to agents (`--ca-file`).
    pub fn ca_file(state_dir: &std::path::Path) -> PathBuf {
        state_dir.join("ca.pem")
    }

    /// Paths to the shared bootstrap client cert + key agents use for the enroll
    /// handshake (`--bootstrap-cert` / `--bootstrap-key`).
    pub fn bootstrap_files(state_dir: &std::path::Path) -> (PathBuf, PathBuf) {
        (
            state_dir.join("bootstrap.pem"),
            state_dir.join("bootstrap.key"),
        )
    }

    fn from_parts(
        ca: Ca,
        identity: SigningIdentity,
        audit_path: PathBuf,
        report_dir: PathBuf,
    ) -> Self {
        let audit = Arc::new(AuditLog::new(audit_path));
        Self {
            registry: Arc::new(Registry::new(audit.clone())),
            identity: Arc::new(identity),
            ca: Arc::new(Mutex::new(ca)),
            audit,
            report_dir,
            agent_seq: Arc::new(Mutex::new(0)),
        }
    }

    pub fn registry(&self) -> Arc<Registry> {
        self.registry.clone()
    }

    pub fn audit(&self) -> Arc<AuditLog> {
        self.audit.clone()
    }

    /// Issue a server leaf cert (PEM) for mTLS, plus the CA cert to require of
    /// clients. Returns `(server_cert, server_key, ca_cert)`.
    pub fn server_identity_pems(&self) -> Result<ServerIdentityPems, String> {
        let ca = self.ca.lock().unwrap();
        let (cert, key) = issue_leaf(
            &ca,
            "alive-server",
            &["localhost".into(), "127.0.0.1".into()],
        )
        .map_err(|e| e.to_string())?;
        Ok((
            cert.into_bytes(),
            key.into_bytes(),
            ca.ca_cert_pem.clone().into_bytes(),
        ))
    }

    /// Build and sign a task from a body + authorized scope.
    pub fn make_task(&self, task_id: &str, scope: Vec<String>, body: task::Body) -> Task {
        let mut task = Task {
            task_id: task_id.to_string(),
            authorized_scope: scope,
            issued_at: 0,
            signature: vec![],
            body: Some(body),
        };
        sign_task(&self.identity, &mut task);
        task
    }
}

/// Write a secret file with owner-only permissions (0600 on Unix).
fn write_secret(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|e| format!("write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    }
    Ok(())
}

fn task_kind(task: &Task) -> &'static str {
    match &task.body {
        Some(task::Body::Scan(_)) => "scan",
        Some(task::Body::Discover(_)) => "discover",
        Some(task::Body::CollectInventory(_)) => "collect_inventory",
        None => "empty",
    }
}

fn ingest_result(report_dir: &PathBuf, agent_id: &str, r: &TaskResult) {
    let _ = std::fs::create_dir_all(report_dir);
    let path = report_dir.join(format!("{agent_id}-{}.json", r.task_id));
    let _ = std::fs::write(path, &r.findings_json);
}

#[tonic::async_trait]
impl Fleet for FleetService {
    async fn enroll(
        &self,
        request: Request<alive_proto::EnrollRequest>,
    ) -> Result<Response<EnrollResponse>, Status> {
        let name = request.into_inner().agent_name;
        let id = {
            let mut seq = self.agent_seq.lock().unwrap();
            *seq += 1;
            format!("agent-{seq}-{name}")
        };
        let (cert, key) = {
            let ca = self.ca.lock().unwrap();
            issue_leaf(
                &ca,
                &id,
                &["localhost".into(), "127.0.0.1".into(), id.clone()],
            )
            .map_err(|e| Status::internal(e.to_string()))?
        };
        let ca_pem = self.ca.lock().unwrap().ca_cert_pem.clone();
        self.audit.record("enroll", &id, "", "issued cert");
        Ok(Response::new(EnrollResponse {
            agent_id: id,
            client_cert_pem: cert.into_bytes(),
            client_key_pem: key.into_bytes(),
            ca_cert_pem: ca_pem.into_bytes(),
            server_verify_key: self.identity.verify_key_bytes().to_vec(),
        }))
    }

    type StreamStream = Pin<Box<dyn Stream<Item = Result<ServerMessage, Status>> + Send + 'static>>;

    async fn stream(
        &self,
        request: Request<Streaming<AgentMessage>>,
    ) -> Result<Response<Self::StreamStream>, Status> {
        let mut inbound = request.into_inner();
        let (tx, rx) = mpsc::channel::<Result<ServerMessage, Status>>(64);
        let registry = self.registry.clone();
        let audit = self.audit.clone();
        let report_dir = self.report_dir.clone();

        tokio::spawn(async move {
            let mut agent_id = String::new();
            while let Ok(Some(msg)) = inbound.message().await {
                match msg.kind {
                    Some(agent_message::Kind::Hello(h)) => {
                        agent_id = h.agent_id;
                        registry.register(&agent_id, tx.clone());
                        audit.record("connect", &agent_id, "", "stream opened");
                    }
                    Some(agent_message::Kind::Result(r)) => {
                        audit.record("result", &agent_id, &r.task_id, &r.status);
                        ingest_result(&report_dir, &agent_id, &r);
                    }
                    _ => {}
                }
            }
            if !agent_id.is_empty() {
                registry.unregister(&agent_id);
                audit.record("disconnect", &agent_id, "", "stream closed");
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}
