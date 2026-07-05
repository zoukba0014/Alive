//! `alive-server` — the fleet control plane. Serves the gRPC API over mTLS,
//! runs a simple interval scheduler that dispatches signed tasks to connected
//! agents, ingests results, and audits every dispatch.

use std::path::PathBuf;
use std::time::Duration;

use alive_proto::fleet::fleet_server::FleetServer;
use alive_proto::{task, DiscoverTask};
use alive_server::FleetService;
use clap::Parser;
use tonic::transport::Server;

#[derive(Parser)]
#[command(name = "alive-server", version, about = "Alive fleet control plane")]
struct Cli {
    /// Listen address.
    #[arg(long, default_value = "127.0.0.1:50051")]
    listen: String,
    /// Append-only audit log path (JSONL).
    #[arg(long, default_value = "./fleet-audit.jsonl")]
    audit: PathBuf,
    /// Directory where ingested findings are written.
    #[arg(long, default_value = "./fleet-reports")]
    reports: PathBuf,
    /// Plaintext transport (dev/testing). Omit for mTLS (recommended).
    #[arg(long)]
    insecure: bool,
    /// Enable a demo scheduler: every N seconds, dispatch a DiscoverTask to all
    /// connected agents.
    #[arg(long)]
    schedule_secs: Option<u64>,
    /// Comma-separated discover targets for the scheduler.
    #[arg(long, default_value = "127.0.0.1")]
    schedule_targets: String,
    /// Authorized scope for scheduled tasks (CIDR/host list, comma-separated).
    #[arg(long, default_value = "127.0.0.1/32")]
    schedule_scope: String,
    /// Ports for scheduled discover tasks.
    #[arg(long, default_value = "80,443,22")]
    schedule_ports: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let addr = cli.listen.parse()?;
    let service = FleetService::new(cli.audit.clone(), cli.reports.clone())
        .map_err(|e| format!("service init: {e}"))?;

    if let Some(secs) = cli.schedule_secs {
        spawn_scheduler(
            service.clone(),
            Duration::from_secs(secs.max(1)),
            split(&cli.schedule_targets),
            split(&cli.schedule_scope),
            cli.schedule_ports.clone(),
        );
    }

    eprintln!(
        "[server] listening on {} ({})",
        cli.listen,
        if cli.insecure { "plaintext" } else { "mTLS" }
    );

    let mut builder = Server::builder();
    if !cli.insecure {
        let (cert, key, ca) = service
            .server_identity_pems()
            .map_err(|e| format!("tls identity: {e}"))?;
        builder = builder.tls_config(alive_transport::server_tls(&cert, &key, &ca))?;
    }
    builder
        .add_service(FleetServer::new(service))
        .serve(addr)
        .await?;
    Ok(())
}

fn split(s: &str) -> Vec<String> {
    s.split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

/// Demo scheduler: on each tick, dispatch a signed DiscoverTask to every
/// connected agent. A production scheduler would map asset groups → cadences.
fn spawn_scheduler(
    service: FleetService,
    period: Duration,
    targets: Vec<String>,
    scope: Vec<String>,
    ports: String,
) {
    tokio::spawn(async move {
        let registry = service.registry();
        let mut tick = 0u64;
        let mut interval = tokio::time::interval(period);
        loop {
            interval.tick().await;
            tick += 1;
            let body = task::Body::Discover(DiscoverTask {
                targets: targets.clone(),
                ports: ports.clone(),
            });
            for agent_id in registry.agent_ids() {
                let task = service.make_task(&format!("sched-{tick}"), scope.clone(), body.clone());
                registry.dispatch(&agent_id, task);
            }
        }
    });
}
