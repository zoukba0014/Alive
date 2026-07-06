//! `alive-agent` — the reference fleet agent. Runs as a visible foreground
//! service (systemd-friendly); it does not hide itself or persist covertly.

use std::path::PathBuf;

use alive_agent::{run_agent, AgentConfig};
use clap::Parser;

#[derive(Parser)]
#[command(name = "alive-agent", version, about = "Alive fleet agent")]
struct Cli {
    /// Control-plane URL, e.g. http://127.0.0.1:50051 or https://host:50051.
    #[arg(long, default_value = "http://127.0.0.1:50051")]
    server: String,
    /// Human-readable name recorded at enrollment.
    #[arg(long, default_value = "agent")]
    name: String,
    /// POC template directory (used by ScanTask).
    #[arg(long)]
    templates: Option<PathBuf>,
    /// Use plaintext (dev/testing). Omit for mTLS.
    #[arg(long)]
    insecure: bool,
    /// CA PEM to trust for the mTLS enrollment bootstrap.
    #[arg(long)]
    ca_file: Option<PathBuf>,
    /// Shared bootstrap client cert (PEM) for the mTLS enroll handshake
    /// (operator-distributed alongside the CA).
    #[arg(long)]
    bootstrap_cert: Option<PathBuf>,
    /// Shared bootstrap client key (PEM) for the mTLS enroll handshake.
    #[arg(long)]
    bootstrap_key: Option<PathBuf>,
    /// Expected server certificate domain (SAN) for mTLS.
    #[arg(long, default_value = "localhost")]
    tls_domain: String,
    /// Persistent offline buffer path. Set to survive server outages: results
    /// are buffered while offline and flushed on reconnect.
    #[arg(long)]
    buffer_path: Option<PathBuf>,
    /// Mesh bind address (ip:port) to join the decentralized peer mesh
    /// (failure detection + leader election). Bind a routable address.
    #[arg(long)]
    mesh_bind: Option<String>,
    /// Seed peer mesh addresses (repeatable / comma-separated).
    #[arg(long, value_delimiter = ',')]
    mesh_seed: Vec<String>,
    /// Reconnect backoff ceiling in seconds (also the offline re-execution cadence).
    #[arg(long, default_value_t = 30)]
    max_backoff_secs: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let read_opt = |p: &Option<PathBuf>| -> std::io::Result<Option<Vec<u8>>> {
        match p {
            Some(p) => Ok(Some(std::fs::read(p)?)),
            None => Ok(None),
        }
    };
    let ca_pem = read_opt(&cli.ca_file)?;
    let bootstrap_cert_pem = read_opt(&cli.bootstrap_cert)?;
    let bootstrap_key_pem = read_opt(&cli.bootstrap_key)?;
    run_agent(AgentConfig {
        server_url: cli.server,
        agent_name: cli.name,
        template_dir: cli.templates,
        insecure: cli.insecure,
        ca_pem,
        bootstrap_cert_pem,
        bootstrap_key_pem,
        tls_domain: cli.tls_domain,
        buffer_path: cli.buffer_path,
        mesh_bind: cli.mesh_bind,
        mesh_seeds: cli.mesh_seed,
        max_backoff_secs: cli.max_backoff_secs,
    })
    .await
}
