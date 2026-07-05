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
    /// Expected server certificate domain (SAN) for mTLS.
    #[arg(long, default_value = "localhost")]
    tls_domain: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let ca_pem = match &cli.ca_file {
        Some(p) => Some(std::fs::read(p)?),
        None => None,
    };
    run_agent(AgentConfig {
        server_url: cli.server,
        agent_name: cli.name,
        template_dir: cli.templates,
        insecure: cli.insecure,
        ca_pem,
        tls_domain: cli.tls_domain,
    })
    .await
}
