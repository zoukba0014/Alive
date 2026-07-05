//! Alive CLI entry point.
//!
//! Subcommands:
//! - `scan` — run http templates against targets, emit findings. With
//!   `--ports`, discover assets first and route POCs by service tag.
//! - `discover` — expand targets, port-scan, fingerprint, emit assets.
//! - `template-check` — report which templates the engine can execute today.

use std::collections::HashSet;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use alive_config::Config;
use alive_core::{Finding, Target};
use alive_discovery::{detect, expand, parse_ports, scan_ports, Service};
use alive_engine::run_http_template;
use alive_fingerprint::tags_for;
use alive_protocols::HttpRunner;
use alive_template::{check_template, load_dir, Template};
use clap::{Parser, Subcommand};
use serde::Serialize;
use tokio::sync::Semaphore;

#[derive(Parser)]
#[command(name = "alive", version, about = "Modular internal security scanner")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run templates against targets.
    Scan(ScanArgs),
    /// Discover live hosts, open ports, and services.
    Discover(DiscoverArgs),
    /// Report template compatibility with the current engine.
    TemplateCheck(TemplateCheckArgs),
}

#[derive(Parser)]
struct ScanArgs {
    /// Target(s): host, host:port, URL, or (with --ports) IP/CIDR/range.
    #[arg(short, long, value_delimiter = ',', required = true)]
    target: Vec<String>,
    /// Directory of nuclei-compatible YAML templates.
    #[arg(long)]
    templates: PathBuf,
    /// Optional ports to discover first (e.g. `80,443,8000-8100`). When set,
    /// Alive port-scans + fingerprints targets and routes POCs by service tag.
    #[arg(short, long)]
    ports: Option<String>,
    /// Optional global config YAML.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Output format.
    #[arg(long, default_value = "text")]
    output: OutputFormat,
}

#[derive(Parser)]
struct DiscoverArgs {
    /// Target(s): IP, host, CIDR (`10.0.0.0/24`), or range (`10.0.0.1-50`).
    #[arg(short, long, value_delimiter = ',', required = true)]
    target: Vec<String>,
    /// Ports to scan, e.g. `80,443,6379,8000-8100`.
    #[arg(short, long)]
    ports: String,
    /// Max concurrent connections.
    #[arg(long, default_value_t = 500)]
    concurrency: usize,
    /// Per-connection timeout, seconds.
    #[arg(long, default_value_t = 3)]
    timeout: u64,
    /// Output format.
    #[arg(long, default_value = "text")]
    output: OutputFormat,
}

#[derive(Parser)]
struct TemplateCheckArgs {
    /// Directory of templates to check.
    #[arg(long)]
    templates: PathBuf,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

/// A discovered asset: a detected service plus its routed nuclei tags.
#[derive(Serialize)]
struct Asset {
    #[serde(flatten)]
    service: Service,
    tags: Vec<String>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Scan(args) => scan(args).await,
        Command::Discover(args) => discover(args).await,
        Command::TemplateCheck(args) => template_check(args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Load only the templates the engine can currently run, warning about the rest.
fn load_runnable(dir: &PathBuf) -> Vec<Template> {
    let mut runnable = Vec::new();
    let (mut skipped, mut failed) = (0usize, 0usize);
    for (path, res) in load_dir(dir) {
        match res {
            Ok(t) => {
                if check_template(&t).runnable {
                    runnable.push(t);
                } else {
                    skipped += 1;
                }
            }
            Err(e) => {
                failed += 1;
                eprintln!("warn: failed to parse {}: {e}", path.display());
            }
        }
    }
    eprintln!(
        "loaded {} runnable template(s); skipped {} unsupported, {} parse failures",
        runnable.len(),
        skipped,
        failed
    );
    runnable
}

/// Normalize a URL/host target string into (Target, base_url) for direct scans.
fn to_target(raw: &str) -> (Target, String) {
    let raw = raw.trim();
    if raw.starts_with("http://") || raw.starts_with("https://") {
        let base = raw.trim_end_matches('/').to_string();
        let host = base
            .split("://")
            .nth(1)
            .unwrap_or(raw)
            .split('/')
            .next()
            .unwrap_or(raw);
        let target = host.parse().unwrap_or_else(|_| Target::new(host, None));
        return (target, base);
    }
    let target: Target = raw.parse().unwrap_or_else(|_| Target::new(raw, None));
    let scheme = match target.port {
        Some(443) | Some(8443) => "https",
        _ => "http",
    };
    let base = match target.port {
        Some(p) => format!("{scheme}://{}:{p}", target.host),
        None => format!("{scheme}://{}", target.host),
    };
    (target, base)
}

/// Resolve a discovery target into concrete IPs: expand IP/CIDR/range specs,
/// otherwise DNS-resolve a hostname.
fn resolve_targets(raw: &str) -> Vec<IpAddr> {
    if let Ok(ips) = expand(raw) {
        return ips;
    }
    let host = host_of(raw);
    match format!("{host}:0").to_socket_addrs() {
        Ok(addrs) => addrs.map(|s| s.ip()).collect(),
        Err(_) => Vec::new(),
    }
}

/// Extract a bare host from a possibly scheme/port-qualified target.
fn host_of(raw: &str) -> &str {
    let no_scheme = raw.split("://").last().unwrap_or(raw);
    let no_path = no_scheme.split('/').next().unwrap_or(no_scheme);
    // Only strip a port when there is a single colon (leave IPv6 literals be).
    if no_path.matches(':').count() == 1 {
        no_path.split(':').next().unwrap_or(no_path)
    } else {
        no_path
    }
}

/// Base URL for an http(s) asset.
fn asset_base_url(service: &Service) -> String {
    let scheme = if service.name == "https" || matches!(service.port, 443 | 8443) {
        "https"
    } else {
        "http"
    };
    format!("{scheme}://{}:{}", service.ip, service.port)
}

/// A template runs against an asset when it is untagged (generic) or shares at
/// least one tag with the asset's fingerprint.
fn template_matches_tags(template: &Template, tags: &HashSet<String>) -> bool {
    template.info.tags.is_empty()
        || tags.is_empty()
        || template.info.tags.iter().any(|t| tags.contains(t))
}

/// Port-scan + fingerprint a set of IPs into assets.
async fn discover_assets(
    ips: &[IpAddr],
    ports: &[u16],
    concurrency: usize,
    timeout: Duration,
) -> Vec<Asset> {
    let open = scan_ports(ips, ports, concurrency, timeout).await;

    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut set = tokio::task::JoinSet::new();
    for (ip, port) in open {
        let sem = sem.clone();
        set.spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            Some(detect(ip, port, timeout).await)
        });
    }

    let mut assets = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(Some(service)) = joined {
            let tags = tags_for(&service.name, service.banner.as_deref());
            assets.push(Asset { service, tags });
        }
    }
    assets.sort_by(|a, b| (a.service.ip, a.service.port).cmp(&(b.service.ip, b.service.port)));
    assets
}

async fn discover(args: DiscoverArgs) -> Result<(), String> {
    let ports = parse_ports(&args.ports).map_err(|e| format!("ports: {e}"))?;
    let mut ips: Vec<IpAddr> = args
        .target
        .iter()
        .flat_map(|t| resolve_targets(t))
        .collect();
    ips.sort_unstable();
    ips.dedup();
    if ips.is_empty() {
        return Err("no resolvable targets".into());
    }
    eprintln!("scanning {} host(s) × {} port(s)", ips.len(), ports.len());

    let assets = discover_assets(
        &ips,
        &ports,
        args.concurrency,
        Duration::from_secs(args.timeout),
    )
    .await;
    emit_assets(&assets, args.output);
    Ok(())
}

async fn scan(args: ScanArgs) -> Result<(), String> {
    let config = match &args.config {
        Some(p) => Config::load(p).map_err(|e| format!("config load: {e}"))?,
        None => Config::default(),
    };

    let templates = Arc::new(load_runnable(&args.templates));
    if templates.is_empty() {
        return Err("no runnable templates".into());
    }

    let runner = Arc::new(
        HttpRunner::new(
            Duration::from_secs(config.scan.timeout_secs),
            config.scan.follow_redirects,
        )
        .map_err(|e| format!("http runner: {e}"))?,
    );

    // Build the (target, base_url, tag-filter) work items. With --ports we
    // discover + fingerprint first and route by tag; otherwise we scan the
    // given URLs/hosts directly with no tag filter (M1 behaviour).
    let mut jobs: Vec<(Target, String, Option<HashSet<String>>)> = Vec::new();
    if let Some(portspec) = &args.ports {
        let ports = parse_ports(portspec).map_err(|e| format!("ports: {e}"))?;
        let mut ips: Vec<IpAddr> = args
            .target
            .iter()
            .flat_map(|t| resolve_targets(t))
            .collect();
        ips.sort_unstable();
        ips.dedup();
        let assets = discover_assets(
            &ips,
            &ports,
            config.scan.concurrency,
            Duration::from_secs(config.scan.timeout_secs),
        )
        .await;
        eprintln!("discovered {} service(s)", assets.len());
        for asset in assets {
            // M1 engine only speaks HTTP; skip non-http services (tcp/dns land in M3).
            if !matches!(asset.service.name.as_str(), "http" | "https") {
                continue;
            }
            let base = asset_base_url(&asset.service);
            let target = Target::new(asset.service.ip.to_string(), Some(asset.service.port));
            jobs.push((target, base, Some(asset.tags.into_iter().collect())));
        }
    } else {
        for raw in &args.target {
            let (target, base) = to_target(raw);
            jobs.push((target, base, None));
        }
    }

    let sem = Arc::new(Semaphore::new(config.scan.concurrency.max(1)));
    let mut set = tokio::task::JoinSet::new();
    for (target, base, tag_filter) in jobs {
        for template in templates.iter() {
            if let Some(tags) = &tag_filter {
                if !template_matches_tags(template, tags) {
                    continue;
                }
            }
            let template = template.clone();
            let runner = runner.clone();
            let sem = sem.clone();
            let target = target.clone();
            let base = base.clone();
            set.spawn(async move {
                let _permit = sem.acquire().await.ok()?;
                run_http_template(&template, &target, &base, runner.as_ref())
                    .await
                    .ok()
                    .flatten()
            });
        }
    }

    let mut findings: Vec<Finding> = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(Some(f)) = joined {
            findings.push(f);
        }
    }

    emit(&findings, args.output);
    Ok(())
}

fn emit(findings: &[Finding], format: OutputFormat) {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(findings).unwrap_or_default()
            );
        }
        OutputFormat::Text => {
            if findings.is_empty() {
                eprintln!("no findings");
            }
            for f in findings {
                println!(
                    "[{}] {} — {} ({})",
                    f.severity, f.template_id, f.target, f.name
                );
            }
        }
    }
}

fn emit_assets(assets: &[Asset], format: OutputFormat) {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(assets).unwrap_or_default()
            );
        }
        OutputFormat::Text => {
            if assets.is_empty() {
                eprintln!("no open services");
            }
            for a in assets {
                let tags = if a.tags.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", a.tags.join(","))
                };
                println!(
                    "{}:{} {}{}",
                    a.service.ip, a.service.port, a.service.name, tags
                );
            }
        }
    }
}

fn template_check(args: TemplateCheckArgs) -> Result<(), String> {
    let (mut runnable, mut not_runnable) = (0usize, 0usize);
    for (path, res) in load_dir(&args.templates) {
        match res {
            Ok(t) => {
                let c = check_template(&t);
                if c.runnable {
                    runnable += 1;
                    println!("OK    {} ({})", t.id, path.display());
                } else {
                    not_runnable += 1;
                    println!("SKIP  {} ({})", t.id, path.display());
                    for r in c.reasons {
                        println!("        - {r}");
                    }
                }
            }
            Err(e) => {
                not_runnable += 1;
                println!("ERROR {}: {e}", path.display());
            }
        }
    }
    println!("\n{runnable} runnable, {not_runnable} not runnable");
    Ok(())
}
