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

use alive_ai::{
    ClaudeProvider, LlmProvider, LocalProvider, ProviderKind, ProviderRouter, RoutingPolicy,
    TriageRequest, TriageVerdict,
};
use alive_brute::{
    load_creds_file, run_brute, wellknown_defaults, BruteConfig, BruteService, FtpService,
    RedisService,
};
use alive_config::{Config, ProviderChoice};
use alive_core::{Finding, Target};
use alive_discovery::{dedup, detect, expand, parse_ports, scan_ports, DedupMode, Service};
use alive_engine::{run_http_template, run_tcp_template, run_tls_template};
use alive_fingerprint::tags_for;
use alive_protocols::{HttpRunner, TcpRunner, TlsRunner};
use alive_report::ReportFormat;
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
    /// Bounded weak-credential checks against an authorized target scope.
    Brute(BruteArgs),
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
    /// Force-enable AI triage of findings for this run (overrides config).
    #[arg(long)]
    ai: bool,
    /// Outbound HTTP requests/second cap (0 = unlimited; overrides config).
    #[arg(long)]
    rate: Option<u32>,
    /// Output format.
    #[arg(long, default_value = "text")]
    output: OutputFormat,
    /// Write the report to this file instead of stdout.
    #[arg(short = 'o', long)]
    output_file: Option<PathBuf>,
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

#[derive(Parser)]
struct BruteArgs {
    /// Target(s): `host` or `host:port`. Repeatable / comma-separated.
    /// Only these targets are probed — brute never discovers its own.
    #[arg(short, long, value_delimiter = ',', required = true)]
    target: Vec<String>,
    /// Service to check.
    #[arg(long)]
    service: BruteServiceKind,
    /// Port override (defaults to the service's well-known port).
    #[arg(short, long)]
    port: Option<u16>,
    /// Credentials file (`user:pass` per line). Required unless --use-default-creds.
    #[arg(long)]
    creds: Option<PathBuf>,
    /// Opt in to the tiny built-in well-known-defaults credential set.
    #[arg(long)]
    use_default_creds: bool,
    /// Max credentials tried per target (0 = all supplied).
    #[arg(long, default_value_t = 50)]
    max_attempts: usize,
    /// Max targets probed concurrently.
    #[arg(long, default_value_t = 8)]
    concurrency: usize,
    /// Delay between attempts against the same target (ms).
    #[arg(long, default_value_t = 200)]
    delay_ms: u64,
    /// Per-connection timeout (seconds).
    #[arg(long, default_value_t = 5)]
    timeout: u64,
    /// Output format.
    #[arg(long, default_value = "text")]
    output: OutputFormat,
    /// Write the report to this file instead of stdout.
    #[arg(short = 'o', long)]
    output_file: Option<PathBuf>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum BruteServiceKind {
    Redis,
    Ftp,
}

impl BruteServiceKind {
    fn default_port(self) -> u16 {
        match self {
            BruteServiceKind::Redis => 6379,
            BruteServiceKind::Ftp => 21,
        }
    }
    fn service(self) -> Box<dyn BruteService> {
        match self {
            BruteServiceKind::Redis => Box::new(RedisService),
            BruteServiceKind::Ftp => Box::new(FtpService),
        }
    }
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Csv,
    Html,
}

impl OutputFormat {
    /// Map to a structured report format; `Text` has no structured equivalent.
    fn as_report(self) -> Option<ReportFormat> {
        match self {
            OutputFormat::Json => Some(ReportFormat::Json),
            OutputFormat::Csv => Some(ReportFormat::Csv),
            OutputFormat::Html => Some(ReportFormat::Html),
            OutputFormat::Text => None,
        }
    }
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
        Command::Brute(args) => brute(args).await,
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
    let raw_ips: Vec<IpAddr> = args
        .target
        .iter()
        .flat_map(|t| resolve_targets(t))
        .collect();
    let (ips, skipped) = dedup(raw_ips, DedupMode::Exact);
    if skipped > 0 {
        eprintln!("deduped {skipped} duplicate target(s)");
    }
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

/// One scan work item: a target plus how to reach it for each protocol.
struct Job {
    target: Target,
    /// http(s) base URL for http templates.
    base_url: String,
    /// `host:port` for tcp/tls templates (when a port is known).
    addr: Option<String>,
    /// Tag filter from fingerprinting; `None` in direct (URL/host) mode.
    tags: Option<HashSet<String>>,
    /// Detected service name; `None` in direct mode.
    service: Option<String>,
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

    let timeout = Duration::from_secs(config.scan.timeout_secs);
    let rate = args.rate.unwrap_or(config.scan.rate_per_sec);
    if rate > 0 {
        eprintln!("rate limiting outbound HTTP to {rate} req/s");
    }
    let http_runner = Arc::new(
        HttpRunner::with_rate(timeout, config.scan.follow_redirects, rate)
            .map_err(|e| format!("http runner: {e}"))?,
    );
    let tcp_runner = Arc::new(TcpRunner::new(timeout));
    let tls_runner = Arc::new(TlsRunner::new(timeout).map_err(|e| format!("tls runner: {e}"))?);

    let jobs = build_jobs(&args, &config).await?;

    let sem = Arc::new(Semaphore::new(config.scan.concurrency.max(1)));
    let mut set = tokio::task::JoinSet::new();
    for job in jobs {
        let job = Arc::new(job);
        for template in templates.iter() {
            if let Some(tags) = &job.tags {
                if !template_matches_tags(template, tags) {
                    continue;
                }
            }
            let template = template.clone();
            let job = job.clone();
            let sem = sem.clone();
            let http_runner = http_runner.clone();
            let tcp_runner = tcp_runner.clone();
            let tls_runner = tls_runner.clone();
            set.spawn(async move {
                let _permit = sem.acquire().await.ok()?;
                dispatch(&template, &job, &http_runner, &tcp_runner, &tls_runner).await
            });
        }
    }

    let mut findings: Vec<Finding> = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(Some(f)) = joined {
            findings.push(f);
        }
    }

    // Rich per-finding triage output is only for interactive text/json to
    // stdout; structured reports (csv/html) and file output go through the
    // report crate on the raw findings (triage annotations there is a TODO).
    let ai_on = config.ai.enabled || args.ai;
    let rich = ai_on
        && !findings.is_empty()
        && matches!(args.output, OutputFormat::Text | OutputFormat::Json)
        && args.output_file.is_none();
    if rich {
        let triaged = run_triage(findings, &config).await;
        emit_triaged(&triaged, args.output);
    } else {
        report_findings(&findings, args.output, args.output_file.as_deref())?;
    }
    Ok(())
}

/// A finding with its optional AI triage verdict attached.
#[derive(Serialize)]
struct TriagedFinding {
    #[serde(flatten)]
    finding: Finding,
    #[serde(skip_serializing_if = "Option::is_none")]
    triage: Option<TriageVerdict>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider: Option<String>,
}

impl TriagedFinding {
    fn untriaged(finding: Finding) -> Self {
        Self {
            finding,
            triage: None,
            provider: None,
        }
    }
}

fn to_kind(c: ProviderChoice) -> ProviderKind {
    match c {
        ProviderChoice::Local => ProviderKind::Local,
        ProviderChoice::Cloud => ProviderKind::Cloud,
    }
}

/// Build the provider router from config. Cloud is only wired when
/// `ANTHROPIC_API_KEY` is present; otherwise the router falls back to local.
fn build_router(config: &Config) -> Result<ProviderRouter, String> {
    let ai = &config.ai;
    let local = Arc::new(
        LocalProvider::new(
            ai.providers.local.base_url.as_str(),
            ai.providers.local.model.as_str(),
        )
        .map_err(|e| e.to_string())?,
    ) as Arc<dyn LlmProvider>;
    let cloud: Option<Arc<dyn LlmProvider>> = if ClaudeProvider::available() {
        Some(Arc::new(
            ClaudeProvider::new(ai.providers.claude.model.as_str()).map_err(|e| e.to_string())?,
        ) as Arc<dyn LlmProvider>)
    } else {
        None
    };
    let policy = RoutingPolicy {
        default_provider: to_kind(ai.default_provider),
        sensitive_data: to_kind(ai.routing.sensitive_data),
        redact_before_cloud: ai.routing.redact_before_cloud,
    };
    Ok(ProviderRouter::new(local, cloud, policy))
}

/// Build a triage request from a finding, using its evidence as the response
/// excerpt (the engine doesn't retain the raw request/response verbatim).
fn triage_request(f: &Finding) -> TriageRequest {
    let response_excerpt = f
        .evidence
        .iter()
        .map(|e| format!("[{}] {}", e.part, e.snippet))
        .collect::<Vec<_>>()
        .join("\n");
    TriageRequest {
        finding: f.clone(),
        request: format!("template `{}` against {}", f.template_id, f.target),
        response_excerpt,
        template_name: f.name.clone(),
        template_tags: Vec::new(),
    }
}

/// Triage findings at/above the configured severity, preserving input order.
/// Findings below the threshold pass through untriaged.
async fn run_triage(findings: Vec<Finding>, config: &Config) -> Vec<TriagedFinding> {
    let router = match build_router(config) {
        Ok(r) => Arc::new(r),
        Err(e) => {
            eprintln!("warn: AI triage disabled ({e}); reporting raw findings");
            return findings
                .into_iter()
                .map(TriagedFinding::untriaged)
                .collect();
        }
    };

    let min = config.ai.min_severity;
    let sem = Arc::new(Semaphore::new(config.scan.concurrency.clamp(1, 8)));
    let mut slots: Vec<Option<TriagedFinding>> = (0..findings.len()).map(|_| None).collect();
    let mut set = tokio::task::JoinSet::new();

    for (idx, finding) in findings.into_iter().enumerate() {
        if finding.severity < min {
            slots[idx] = Some(TriagedFinding::untriaged(finding));
            continue;
        }
        let router = router.clone();
        let sem = sem.clone();
        set.spawn(async move {
            let _permit = sem.acquire().await.ok();
            let req = triage_request(&finding);
            match router.triage(&req).await {
                Ok((verdict, provider)) => (
                    idx,
                    TriagedFinding {
                        finding,
                        triage: Some(verdict),
                        provider: Some(provider),
                    },
                ),
                Err(e) => {
                    eprintln!("warn: triage failed for {}: {e}", finding.template_id);
                    (idx, TriagedFinding::untriaged(finding))
                }
            }
        });
    }

    while let Some(joined) = set.join_next().await {
        if let Ok((idx, tf)) = joined {
            slots[idx] = Some(tf);
        }
    }
    slots.into_iter().flatten().collect()
}

fn emit_triaged(items: &[TriagedFinding], format: OutputFormat) {
    match format {
        // csv/html aren't reached here (the scan path routes them to
        // report_findings), but keep the match exhaustive with a json fallback.
        OutputFormat::Json | OutputFormat::Csv | OutputFormat::Html => {
            println!(
                "{}",
                serde_json::to_string_pretty(items).unwrap_or_default()
            );
        }
        OutputFormat::Text => {
            if items.is_empty() {
                eprintln!("no findings");
            }
            for it in items {
                let f = &it.finding;
                match &it.triage {
                    Some(v) => {
                        let tag = if v.is_true_positive { "TP" } else { "FP?" };
                        println!(
                            "[{}] [{tag} {:.0}%] {} — {} ({}) via {}",
                            f.severity,
                            v.confidence * 100.0,
                            f.template_id,
                            f.target,
                            f.name,
                            it.provider.as_deref().unwrap_or("?"),
                        );
                    }
                    None => println!(
                        "[{}] {} — {} ({})",
                        f.severity, f.template_id, f.target, f.name
                    ),
                }
            }
        }
    }
}

/// Build scan jobs. With `--ports`, discover + fingerprint first and route by
/// tag; otherwise scan the given URLs/hosts directly (no tag filter).
async fn build_jobs(args: &ScanArgs, config: &Config) -> Result<Vec<Job>, String> {
    let mut jobs = Vec::new();
    if let Some(portspec) = &args.ports {
        let ports = parse_ports(portspec).map_err(|e| format!("ports: {e}"))?;
        let raw_ips: Vec<IpAddr> = args
            .target
            .iter()
            .flat_map(|t| resolve_targets(t))
            .collect();
        let (ips, skipped) = dedup(raw_ips, DedupMode::Exact);
        if skipped > 0 {
            eprintln!("deduped {skipped} duplicate target(s)");
        }
        let assets = discover_assets(
            &ips,
            &ports,
            config.scan.concurrency,
            Duration::from_secs(config.scan.timeout_secs),
        )
        .await;
        eprintln!("discovered {} service(s)", assets.len());
        for asset in assets {
            let addr = Some(format!("{}:{}", asset.service.ip, asset.service.port));
            let target = Target::new(asset.service.ip.to_string(), Some(asset.service.port));
            jobs.push(Job {
                target,
                base_url: asset_base_url(&asset.service),
                addr,
                tags: Some(asset.tags.into_iter().collect()),
                service: Some(asset.service.name),
            });
        }
    } else {
        for raw in &args.target {
            let (target, base) = to_target(raw);
            let addr = target_addr(&target, &base);
            jobs.push(Job {
                target,
                base_url: base,
                addr,
                tags: None,
                service: None,
            });
        }
    }
    Ok(jobs)
}

/// Run the template against a job using the runner matching its protocol block.
async fn dispatch(
    template: &Template,
    job: &Job,
    http: &HttpRunner,
    tcp: &TcpRunner,
    tls: &TlsRunner,
) -> Option<Finding> {
    if !template.http.is_empty() {
        // Only run http templates against http-like services (or in direct mode)
        // to avoid firing web POCs at every open port.
        let http_ok = job
            .service
            .as_deref()
            .map(|s| s == "http" || s == "https")
            .unwrap_or(true);
        if !http_ok {
            return None;
        }
        run_http_template(template, &job.target, &job.base_url, http)
            .await
            .ok()
            .flatten()
    } else if !template.tcp.is_empty() {
        let addr = job.addr.as_deref()?;
        run_tcp_template(template, &job.target, addr, tcp)
            .await
            .ok()
            .flatten()
    } else if !template.ssl.is_empty() {
        let addr = job.addr.as_deref()?;
        run_tls_template(template, &job.target, addr, tls)
            .await
            .ok()
            .flatten()
    } else {
        None
    }
}

/// Derive a `host:port` address for tcp/tls templates in direct mode.
fn target_addr(target: &Target, base_url: &str) -> Option<String> {
    if let Some(p) = target.port {
        Some(format!("{}:{}", target.host, p))
    } else if base_url.starts_with("https") {
        Some(format!("{}:443", target.host))
    } else if base_url.starts_with("http") {
        Some(format!("{}:80", target.host))
    } else {
        None
    }
}

/// Emit findings as text (stdout lines) or a structured report (json/csv/html),
/// to `output_file` when given, else stdout.
fn report_findings(
    findings: &[Finding],
    format: OutputFormat,
    output_file: Option<&std::path::Path>,
) -> Result<(), String> {
    // Text has no structured report form: lines to stdout, or a plain dump to file.
    let Some(report_format) = format.as_report() else {
        let mut body = String::new();
        for f in findings {
            body.push_str(&format!(
                "[{}] {} — {} ({})\n",
                f.severity, f.template_id, f.target, f.name
            ));
        }
        match output_file {
            Some(p) => {
                std::fs::write(p, body).map_err(|e| format!("write {}: {e}", p.display()))?
            }
            None => {
                if findings.is_empty() {
                    eprintln!("no findings");
                } else {
                    print!("{body}");
                }
            }
        }
        return Ok(());
    };

    match output_file {
        Some(p) => {
            alive_report::write_report(findings, report_format, p)
                .map_err(|e| format!("write {}: {e}", p.display()))?;
            eprintln!("wrote {} finding(s) to {}", findings.len(), p.display());
        }
        None => {
            let body = alive_report::render(findings, report_format)
                .map_err(|e| format!("render report: {e}"))?;
            println!("{body}");
        }
    }
    Ok(())
}

fn emit_assets(assets: &[Asset], format: OutputFormat) {
    match format {
        // Assets aren't findings; csv/html reports are finding-shaped, so fall
        // back to json for structured discover output.
        OutputFormat::Json | OutputFormat::Csv | OutputFormat::Html => {
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

async fn brute(args: BruteArgs) -> Result<(), String> {
    // Credentials come from an explicit file, or the opt-in well-known set —
    // never a large implicit list. See WORKSPACE_SPEC safety controls.
    let creds = if let Some(path) = &args.creds {
        load_creds_file(path).map_err(|e| format!("creds: {e}"))?
    } else if args.use_default_creds {
        eprintln!("using built-in well-known default credentials (opt-in)");
        wellknown_defaults()
    } else {
        return Err("provide --creds <file> or --use-default-creds".into());
    };
    if creds.is_empty() {
        return Err("no credentials to try".into());
    }

    let port = args.port.unwrap_or(args.service.default_port());
    let targets: Vec<(String, u16)> = args
        .target
        .iter()
        .map(|t| parse_brute_target(t, port))
        .collect();

    let service: Arc<dyn BruteService> = Arc::from(args.service.service());
    let config = BruteConfig {
        max_attempts: args.max_attempts,
        concurrency: args.concurrency,
        delay: Duration::from_millis(args.delay_ms),
        timeout: Duration::from_secs(args.timeout),
    };
    let per_target = if config.max_attempts == 0 {
        creds.len()
    } else {
        config.max_attempts.min(creds.len())
    };
    eprintln!(
        "brute {}: {} target(s) × up to {} cred(s)",
        service.name(),
        targets.len(),
        per_target
    );

    let findings = run_brute(targets, service, Arc::new(creds), config).await;
    report_findings(&findings, args.output, args.output_file.as_deref())
}

/// Parse a brute target `host` or `host:port`, defaulting the port.
fn parse_brute_target(raw: &str, default_port: u16) -> (String, u16) {
    let raw = raw.trim();
    if raw.matches(':').count() == 1 {
        if let Some((h, p)) = raw.split_once(':') {
            if let Ok(port) = p.parse() {
                return (h.to_string(), port);
            }
        }
    }
    (raw.to_string(), default_port)
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
