//! Alive CLI entry point.
//!
//! M1 subcommands:
//! - `scan`          run http templates against targets, emit findings
//! - `template-check` report which templates the engine can execute today

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use alive_config::Config;
use alive_core::{Finding, Target};
use alive_engine::run_http_template;
use alive_protocols::HttpRunner;
use alive_template::{check_template, load_dir, Template};
use clap::{Parser, Subcommand};
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
    /// Report template compatibility with the current engine.
    TemplateCheck(TemplateCheckArgs),
}

#[derive(Parser)]
struct ScanArgs {
    /// Target(s): host, host:port, or full URL. Repeatable / comma-separated.
    #[arg(short, long, value_delimiter = ',', required = true)]
    target: Vec<String>,
    /// Directory of nuclei-compatible YAML templates.
    #[arg(long)]
    templates: PathBuf,
    /// Optional global config YAML.
    #[arg(long)]
    config: Option<PathBuf>,
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

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Scan(args) => scan(args).await,
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

/// Normalize a target string into (Target, base_url).
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

    let sem = Arc::new(Semaphore::new(config.scan.concurrency.max(1)));
    let mut set = tokio::task::JoinSet::new();

    for raw in &args.target {
        let (target, base) = to_target(raw);
        for template in templates.iter() {
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
