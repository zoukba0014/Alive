# DEV_LOG

Purpose: curated handoff state for agents and developers. This is not a raw transcript. Keep it short, factual, and useful after context loss.

## Current Handoff

- Branch: `feature/rust-rewrite`
- Goal: Rust rewrite of Alive per `ROADMAP.md`, milestone by milestone.
- Current status: **M2 (discovery + fingerprint) complete.** `alive discover` + tag-routed `alive scan --ports` work; fingerprint-first routing in place.
- Next action: **Start M3 — multi-protocol + DSL** (`protocols` tcp/dns/tls runners; `dsl` expression engine for `dsl:` matchers/extractors; payload attack modes). See `ROADMAP.md`.
- Blockers: none.
- Relevant files: `crates/{discovery,fingerprint}/src/*`, `bin/alive/src/main.rs`.
- Relevant docs: `ROADMAP.md` (plan), `map.md`, `WORKSPACE_SPEC.md`, `GIT_FLOW.md`.
- Last test command: `cargo test -q && cargo clippy --workspace`
- Last test result: 28 tests passed (core 6, discovery 11, engine 2, fingerprint 7, template 2); clippy clean; fmt clean.
- Docs sync: crate maps/specs scaffolded for discovery + fingerprint; root map refreshed.

## Recent Sessions

### 2026-07-06 — M2 Discovery + fingerprint

#### Summary
- Added asset discovery + fingerprint-first tag routing.

#### Changed
- `alive-discovery`: `expand` (IP/CIDR/range), `parse_ports` (`80,443,8000-9000`),
  `scan_ports` (async connect, Semaphore+JoinSet), `ping` (surge-ping ICMP, best-effort),
  `service::detect` (well-known-port table + best-effort banner grab).
- `alive-fingerprint`: `favicon_hash` (Shodan mmh3: python-style base64 encodebytes + murmur3),
  `tags_for(service, banner)` → nuclei tags.
- `bin/alive`: new `discover` subcommand; `scan --ports` discovers+fingerprints then routes
  POCs by tag (`template_matches_tags`: untagged/generic templates always run).

#### Decisions
- Connect-scan liveness is the privilege-free default; ICMP is optional and degrades to it.
- `scan` skips non-HTTP services for now (engine speaks only HTTP until M3).
- `expand` rejects hostnames on purpose; CLI DNS-resolves them in `resolve_targets`.

#### Failed Attempts
- None.

#### Next Steps
- M3: tcp/dns/tls runners + `dsl` expression engine + payload attack modes.

### 2026-07-06 — M1 Scan engine foundation

#### Summary
- Built the deterministic HTTP scan pipeline end-to-end.

#### Changed
- `alive-config`: global YAML config (`scan.concurrency/timeout/redirects`).
- `alive-template`: nuclei-compatible model (info/http/matchers/extractors), YAML loader,
  and `check_template` compatibility reporter (unknown types → `Unsupported`, reported not fatal).
- `alive-engine`: transport-agnostic `HttpClient` trait + `HttpResponse`; matcher eval
  (status/word/regex/size, and/or, negative, part body/header/all) + regex extractor;
  `run_http_template` (stop-at-first-match).
- `alive-protocols`: reqwest `HttpRunner` (rustls, accepts invalid certs like nuclei).
- `bin/alive`: clap CLI `scan` (concurrency via Semaphore+JoinSet, text/json output) and
  `template-check`. Added `pocs/http-title-example.yaml`.

#### Decisions
- Unknown matcher/extractor/protocol → captured, not fatal; `template-check` surfaces them.
- HTTP runner accepts invalid certs by default (internal self-signed hosts are normal).

#### Failed Attempts
- None.

#### Next Steps
- M2: `discovery` (icmp/portscan) + `fingerprint` (tag routing).

### 2026-07-06 — M0 Bootstrap

#### Summary
- Initialized the Rust rewrite: Cargo workspace + `alive-core` crate + doc workflow + `ROADMAP.md`.

#### Changed
- Added `Cargo.toml` (workspace), `crates/core` with `Target`/`Finding`/`Severity`/`Protocol`/`Error`.
- Added `.gitignore`; gitignored the old Go `alive` binary and `Alive_release/`.
- Scaffolded doc workflow (map/specs/git-flow/dev-log); wrote `ROADMAP.md` + filled `WORKSPACE_SPEC.md`.

#### Decisions
- Locked design decisions recorded in `ROADMAP.md` (nuclei-compatible YAML, all-in-one,
  fingerprint-first, switchable AI provider, gRPC stream push, decentralized peer-elected mesh,
  scoped-command safety model). Full picture in `WORKSPACE_SPEC.md`.
- Old Go sources left in place for now; superseded by the rewrite, cleaned up later.

#### Failed Attempts
- None.

#### Next Steps
- M1: scan engine foundation. Start with `config` + `template` (nuclei YAML model).

## Log Hygiene

- Keep `Current Handoff` current and concise.
- Add one `Recent Sessions` entry per meaningful task/session.
- Record failed attempts only when they prevent repeated mistakes.
- Move old entries to `devlogs/YYYY-MM.md` if this file becomes too long.
