# DEV_LOG

Purpose: curated handoff state for agents and developers. This is not a raw transcript. Keep it short, factual, and useful after context loss.

## Current Handoff

- Branch: `feature/rust-rewrite`
- Goal: Rust rewrite of Alive per `ROADMAP.md`, milestone by milestone.
- Current status: **M4 (AI triage layer) complete.** `alive-ai` provider-switchable triage (local + Claude), sensitive→local routing + redaction, wired into `scan --ai`.
- Next action: **Start M5 — brute + report + OOB** (`brute`: SSH/MySQL/Redis/... allowlisted creds; `report`: json/csv/html; `oob`: interactsh). See `ROADMAP.md`.
- Blockers: none.
- Relevant files: `crates/ai/src/*`, `crates/config/src/lib.rs`, `bin/alive/src/main.rs`, `configs/alive.example.yaml`.
- Relevant docs: `ROADMAP.md` (plan), `map.md`, `WORKSPACE_SPEC.md`, `GIT_FLOW.md`.
- Last test command: `cargo test -q && cargo clippy --workspace`
- Last test result: 52 tests passed; clippy 0 issues; fmt clean.
- Docs sync: ai crate maps/specs scaffolded; root map refreshed.
- Deferred (still open): DNS runner + HTTP payload attack modes (from M3). Live LLM triage not exercised in tests (needs network/keys) — plumbing covered by FakeProvider.

## Recent Sessions

### 2026-07-06 — M4 AI triage layer

#### Summary
- Added a provider-switchable LLM triage layer on top of the deterministic engine.

#### Changed
- `alive-ai` (new): `LlmProvider` trait, `TriageRequest`/`TriageVerdict`; `ClaudeProvider`
  (reqwest → `/v1/messages`, structured output forced via a `record_triage` tool + tool_choice;
  no sampling params; key from `ANTHROPIC_API_KEY`); `LocalProvider` (OpenAI-compatible
  `/chat/completions`, `response_format: json_object`); `ProviderRouter` (sensitive→local security
  boundary, redact-before-cloud); `redact.rs` (RFC1918/loopback IPs + `.internal`/`.local` hosts).
- `alive-config`: `ai` section (disabled by default, `min_severity=medium`, provider/routing
  sub-structs), all `#[serde(default)]`; added `alive-core` dep for `Severity`; local `ProviderChoice`.
- `bin/alive`: `scan --ai` triages findings ≥ min_severity (bounded concurrency); false positives
  annotated `[FP?]`, never dropped; JSON adds `triage`/`provider`.
- `configs/alive.example.yaml`: sample config with commented model-tier options.

#### Decisions
- Structured output guaranteed via forced `record_triage` tool (not free-form JSON) → schema-valid.
- Default cloud model `claude-opus-4-8` (per API guidance); tiers documented for the user to pick.
- Enabled reqwest `json` feature on the workspace dep (additive).

#### Failed Attempts
- None.

#### Next Steps
- M5: `brute` + `report` (html) + `oob` (interactsh).

### 2026-07-06 — M3 Multi-protocol + DSL

#### Summary
- Added tcp/tls protocol execution and a nuclei-style DSL expression engine.

#### Changed
- `alive-dsl` (new): `eval_bool`/`eval_string` on `evalexpr` 11 (pinned; v12 API churn),
  VarMap from responses, ~18 DSL functions (len/contains/md5/sha*/base64/hex/url*/regex/...).
- `alive-template`: added `Matcher::Dsl`/`Extractor::Dsl`; typed `tcp`/`dns`/`ssl` blocks; `Part::Data`.
- `alive-engine`: protocol-agnostic `MatchInput` (one matcher path for http/tcp/tls + dsl);
  `run_tcp_template`, `run_tls_template`; `TcpClient`/`TlsClient` traits.
- `alive-protocols`: `TcpRunner` (escape decoding), `TlsRunner` (rustls handshake + x509 leaf extraction).
- `bin/alive`: `scan` dispatches per protocol block via a `Job` model; http gated to http-like services.

#### Decisions
- evalexpr pinned to 11 (12 introduced `NumericTypes` generics that churn the Value/Function API).
- DNS + HTTP payload attack modes deferred to keep the milestone green; both flagged in handoff.

#### Failed Attempts
- None (evalexpr 12 generics avoided by pinning to 11).

#### Next Steps
- M4: `ai` crate — provider-switchable LLM triage on findings.

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
