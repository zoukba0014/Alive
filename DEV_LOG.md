# DEV_LOG

Purpose: curated handoff state for agents and developers. This is not a raw transcript. Keep it short, factual, and useful after context loss.

## Current Handoff

- Branch: `feature/rust-rewrite`
- Goal: Rust rewrite of Alive per `ROADMAP.md`, milestone by milestone.
- Current status: **M7 (decentralized resilience) complete.** `alive-mesh` (custom SWIM-style detector + lowest-live-id leader election) + `alive-buffer` (redb FIFO) + agent offline re-run/buffer/flush-on-reconnect. Resilience + offline safety tests green.
- Next action: **Start M8 — hardening & performance** (template clustering / request dedup; bloom-filter target dedup; rate limiting/backpressure; audit hardening; benchmarks). Final milestone → usable version. See `ROADMAP.md`.
- Blockers: none.
- Relevant files: `crates/{mesh,buffer}/src/*`, `bin/alive-agent/src/run.rs`.
- Relevant docs: `ROADMAP.md` (plan), `map.md`, `WORKSPACE_SPEC.md`, `GIT_FLOW.md`.
- Last test command: `cargo test -q && cargo clippy --workspace`
- Last test result: 85 tests passed; clippy 0 issues; fmt clean.
- Docs sync: mesh/buffer maps/specs scaffolded; root map refreshed.
- Deferred (still open): DNS runner + payload modes (M3); SSH brute (M5); interactsh crypto (M5); csv/html triage annotations (M4); M6 simplifications (full-keypair enroll, interval scheduler, plaintext-localhost e2e); M7: full peer→leader result forwarding deferred (per-agent flush shipped; leader designated via `is_leader()`); memberlist crate not used (custom SWIM behind a drop-in seam).

## Recent Sessions

### 2026-07-06 — M7 Decentralized resilience

#### Summary
- Agents survive server outages: gossip health, keep running cached tasks, buffer + flush on recovery.

#### Changed
- `alive-mesh` (new): custom SWIM-style failure detector (time-injected `MembershipState` +
  `GossipMembership` UDP wrapper); **leader = lowest live NodeId**, re-elects on membership change.
- `alive-buffer` (new): redb-backed durable FIFO (`enqueue`/`drain`/`len`), survives restart.
- `bin/alive-agent`: reconnect w/ capped backoff; flush-on-reconnect; offline path re-runs cached
  signed tasks (stored as prost bytes, sig+scope preserved) and buffers results; mesh join via `--mesh-bind`.
  New flags: `--buffer-path`, `--mesh-bind`, `--mesh-seed`, `--max-backoff-secs`.

#### Decisions
- Custom SWIM (not `memberlist`) to keep the workspace green + fully unit-testable; drop-in seam kept.
- Offline safety preserved: cached tasks re-verified (sig + scope) before every re-run (tested);
  flushed results reach the server as normal `Result`s (audit-logged).
- Full peer→leader result forwarding deferred; per-agent flush shipped, leader designated for relay.

#### Failed Attempts
- None.

#### Next Steps
- M8: template clustering/dedup, bloom target dedup, rate limiting, benchmarks → usable version.

### 2026-07-06 — M6 Fleet foundation

#### Summary
- Built the distributed control plane: server + agent over a long-lived gRPC bidi stream.

#### Changed
- `alive-proto` (new): tonic/prost gRPC (`Fleet { Enroll, Stream }`), vendored protoc via build.rs.
  `Task.body` is a closed oneof `ScanTask|DiscoverTask|CollectInventoryTask` — the safety boundary;
  no free-form command/shell field exists. Task carries task_id, authorized_scope, issued_at, ed25519 signature.
- `alive-transport` (new): mTLS builders (rustls), `rcgen` CA + leaf issuance, ed25519 `sign`/`verify`
  over canonical task bytes, `scope` CIDR/host allowlist check.
- `alive-server` (new bin): gRPC service, agent registry, interval scheduler, result ingest (→alive-report),
  append-only JSONL audit log.
- `alive-agent` (new bin): enroll → mTLS stream → verify+scope-check+execute (reusing scanner engine) → stream results.

#### Decisions
- Server signs every task; agent refuses bad-sig or out-of-scope BEFORE executing (both tested).
- Fixed TaskType catalog enforced at the schema level (no arbitrary shell — matches WORKSPACE_SPEC).
- Simplifications (documented): full-keypair enrollment (no CSR parse), interval scheduler (not cron),
  e2e test on plaintext localhost (mTLS covered by transport unit tests + real binaries).

#### Failed Attempts
- Renamed the bidi RPC `Connect`→`Stream` (collided with tonic's generated client constructor).

#### Next Steps
- M7: `mesh` (SWIM + leader election) + offline buffer + flush-on-reconnect.

### 2026-07-06 — M5 Brute + report + OOB

#### Summary
- Completed the standalone scanner: credential checks, multi-format reports, OOB client.

#### Changed
- `alive-report` (new): json/csv/html emitters; self-contained HTML (severity summary + table).
- `alive-brute` (new): `BruteService` trait + Redis/FTP (pure tokio, no C deps); allowlisted
  `CredentialSource`; bounded `run_brute` (max-attempts + concurrency + delay, stop-on-first-success).
- `alive-oob` (new): `OobClient` trait + `HttpOobClient` (correlation-id payloads + HTTP poll).
- `bin/alive`: `brute` subcommand; `--output csv|html` + `-o/--output-file` on scan/brute.

#### Decisions
- Safety: no built-in wordlist; creds only from `--creds` file or opt-in `--use-default-creds`;
  brute never discovers targets; conservative bounded defaults (50 attempts / 8 conc / 200ms).
- SSH brute deferred (russh C-dep/compile risk); interactsh RSA crypto deferred (HTTP-poll shipped) —
  both drop-in behind their traits.

#### Failed Attempts
- None.

#### Next Steps
- M6: fleet foundation — `proto` + `transport` (mTLS/signing) + `alive-server` + `alive-agent` (gRPC stream).

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
