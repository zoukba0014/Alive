# Alive

A modular, YAML-configurable **internal security scanner** with an AI analysis
layer and a distributed agent fleet — a Rust rewrite of the original Go tool.

> **Authorized internal use only.** Alive is built for maintaining your own
> company's security posture: scheduled scanning, targeted verification, and
> asset discovery on infrastructure you own or are authorized to test. It is
> deliberately **not** a covert C2 — see [Safety model](#safety-model).

## What it does

- **Asset discovery** — ICMP/connect host liveness, async TCP port scanning,
  service detection, and fingerprint-first routing (favicon mmh3 + banners →
  nuclei tags) so POCs only run against matching services.
- **nuclei-compatible POC engine** — loads nuclei-style YAML templates and runs
  them over HTTP / TCP / TLS with `status`/`word`/`regex`/`size`/`dsl` matchers,
  regex/dsl extractors, and a built-in DSL expression engine (~18 functions).
- **AI triage** — an optional LLM layer that judges each finding's exploitability,
  re-scores severity, and suggests remediation. **Provider-switchable**: sensitive
  findings stay on a **local** model (Ollama/vLLM); complex reasoning can go to
  **Claude**, with internal identifiers redacted before egress.
- **Credential checks** — bounded, allowlist-only weak-credential probing (Redis, FTP).
- **Reports** — JSON, CSV, and self-contained HTML.
- **Distributed fleet** — a control-plane **server** dispatches signed, scoped
  tasks over a long-lived gRPC stream to enrolled **agents** (mTLS). Agents
  survive server outages: they gossip health (SWIM), elect a leader, keep running
  cached tasks offline, and flush buffered results on reconnect.

## Architecture

```
Distributed fleet:  alive-server (control plane) ──gRPC bidi stream (mTLS)── alive-agent ×N ──SWIM gossip mesh──
AI layer:           triage · provider router (sensitive→local, redact→cloud)
Deterministic core: discovery · protocols(http/tcp/tls) · fingerprint · engine(nuclei) · brute
POC library:        nuclei-compatible YAML templates (./pocs)
```

Cargo workspace layout:

| Crate | Responsibility |
|---|---|
| `alive-core` | Shared types: `Target`, `Finding`, `Severity`, `Protocol`, `Error` |
| `alive-config` | Global YAML config (`scan`, `ai` sections) |
| `alive-template` | nuclei-compatible template model + loader + `template-check` |
| `alive-dsl` | nuclei DSL expression engine (evalexpr + helper functions) |
| `alive-engine` | Matcher/extractor evaluation, per-protocol execution, template clustering |
| `alive-protocols` | HTTP (reqwest) / TCP / TLS runners + rate limiting |
| `alive-discovery` | Target expansion, port scan, service detection, dedup |
| `alive-fingerprint` | Service→tag routing, Shodan-style favicon hash |
| `alive-ai` | `LlmProvider` trait, Claude + local providers, routing + redaction, triage |
| `alive-brute` | Bounded, allowlisted credential checks |
| `alive-report` | JSON / CSV / HTML report emitters |
| `alive-oob` | Out-of-band (OOB) interaction client |
| `alive-proto` | gRPC service + fixed `TaskType` catalog (tonic/prost) |
| `alive-transport` | mTLS, CA enrollment, ed25519 task signing, scope checks |
| `alive-mesh` | SWIM-style membership + peer leader election |
| `alive-buffer` | redb-backed durable offline result queue |
| `alive` / `alive-server` / `alive-agent` | CLI, control plane, endpoint agent |

## Build

```sh
cargo build --release        # binaries in ./target/release/{alive,alive-server,alive-agent}
cargo test                   # 95 unit/integration tests
```

## CLI usage (`alive`)

```sh
# Check which templates the engine can run
alive template-check --templates ./pocs

# Scan explicit URLs/hosts with a template dir
alive scan -t http://10.0.0.5 --templates ./pocs --output json

# Discovery-first: scan a range, fingerprint, run only tag-matched POCs
alive scan -t 10.0.0.0/24 -p 80,443,6379,8000-8100 --templates ./pocs \
  --rate 200 -o report.html --output html

# Asset discovery only
alive discover -t 10.0.0.0/24 -p 80,443,6379 --output json

# Weak-credential check (allowlisted creds only)
alive brute -t 10.0.0.5 --service redis --creds ./creds.txt --max-attempts 50

# Enable AI triage for a run (config controls provider/routing)
alive scan -t 10.0.0.0/24 -p 443 --templates ./pocs --ai
```

Configuration lives in `configs/alive.example.yaml` (scan tuning + the `ai`
section: providers, model tiers, and the sensitive→local routing policy). AI is
off by default; the cloud provider reads `ANTHROPIC_API_KEY` from the environment.

## Fleet usage

```sh
# Control plane: schedules + dispatches signed, scoped tasks; audit-logs everything
alive-server --schedule-secs 3600
alive-server --verify-audit            # verify the tamper-evident audit hash-chain

# Endpoint agent: enrolls, connects over mTLS, executes verified tasks, gossips + buffers
alive-agent --server https://server:8443 --mesh-bind 0.0.0.0:7946 \
  --mesh-seed peer1:7946 --buffer-path /var/lib/alive/buffer.redb
```

## Safety model

These controls are what make Alive a legitimate internal-ops tool rather than
offensive malware, and are enforced in code (see `WORKSPACE_SPEC.md`):

- **Fixed command catalog** — the server can only dispatch enumerated task types
  (`scan` / `discover` / `collect_inventory`). There is no arbitrary-shell path.
- **Signed tasks** — every task is ed25519-signed by the server; agents verify
  the signature (and that targets ⊆ authorized scope) **before** executing —
  including cached tasks re-run while offline.
- **mTLS identity** — each agent holds a CA-issued certificate from enrollment.
- **Asset authorization** — tasks carry an authorized scope; out-of-scope targets
  are refused.
- **Audit** — every dispatch and result is written to a tamper-evident
  (hash-chained) JSONL audit log.
- **Least privilege, no stealth** — the agent is a visible, logged service; it
  performs no evasion, persistence-hiding, or anti-forensics.
- **Bounded credential checks** — no built-in wordlists; credentials come only
  from an explicit file or an opt-in default set, with attempt/concurrency/rate caps.

## Project docs

- `ROADMAP.md` — the milestone plan (M0–M8) and locked design decisions.
- `WORKSPACE_SPEC.md` — cross-crate contracts + the safety controls above.
- `DEV_LOG.md` — current state and per-milestone handoff notes.
- `map.md` + per-crate `map.md`/`CRATE_SPEC.md` — navigation and detail docs.

## Status

All milestones **M0–M8 complete**. Known non-blocking follow-ups are tracked in
`DEV_LOG.md` (e.g. DNS runner, SSH brute service, full interactsh crypto, wiring
the scan loop through the template-clustering primitive).
