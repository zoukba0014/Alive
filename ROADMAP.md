# Alive — Rewrite Roadmap

Rust rewrite of the Alive scanner: a **modular, YAML-configurable internal
security scanner** with an AI analysis layer and a distributed agent fleet for
scheduled, authorized internal security operations.

> Authorization scope: this system is built for **authorized internal security
> maintenance only**. See [`WORKSPACE_SPEC.md`](WORKSPACE_SPEC.md) for the
> non-negotiable safety controls (scoped command catalog, signed tasks, mTLS
> identity, asset allowlist, audit logging, no stealth/evasion).

## Locked Design Decisions

| Area | Decision |
|---|---|
| POC/EXP format | **nuclei-compatible YAML** (reuse the community template ecosystem) |
| Scanner scope | **All-in-one** (discovery + port scan + fingerprint + brute + POC), fscan-style |
| Fingerprint | **Fingerprint-first**: identify service → only run POCs whose tags match |
| AI usage | LLM as analysis/decision layer on top of a deterministic engine |
| AI provider | **Switchable provider** (local Ollama/vLLM + cloud Claude), sensitive data → local |
| AI first capability | **Triage** (false-positive filtering, severity, remediation) |
| Fleet comms | **Long-lived gRPC bidirectional stream**, server pushes tasks |
| Fleet resilience | **Fully decentralized** SWIM gossip mesh with **peer leader election** |
| Command model | Server dispatches only a **fixed TaskType catalog**, never arbitrary shell |

## Architecture Layers

```
Distributed fleet:  server (control plane) ── gRPC stream ── agents ── SWIM gossip mesh
AI layer:           triage · decision routing · POC generation (provider-switchable)
Deterministic core: discovery · protocols(http/tcp/dns/tls) · fingerprint · engine · brute
POC library:        nuclei-compatible YAML templates
```

## Milestones

Each milestone is a shippable increment. Rule: **every step ends with a
passing `cargo build` + `cargo test`, then commit + push.**

### M0 — Bootstrap ✅
- Cargo workspace, `alive-core` (Target/Finding/Severity/Protocol/Error), doc workflow, this roadmap.
- **Done when:** `cargo test` passes; docs scaffolded; pushed.

### M1 — Scan engine foundation
- Crates: `config`, `template` (nuclei YAML parse + `template-check`), `engine` (status/word/regex matchers, regex extractor), `protocols/http`, `bin/alive` CLI.
- **Done when:** `alive scan -t <host> -p 80,443 --templates ./pocs/` reads YAML, runs HTTP POCs, emits JSON findings.

### M2 — Discovery + fingerprint
- Crates: `discovery` (ICMP alive, async connect port scan, service detect), `fingerprint` (banner + favicon mmh3 → tag routing).
- **Done when:** a scan discovers live hosts/ports, fingerprints services, and only runs tag-matched POCs.

### M3 — Multi-protocol + DSL
- `protocols` tcp/dns/tls runners; `dsl` expression engine (matcher `dsl:` + extractor `dsl:`); payload attack modes (batteringram/pitchfork/clusterbomb).
- **Done when:** representative tcp/dns/ssl community templates run; DSL function coverage measured by `template-check`.

### M4 — AI analysis layer (triage)
- Crate: `ai` — `LlmProvider` trait, local + Claude providers, router (sensitive→local, redact-before-cloud), `triage()` with enforced JSON schema; wire into `report`.
- **Done when:** findings above a severity threshold get an AI verdict (is_true_positive/confidence/severity/reasoning/evidence_refs/remediation).

### M5 — Brute + report + OOB
- `brute` (SSH/MySQL/Redis/... via allowlisted creds), `report` (json/csv/html), `oob` (interactsh client).
- **Done when:** weak-credential checks, OOB-based POCs, and an HTML report all work.

### M6 — Fleet foundation
- Crates: `proto` (gRPC + fixed `TaskType` catalog), `transport` (mTLS, enrollment, ed25519 task signing), `bin/alive-server` (scheduler/dispatch/ingest/audit), `bin/alive-agent` (enroll → long-lived stream → execute → local buffer).
- **Done when:** server schedules a scan task, pushes it over a bidi stream to an enrolled agent, agent verifies signature + mTLS, runs it, streams findings back; every dispatch is audit-logged.

### M7 — Decentralized resilience
- Crate: `mesh` (memberlist SWIM membership + peer failure detection + **leader election**), offline persistent buffer (redb/sled) with flush-on-reconnect, leader aggregates & relays reports when the server is unreachable.
- **Done when:** killing the server does not stop scheduled work — agents keep running cached tasks, gossip health, elect a leader that aggregates results, and flush to the server on recovery.

### M8 — Hardening & performance
- Template clustering (dedupe identical requests), bloom-filter target dedup, rate limiting/backpressure, audit hardening, benchmarks.
- **Done when:** large-range scans are fast and bounded; audit trail is complete.

## Status

- Current: **M0 complete.** Next: **M1**.
- Live handoff detail lives in [`DEV_LOG.md`](DEV_LOG.md).
