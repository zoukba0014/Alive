# Workspace Spec

Detail layer for cross-component rules. Read after `map.md` when a task may affect more than one crate, service, module, API, or external boundary.

## Read Order

1. `DEV_LOG.md` Current Handoff
2. `map.md`
3. This file
4. Relevant crate `map.md`
5. Relevant `CRATE_SPEC.md` / `MODULE_SPEC.md`

## Workspace Responsibilities

This repository is the Rust rewrite of the Alive scanner — a modular,
YAML-configurable **internal** security scanner with an AI analysis layer and a
distributed agent fleet. The full plan and milestone breakdown live in
[`ROADMAP.md`](ROADMAP.md).

Owns:
- A deterministic scan engine: discovery, protocol probes (http/tcp/dns/tls),
  fingerprinting, a nuclei-compatible YAML POC engine, and credential checks.
- An AI layer (`ai`) that triages/decides on top of engine output — it never
  sends raw packets itself.
- A distributed fleet: `server` (control plane) + `agent` (endpoint), plus a
  decentralized `mesh` for resilience.

Out of scope (hard boundaries):
- Arbitrary remote shell execution. The server dispatches only a fixed
  `TaskType` catalog (scan / run_poc / collect_inventory). No generic exec.
- Any stealth, anti-forensics, evasion, or persistence-hiding capability. The
  agent is a **visible, managed service** that logs its own activity.
- Scanning outside the configured asset allowlist / owned ranges.

## Safety & Authorization Controls (non-negotiable)

These are the controls that keep this a legitimate internal-ops tool rather
than offensive malware. Any change touching the fleet must preserve them:

- **Scoped commands**: server → agent tasks are an enumerated `TaskType`; the
  agent has no code path to run attacker-supplied shell.
- **Signed tasks**: every task is signed with the server's ed25519 key; agents
  verify before executing (defends even against a compromised peer relay).
- **mTLS identity**: each agent has its own certificate issued at enrollment.
- **Asset authorization**: tasks carry an authorized scope; targets outside it
  are refused.
- **Audit**: every dispatched task + result + actor is recorded immutably.
- **Least privilege + no stealth**: agent runs with minimal privileges as a
  named service and never hides itself.

## High-Risk Couplings

- Cross-crate API contracts and data models — `alive-core` types (`Finding`,
  `Target`, `Severity`) are the shared currency; keep them serialization-stable.
- The nuclei-compatible template schema (`template` crate) — external contract.
- The gRPC `proto` / `TaskType` catalog — shared across `server`/`agent`/`mesh`.
- AI provider routing — the sensitive-data → local-provider rule is a security
  boundary, not just config.
- Serialization, encoding, schema, and configuration formats.
- State, concurrency, persistence (offline buffer), and external boundaries.
- Authentication, authorization, secrets, and deployment assumptions.

## Change Checklist

When a change affects workspace-level behavior:

- [ ] Update `map.md` if navigation or component ownership changed.
- [ ] Update affected `CRATE_SPEC.md` and `MODULE_SPEC.md` files.
- [ ] Update `DEV_LOG.md` with decision, status, tests, and next action.
- [ ] Run relevant tests/checks or record why they were not run.
