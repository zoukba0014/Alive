# Workspace Map

Navigation layer for this repository. Read this first, then route to the smallest relevant detail docs.

## Task Router

| Task Type | Read First | Then Read | Notes |
|---|---|---|---|
| New task / resumed task | `DEV_LOG.md` | `git log --oneline -5`, this file | Recover handoff before planning |
| Cross-component change | `WORKSPACE_SPEC.md` | affected crate/module specs | Check shared contracts and invariants |
| Crate-level change | target crate `map.md` | target `CRATE_SPEC.md` | Confirm boundaries and entry points |
| Module logic change | target crate `map.md` | target `MODULE_SPEC.md` | Keep scope narrow |
| Debugging | `DEV_LOG.md` + relevant map | source files + relevant spec | Record failed attempts in `DEV_LOG.md` |
| Documentation update | this file | affected `*_SPEC.md` | Keep navigation and detail docs consistent |

## Components

| Component | Path | Purpose | Docs |
|---|---|---|---|
| `alive` | `bin/alive` | TODO | `bin/alive/map.md` |
| `alive-ai` | `crates/ai` | TODO | `crates/ai/map.md` |
| `alive-brute` | `crates/brute` | TODO | `crates/brute/map.md` |
| `alive-config` | `crates/config` | TODO | `crates/config/map.md` |
| `alive-core` | `crates/core` | TODO | `crates/core/map.md` |
| `alive-discovery` | `crates/discovery` | TODO | `crates/discovery/map.md` |
| `alive-dsl` | `crates/dsl` | TODO | `crates/dsl/map.md` |
| `alive-engine` | `crates/engine` | TODO | `crates/engine/map.md` |
| `alive-fingerprint` | `crates/fingerprint` | TODO | `crates/fingerprint/map.md` |
| `alive-oob` | `crates/oob` | TODO | `crates/oob/map.md` |
| `alive-protocols` | `crates/protocols` | TODO | `crates/protocols/map.md` |
| `alive-report` | `crates/report` | TODO | `crates/report/map.md` |
| `alive-template` | `crates/template` | TODO | `crates/template/map.md` |

## Detail Layer

- `DEV_LOG.md` — current handoff and recent session summaries.
- `GIT_FLOW.md` — branch, commit, PR, and cleanup rules.
- `WORKSPACE_SPEC.md` — cross-component invariants.
- `<crate>/map.md` — crate navigation.
- `<crate>/CRATE_SPEC.md` — crate responsibilities and boundaries.
- `<crate>/src/MODULE_SPEC.md` and `<crate>/src/<module>/MODULE_SPEC.md` — module details.

## Maintenance

- Keep this file navigational; do not add implementation details here.
- Update component rows when packages/modules are added, moved, or removed.
- Refresh generated navigation only when you are ready to review map customizations.
