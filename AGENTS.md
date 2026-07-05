<!-- agent-doc-workflow:start -->
## Agent Bootstrap Workflow

- Start each task by applying `agent-doc-workflow`.
- Read `DEV_LOG.md` Current Handoff, then check `git status --short` and `git log --oneline -5`.
- Follow `GIT_FLOW.md`; do not develop directly on `main` unless explicitly approved.
- Read `map.md` before changing code, then open only the relevant `*_SPEC.md` files.
- Plan before edits unless the user explicitly asks for direct changes.
- Update `DEV_LOG.md` and relevant docs when behavior, boundaries, APIs, flows, or module responsibilities change.
<!-- agent-doc-workflow:end -->
