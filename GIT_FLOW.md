# Git Flow

This repository follows a simplified Git Flow for all agent and human coding tasks.

## Required Rules

- Do not develop directly on `main` unless explicitly approved for an emergency/direct edit.
- Start code work from an appropriate branch:
  - `feature/<name>` for new features
  - `fix/<name>` for bug fixes
  - `docs/<name>` for documentation-only work
  - `refactor/<name>` for refactors
  - `hotfix/<name>` for urgent production fixes
- Keep commits scoped and reviewable.
- Use conventional commit messages.
- Keep the working tree understandable for the next developer/agent.

## Start of Work

```bash
git checkout main
git pull origin main
git checkout -b feature/<short-description>
```

If the task starts on an existing branch, inspect state first:

```bash
git branch --show-current
git status --short
git log --oneline -5
```

## During Work

- Make incremental, focused changes.
- Run relevant tests/checks before closeout.
- Update `DEV_LOG.md` with current status, decisions, failed attempts, test results, and next steps.
- Update `map.md` / `*_SPEC.md` when behavior, boundaries, flows, APIs, invariants, or module responsibilities change.

## Commit Messages

Use conventional commits:

```text
feat: add new behavior
fix: correct broken behavior
docs: update documentation
refactor: restructure without behavior change
test: add or fix tests
chore: maintenance
```

## Before Push / PR

```bash
git status --short
git diff --check
# run project-specific tests/checks
git push -u origin <branch>
```

PR summary should include:
- What changed
- How it was tested
- Docs sync status
- DEV_LOG handoff status

## Cleanup After Merge

```bash
git checkout main
git pull origin main
git branch -d <branch>
git push origin --delete <branch>
```

## Exceptions

If the user explicitly requests direct edits on `main`, proceed only after noting the exception in the task summary and `DEV_LOG.md`.
