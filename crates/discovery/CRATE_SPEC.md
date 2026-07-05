# alive-discovery Crate Spec

Detail layer for crate/package `alive-discovery` at `crates/discovery`.

## Read Order

1. Repository `DEV_LOG.md`
2. Repository `map.md`
3. Crate `map.md`
4. This file
5. Target `MODULE_SPEC.md`

## Responsibility

- TODO: describe what this crate owns.
- TODO: describe what this crate must not own.

## Entry Points

- `src/lib.rs` if this is a library crate.
- `src/main.rs` if this is a binary crate.
- TODO: list public APIs, commands, handlers, or integration points.

## Dependencies and Boundaries

- TODO: important internal dependencies.
- TODO: important external dependencies.
- TODO: data/config/error contracts shared with other crates.

## Module List

- `src/MODULE_SPEC.md`
- `src/<module>/MODULE_SPEC.md`

## Change Checklist

- [ ] Update affected module specs.
- [ ] Update workspace spec if cross-crate contracts changed.
- [ ] Update maps if navigation changed.
- [ ] Update `DEV_LOG.md` with status, tests, and next action.
