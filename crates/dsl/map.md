# alive-dsl Map

Navigation layer for crate/package `alive-dsl` at `crates/dsl`.

## Task Router

| Task Type | Read First | Then Read |
|---|---|---|
| Crate API or boundary change | `CRATE_SPEC.md` | affected module specs |
| Module implementation change | this map | target `MODULE_SPEC.md` |
| Debugging | relevant source files | relevant `MODULE_SPEC.md` + repository `DEV_LOG.md` |
| Docs update | this map | affected specs |

## Module Entry Points

| Module | Path | Docs | Purpose |
|---|---|---|---|
| crate root | `src` | `src/MODULE_SPEC.md` | TODO |

## Maintenance

- Keep this file navigational.
- Add or refresh module rows when first-level `src/` modules change.
