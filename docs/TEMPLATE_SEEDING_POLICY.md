# Template Seeding Policy

## Purpose

This document defines the rules governing how `dasops create` seeds new product repositories from the template.

## Seeding Rules

### Required Files

Every seeded repo MUST contain:

| File | Source | Mutable After Seed |
|------|--------|-------------------|
| `cadence.yaml` | Generated from template + user inputs | Yes |
| `tooling_lock.json` | Copied from template | Yes (reviewed manual pin update) |
| `local_extension_manifest.json` | Copied from template | Yes |
| `STANDARD_REF.md` | Copied with the template's declared Standard baseline | Yes (reviewed Standard reference update) |
| `scripts/verify` | Copied from template | Yes (with constraints) |
| `README.md` | Generated from template | Yes |
| `VERSION` | Set to `0.1.0` | Yes |
| `CHANGELOG.md` | Generated initial release log | Yes |

### Forbidden Patterns

The template MUST NOT seed:

1. **Copied standard text** — No `docs/standards/DAS_STANDARD.md`. Use `STANDARD_REF.md` to point to the canonical standard.
2. **Stale baseline names** — No legacy `current-baseline` baseline or other deprecated identifiers.
3. **Absolute paths** — No `<sandbox-root>/`, no host-specific paths.
4. **Fixture-only data** — No seeded example data may pass verification without real content.

### Template Update Flow

When the template changes:

1. Existing repos are NOT auto-updated.
2. There is no automatic Standard upgrade command. Review the new Standard,
   update `STANDARD_REF.md` and the corresponding version/pin fields in
   `tooling_lock.json` and any project closure/lock files together, preserve local
   document content, then run the product's existing verification entry point.
   Keep the source changes reviewable and record the selected Standard version.
3. `dasops doctor` checks required structure, lock/schema constraints and task state.
   It does not prove byte-for-byte template freshness or authorize an upgrade.
4. Manual re-seeding is never required for existing repos.

## Verification

The template itself is verified by `dasops/scripts/verify`, which checks:

- Template completeness (all required files present)
- No forbidden patterns
- Schema validity of seeded JSON files
- Verify script executability
