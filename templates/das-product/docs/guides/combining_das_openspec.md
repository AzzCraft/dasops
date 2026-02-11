# Combining DAS and OpenSpec in this repository

## Mental model

- **DAS** tells you *what* must exist and must be enforced:
  - Master Doc and UI Spec as canonical truth
  - Contract-first evolution rules
  - Verify gates as CI entrypoints

- **OpenSpec** gives you a *change-folder workflow* and an *artifact graph*:
  - `openspec/specs/` = “current truth”
  - `openspec/changes/<change-id>/` = proposed updates for a change
  - schemas define which artifacts to generate and their dependencies

In this repo we keep DAS “canonical docs” in `docs/`, and use OpenSpec change folders as the
mechanism to generate / track deltas and execution plans.

## Artifact mapping (default)

OpenSpec schema: `das-standard`

| DAS need | Generated artifact (per change) | File |
|---|---|---|
| Master Doc updates | Master Doc Delta | `master_doc_delta.md` |
| Contracts / interface plan | Contracts Plan | `contracts_plan.md` |
| Verify gates plan | Verification Plan | `verification_plan.md` |
| WBS / acceptance + verify commands | Execution Tasks | `tasks.md` |

## Why change folders instead of editing the Master Doc directly?

Because it keeps “proposal vs truth” diffs explicit, reviewable, and archivable.

When you finish a change, you can:
- merge code + updated canonical docs in `docs/`
- archive the change folder (OpenSpec style), keeping history

## Where templates live

Project-local OpenSpec schema and templates:

- `openspec/schemas/das-standard/schema.yaml`
- `openspec/schemas/das-standard/templates/*.md`
