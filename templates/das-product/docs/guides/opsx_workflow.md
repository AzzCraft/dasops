# OpenSpec OPSX workflow (DAS-aligned)

This repo ships an OpenSpec-style `openspec/changes/<change-id>/` layout **aligned to DAS**:

- `master_doc_delta.md`
- `contracts_plan.md`
- `verification_plan.md`
- `tasks.md`

A practical workflow is:

1) **Explore** (clarify the problem)
2) **Spec** (contracts-first)
3) **Plan** (verification gates)
4) **Apply** (implementation)
5) **Sync** (merge deltas into `docs/master_doc.md`)

> In this repo, those steps map to artifacts and scripts. Use `dasops status` to see what's next.

---

## 1. Create a change folder

### Option A (recommended for most teams): generate template artifacts now

```bash
dasops new-change --id <change-id> --intent "<what/why>"
```

This creates the change folder *and* copies templates for the four artifacts.

Each template includes a draft marker:

```md
<!-- DASOPS:DRAFT -->
```

Remove the draft marker when you consider the artifact complete, so `dasops status` can accurately report DONE.

### Option B (OPSX / generation-first): create metadata only

If you prefer to have OpenSpec OPSX (or your IDE agent) generate artifacts from scratch:

```bash
dasops new-change --id <change-id> --intent "<what/why>" --empty
```

This creates the folder and task lock directory, but does not pre-create artifact files.

---

## 2. Orchestrator responsibilities

- Keep `docs/master_doc.md` as the "system truth".
- Maintain `openspec/changes/<change-id>/tasks.md` as the **single source of truth** for:
  - Task IDs
  - Owners
  - Dependencies
  - Verify gates
- Ensure contracts are updated **before** implementation when cross-boundary changes are involved.

---

## 3. Worker responsibilities

Workers should:

- Only work on tasks assigned to them.
- Claim tasks with a lock before writing code.
- Run the verify gate for every task.

See `docs/USER_MANUAL.md` for step-by-step instructions.
