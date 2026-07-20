# Project AI Instructions (DAS + OpenSpec)

These are **override** instructions for AI agents working in this repo.

## Non-negotiable rules

1) **Docs-as-Software**: treat docs as code. If a change affects requirements, workflows, contracts, budgets,
   determinism tiering, security posture, or verification gates, you MUST update `docs/master_doc.md`
   (or document an explicit waiver) in the same PR.

2) **Contracts first**: do not change serialized field casing or semantics without an explicit compatibility plan.
   Prefer tolerant readers / additive changes.

3) **Verify gates**: before you claim a task is “done”, run the task's verify command (and at minimum `./scripts/verify`).

4) **OpenSpec change folders**: for new work, create (or use) an `openspec/changes/<change-id>/` folder and
   keep planning artifacts there (`master_doc_delta.md`, `contracts_plan.md`, `verification_plan.md`, `tasks.md`).

5) **Deterministic artifact paths**:
   - Do not create alternate task plans (no stray `tasks.md` elsewhere).
   - Do not create legacy delta folders (`docs/deltas/...`).
   - `./scripts/verify` enforces these rules; if it fails, fix the layout.

6) **Multi-agent governance**:
   - Orchestrator is the single authority for **task breakdown, owner assignment, dependencies, and verify gates**.
   - If you are a Worker, you MUST only implement tasks assigned to you in `openspec/changes/<change-id>/tasks.md`.
   - If you discover missing work, you MUST add it as a **PROPOSED** item (do not self-assign) and wait for Orchestrator approval.

7) **Task lock (anti-collision)**:
   - A Worker MUST claim a task before doing meaningful work.
   - Preferred: `dasops start-task --change-id <id> --task-id T-001 --owner <worker>` (creates branch/worktree + claims).
   - The lock file lives at `openspec/changes/<change-id>/task_locks/T-001.lock`. If it exists and is owned by someone else: stop.

8) **Draft markers (artifact readiness)**:
   - Change-folder templates start with `<!-- DASOPS:DRAFT -->`.
   - Do not remove the marker until the artifact is complete. `dasops status` only marks artifacts DONE after the marker is removed.

## Working conventions

- Keep changes small and reviewable.
- If you add new dependencies, justify them in the PR and keep them minimal.
- Prefer deterministic tests and reproducible commands.
- Update `progress.txt` at the end of meaningful sessions (external memory) and commit it.

## Where to look

- Canonical docs:
  - `docs/master_doc.md`
  - `docs/ui_spec.md`
- Governance:
  - `docs/policies/AGENT_OPERATING_MODEL.md`
- DAS Standard:
  - `STANDARD_REF.md`
- OpenSpec schema used in this repo:
  - `openspec/schemas/das-standard/schema.yaml`
