# CLAUDE.md — AI operating rules (DAS + OpenSpec)

This repository follows **Docs as Software (DAS)** and an **OpenSpec-style change workflow**.

This file exists to support tools that automatically load `CLAUDE.md` as project instructions.
Even if you are not using Claude Code, treat this as canonical AI rules.

## Always read these files first (in order)

1) `docs/master_doc.md` — system truth (requirements, topology, contracts, verify gates, traceability)
2) `docs/ui_spec.md` — UI contract (screens, states, workflows)
3) `progress.txt` — project progress / external memory
4) `openspec/changes/<change-id>/tasks.md` — execution plan for the active change

## Non-negotiable rules

1) **Docs-as-Software**: if a change impacts requirements, workflows, contracts, budgets, determinism, security posture, or verification gates, update `docs/master_doc.md` (or document an explicit waiver) in the same PR.

2) **Contracts first**: do not change serialized field casing or semantics without a compatibility plan. Prefer tolerant readers and additive changes.

3) **Deterministic artifact paths**: do not create random folders or alternative task files. The only authoritative task plan is `openspec/changes/<change-id>/tasks.md`.

4) **Verify gates**: run the exact verify command listed for the task. At minimum, run `./scripts/verify` before claiming “done”.

5) **Multi-agent governance**:
   - Orchestrator is the single authority for task breakdown, owner assignment, dependencies, and verify gates.
   - Workers implement only tasks assigned to them.
   - If a Worker discovers missing work, add it as a **PROPOSED** item (do not self-assign).

6) **Task lock (anti-collision)**:
   - A Worker MUST claim a task before doing meaningful work.
   - Lock file: `openspec/changes/<change-id>/task_locks/<task-id>.lock`.
   - If a lock exists and is owned by someone else: stop.

## Conventions

- Keep changes small and reviewable.
- Prefer deterministic tests and reproducible commands.
- Always reference exact file paths in instructions.

## Notes for Codex

- If using Codex CLI, set `CODEX_HOME=$(pwd)/.codex` so Codex uses this repo’s config.
- Workers should run in non-interactive mode (`codex exec --full-auto`).
