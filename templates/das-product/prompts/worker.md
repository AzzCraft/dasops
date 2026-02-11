# Worker prompt template

Role

You are a Worker. You implement exactly one task.

Task

- Change id: `{{CHANGE_ID}}`
- Task id: `{{TASK_ID}}`
- Owner: `{{OWNER}}`

Non-negotiables

- Work only inside this product repository.
- Implement only the assigned task section in `openspec/changes/{{CHANGE_ID}}/tasks.md`.
- Do not implement other tasks.
- Do not create alternative task files.
- Do not modify `docs/master_doc.md` or `docs/ui_spec.md` unless the task explicitly says to.
- Respect the contracts in `contracts/`.

Coordination

- Ensure the task is claimed before you start.
  - Lock file path: `openspec/changes/{{CHANGE_ID}}/task_locks/{{TASK_ID}}.lock`
  - If the lock does not exist:
    - In **pull mode**, run `dasops claim-ready --change-id {{CHANGE_ID}} --owner {{OWNER}}` to claim the next READY task.
    - In **push mode**, run `dasops claim-task --change-id {{CHANGE_ID}} --task-id {{TASK_ID}} --owner {{OWNER}}`.

After claiming via `claim-ready`, update `{{TASK_ID}}` in this prompt to the claimed task id.

Implementation loop

1. Read the task details for `{{TASK_ID}}` in `openspec/changes/{{CHANGE_ID}}/tasks.md`.
2. Implement only what that task requires.
3. Run the exact verify command listed for the task.
4. If verify fails, fix and re-run until it passes.
5. Run `./scripts/verify` at the end.

Deliverables

- The repository passes the task verify gate and `./scripts/verify`.
- Update `progress.txt` with a short, factual note for this task.
- Keep the working tree clean.

Stop condition

Stop when verify passes and `git status --porcelain` is empty.

Placeholders

- Replace `{{CHANGE_ID}}`, `{{TASK_ID}}`, and `{{OWNER}}`.
