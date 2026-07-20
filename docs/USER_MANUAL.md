# dasops User Manual

Install the CLI in a factory checkout, then create product repositories in a
separate directory:

```bash
python3 -m pip install .
dasops create --dest ../my-product --master-doc /path/to/master_doc.md --ui-spec /path/to/ui_spec.md
cd ../my-product
bash scripts/verify
```

The primary truth paths are `docs/master_doc.md`, `docs/ui_spec.md`,
`STANDARD_REF.md`, and `openspec/changes/<change-id>/`. Each change keeps
`master_doc_delta.md`, `contracts_plan.md`, `verification_plan.md`, `tasks.md`,
and `task_locks/` together.

An orchestrator creates the plan; workers claim and complete a task:

```bash
dasops claim-ready --change-id add-login --owner worker01
dasops start-task --change-id add-login --task-id T-001 --owner worker01
dasops complete-task --change-id add-login --task-id T-001 --owner worker01
dasops lock-status --change-id add-login --task-id T-001 --json
```

Use `dasops doctor` for a local health report. The generated
`scripts/verify-backend`, `scripts/verify-contracts`, and
`scripts/verify-frontend` are intentionally fail-closed until the product
owner supplies the corresponding evidence; frontend verification is a baseline
ratchet governed by `visualMatrix` evidence.

This v1.0 product scaffold does not install or configure Cadence/suite. Do not
add closure locks or extension manifests until a repository owner can provide a
complete immutable closure that validates against the applicable schema.
