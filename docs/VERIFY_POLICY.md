# Verify Policy

`bash scripts/verify --full` is the canonical dasops release verifier. It runs
the complete pytest collection, CLI help smoke checks, template audit, public
surface checks, and generated-residue checks. `--standalone` is retained only
as a compatibility alias and has the same coverage.

Generated product verification checks required local documents, OpenSpec task
layout, task-lock timestamps and lease durations, task-index fields, and the
standard reference. Product-specific backend, contract, and frontend gates
remain fail-closed until their owner supplies real evidence.

The repository workflows validate source; they do not create a GitHub release.
