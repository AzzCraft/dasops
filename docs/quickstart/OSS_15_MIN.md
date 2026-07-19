# OSS 15 Minute Quickstart

This quickstart exercises the public create, verify, evidence, and replay path without a commercial license or external network dependency.

## Prerequisites

- Python 3.11 or newer.
- Go toolchain for `cadence-core` verification tests.
- A checkout containing `das-suite`, `dasops`, `das-standard`, and `cadence-oss`.

## Flow

1. Create a product repo with `PYTHONPATH=dasops python3 -m dasops create --dest /tmp/das-demo-product --master-doc dasops/templates/das-product/docs/master_doc.md --ui-spec dasops/templates/das-product/docs/ui_spec.md --change-id initial --intent "DAS demo bootstrap"`.
2. Run `python -m dasops doctor` and confirm the toolchain report is machine-readable JSON.
3. Execute `cadence-oss/cadence-core/scripts/verify` against the generated repo.
4. Export the EvidenceBundle from the verify output and run the verifier again in replay mode.
5. Attach the verification log to `das-suite/release/evidence_index.json` for release traceability.

Clean-room release replay uses one command: `das-suite/scripts/verify-clean-room --one-command`.

The expected green path is: repository scaffold created, DAS standard references present, verification returns zero, evidence hash chain verifies, and replay produces the same canonical digest.
