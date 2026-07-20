## Task index

| Task ID | Title | Owner | Status | Depends on | Verify gate |
| --- | --- | --- | --- | --- | --- |
| T-100 | Lock lifecycle cleanup | worker-lock | IN_PROGRESS | - | `./scripts/verify` |
| T-101 | Registry parity gate | worker-registry | BLOCKED | T-100 | `./scripts/verify-contracts` |
| T-102 | GUI command hints | worker-gui | PROPOSED | T-101 | `./scripts/verify-frontend` |

### T-100 Lock lifecycle cleanup
- Owner: worker-lock
- Status: IN_PROGRESS
- Verification:
  - Run `./scripts/verify`

### T-101 Registry parity gate
- Owner: worker-registry
- Status: BLOCKED
- Verification:
  - Run `./scripts/verify-contracts`
