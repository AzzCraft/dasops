## Task index

| Task ID | Title | Owner | Status | Depends on | Verify gate |
| --- | --- | --- | --- | --- | --- |
| T-010 | Prepare API contract | worker-a | DONE | - | `./scripts/verify-backend` |
| T-011 | Build UI flow | worker-b | IN_PROGRESS | T-010 | `./scripts/verify-frontend` |
| T-012 | Reconcile docs | - | TODO | T-010 T-011 | `./scripts/verify` |

### T-010 Prepare API contract
- Owner: worker-a
- Status: DONE
- Verification:
  - Run `./scripts/verify-backend`

### T-011 Build UI flow
- Owner: worker-b
- Status: IN_PROGRESS
- Verification:
  - Run `./scripts/verify-frontend`

### T-012 Reconcile docs
- Owner: -
- Status: TODO
- Verification:
  - Run `./scripts/verify`
