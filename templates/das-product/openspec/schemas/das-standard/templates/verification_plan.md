<!-- DASOPS:DRAFT -->
> **Draft marker:** remove the `<!-- DASOPS:DRAFT -->` line when this artifact is complete (so `dasops status` can mark it as DONE).

# Verification Plan (DAS §10 aligned)

## Verify entrypoints
List exact commands that must pass.

| Area | Command | Notes |
|---|---|---|
| System | ./scripts/verify | Required for every PR |
| Backend | ./scripts/verify-backend | If backend touched |
| Frontend | ./scripts/verify-frontend | If frontend touched |
| Contracts | ./scripts/verify-contracts | If contracts touched |

## Boundary checks (fail fast)
- What boundaries exist?
- What checks enforce them?

## Test strategy
- Unit tests:
- Integration tests:
- Contract tests:
- Replay / deterministic evals (if applicable):

## Evidence required in PR
- Links to logs / screenshots:
- Test output excerpts:
