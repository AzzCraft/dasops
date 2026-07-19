# Project Master Doc

This document is the single source of truth for:

- requirements and scope
- repo topology and module boundaries
- cross-boundary contracts
- verification gates
- traceability from requirements to contracts and tests

If a change affects any of these elements, update this file in the same pull request.

## 2.3 Conformance profile

- DAS profile: L0 or L1 or L2

## 1. Scope

- Build and operate a DAS-governed product repository with documented scope,
  contracts, verification gates, and release evidence.
- Keep product behavior traceable from requirement to contract to executable
  verification.

## 1.4 Workflows

- W1: Author proposes a change, claims a task lock, updates contracts and code,
  runs verify gates, and attaches evidence before review.

## 3. Repo topology

- frontend: product UI package and managed visual evidence artifacts.
- backend: service or CLI runtime owned by the product team.
- contracts: schemas, fixtures, compatibility checks, and policy packs under
  `contracts/` and `openspec/changes/`.

## 4. Contracts

System-level contract inventory.

Change-level contract drafts live in:

`openspec/changes/<change-id>/contracts_plan.md`

## 0.11 Traceability

Recommended form:

Requirement -> Contract -> Verify gate

- Product scope -> `docs/master_doc.md` -> `./scripts/verify`
- UI behavior -> `docs/ui_spec.md` -> `./scripts/verify-frontend`
- Contract change -> `contracts/` and `openspec/changes/` -> `./scripts/verify-contracts`

## 10. Verification gates

System-level verify commands.

- `./scripts/verify`
- `./scripts/verify-contracts`
- `./scripts/verify-backend`
- `./scripts/verify-frontend`

## 11. Execution plan

### 11.0 Operating model

See `docs/policies/AGENT_OPERATING_MODEL.md`.

### 11.1 Project-level WBS

- Maintain required DAS shell files and governance docs.
- Keep change folders, task locks, and verification evidence current.
- Promote releases only after all configured verify gates pass.
