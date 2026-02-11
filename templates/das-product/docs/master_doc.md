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

TBD

## 1.4 Workflows

- W1: TBD

## 3. Repo topology

List the repos, modules, and boundaries.

- frontend: TBD
- backend: TBD
- contracts: TBD

## 4. Contracts

System-level contract inventory.

Change-level contract drafts live in:

`openspec/changes/<change-id>/contracts_plan.md`

## 0.11 Traceability

Recommended form:

Requirement -> Contract -> Verify gate

TBD

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

TBD
