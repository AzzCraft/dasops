# UI Spec

This document is the UI contract.

It defines screens, states, and user workflows.

If UI behavior changes, update this file in the same pull request.

## 1. User workflows

- W1: Reviewer opens the product status screen, checks current change state,
  runs verification, and exports evidence for review.

## 2. Screens

### 2.1 Screen: Product Status

- Purpose: show current version, active change, task-lock state, verification
  result, and evidence links.
- Entry conditions: repository has `VERSION`, `docs/master_doc.md`, and
  `scripts/verify`.

## 3. UI state machines

Use Mermaid `stateDiagram-v2` for state machines.

## 4. Error handling

- Validation errors show the failing file path, stable error code, and command
  to rerun after correction.
- Permission errors disable write actions and keep read-only evidence visible.

## 5. Analytics and events

- `product_status_opened`
- `verify_requested`
- `evidence_export_requested`
