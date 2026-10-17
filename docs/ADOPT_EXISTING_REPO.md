# Adopting an Existing Repo into DAS Governance

## Overview

This guide explains how to bring an existing repository under DAS verification governance using the OPS-002 `audit-repo`, `adopt-repo`, `normalize-repo`, and `trace-check` flow.

## Prerequisites

- Python 3.9+
- `dasops` installed (`pip install -e .` from the dasops repo)
- Target repo must be a git repository

## Steps

### 1. Audit the Repository

```bash
python3 -m dasops audit-repo <repo-path> --json
```

This checks for:
- Required structural files (VERSION, CHANGELOG.md, README.md, LICENSE, NOTICE)
- Required doc files (docs/master_doc.md, docs/ui_spec.md)
- Change management infrastructure (openspec/changes)
- Build/verify prerequisites (BUILD_REQUIREMENTS.md, VERIFY_REQUIREMENTS.md)
- Cadence configuration (cadence.yaml or cadence.yml)
- Verification script (scripts/verify)

### 2. Normalize the Repository

```bash
python3 -m dasops adopt-repo <repo-path> --json
```

This creates missing governance baseline files with concrete default content.
Verify scripts are created executable and fail closed until their required
evidence is present.

### 3. Repair Documentation Links

```bash
python3 -m dasops normalize-repo <repo-path> --json
```

Scans markdown files for known stale standard-version links, rewrites them to canonical targets, and reports the edits.

### 4. Trace Check

```bash
python3 -m dasops trace-check <repo-path> --json
```

Verifies:
- VERSION file is non-empty
- Current version appears in CHANGELOG.md
- Required artifacts trace through requirements, tasks, verify, and evidence nodes

### 5. Run Verification

After adoption, run the full verify:

```bash
bash <repo-path>/scripts/verify
```

## Common Issues

| Issue | Resolution |
|-------|-----------|
| Missing cadence.yaml | Create from template: `dasops create --cadence-only <repo-path>` |
| Broken doc links | Run `--repair-links` to identify, then fix manually |
| VERSION not in CHANGELOG | Add a release entry to CHANGELOG.md |
