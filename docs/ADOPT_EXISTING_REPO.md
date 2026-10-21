# Adopting an Existing Repo into DAS Governance

## Overview

This guide explains how to bring an existing repository under DAS verification governance using the OPS-002 `audit-repo`, `adopt-repo`, `normalize-repo`, and `trace-check` flow.

## Prerequisites

- Python 3.10+
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
Type conflicts are refused before seeding; move or back up the conflicting path and retry. Existing files are preserved.
The generated executable verify script returns `not_configured` (exit 2). Replace
it with the actual project gate; adoption does not prove that verification ran.

### 3. Repair Documentation Links

```bash
python3 -m dasops normalize-repo <repo-path> --json
```

Repairs known stale links only when the old target is missing and the proposed local file exists. Valid historical links remain unchanged. Other broken links require manual correction.

### 4. Trace Check

```bash
python3 -m dasops trace-check <repo-path> --json
```

Verifies:
- VERSION file is non-empty
- Current version appears in CHANGELOG.md
- Required baseline layout has the expected file/directory types

This is a layout/version check only; it does not verify task/evidence relations.

### 5. Run Verification

After configuring the project gate, run it from the target repository:

```bash
cd <repo-path>
bash scripts/verify
```

## Common Issues

| Issue | Resolution |
|-------|-----------|
| Missing cadence.yaml | Run `dasops adopt-repo <repo-path>` to seed a missing file, then configure it for the project |
| Broken doc links | Run `dasops normalize-repo <repo-path>` for supported safe repairs; inspect remaining links manually |
| VERSION not in CHANGELOG | Add a release entry to CHANGELOG.md |
