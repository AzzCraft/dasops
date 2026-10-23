# dasops Factory

The current source candidate is **1.2.0-beta.1** (Python package version
`1.2.0b1`), with reference support for DAS Standard 1.5.0-beta.1. It retains the
factory workflows below and adds controlled Standard adoption, authenticated
governed operations and evidence-bound completion references. See
[`dasops/protected/candidates/README.md`](dasops/protected/candidates/README.md)
for the installation and trust boundaries. Final installed beta acceptance and
publication remain unfinished; public TEST fixtures confer no deployment authority.

This repository is a CLI + GUI **Factory tool** that generates DAS-aligned product repos, change folders, and workflows in a separate **Product repository** scaffold.

Recommended usage:

- Clone **DAS Suite** (another repo das-suite) and let it pull this repo into `src/dasops`.
- Use `dassuite new-product` or `python3 -m dasops create` to scaffold your product repo.

Without **DAS Suite**, one can just git clone this repo to use this tool. See instructions below.

Key idea: keep tooling and the generated product **physically isolated** to prevent a common AI failure mode—agents accidentally running/modifying the factory GUI/tooling instead of the product code.

---

## What this repo contains

- **CLI tool**: `dasops` (scaffold + change-folder helpers)
- **GUI**: Streamlit app (bootstrap a product repo for non-expert users)
- **Product repo template**: `templates/das-product/` (DAS + OpenSpec-style change folders + verify gates + agent governance)

After generation, you work in the **product repo** (not this factory repo).

---

## Quickstart

### 0) Prerequisites

- Git
- Python 3.10+
- (Recommended) VS Code
- (Workers) Codex CLI (OpenAI)

### 1) Install

If you are using DAS Suite:

```bash
cd das-suite
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m pip install -e .

dassuite sync --tier oss
```

If you are using this repo directly:

```bash
git clone https://github.com/AzzCraft/dasops.git
cd dasops
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
dasops --help
```

### 2) Create a new product repo (CLI)

```bash
# Create a product repo in a *different* directory (physical isolation)
python3 -m dasops create \
  --dest ~/projects/my-product \
  --master-doc /path/to/master_doc.md \
  --ui-spec /path/to/ui_spec.md \
  --change-id initial \
  --intent "Initial bootstrap"
```

By default, `dasops create` refuses to create the product repo inside the factory folder.

Then:

```bash
cd ~/projects/my-product
./scripts/verify
```

### 3) Create a new product repo (GUI)

```bash
python3 -m pip install -r requirements-gui.txt
streamlit run gui/app.py
```

---

## Multi-worker essentials

In the **product repo**, each change folder has:

- `openspec/changes/<change-id>/tasks.md`
- `openspec/changes/<change-id>/task_locks/<task-id>.lock`

Recommended worker flow:

### Pull-based dispatch (recommended when dependencies are common)

If tasks have dependencies, pre-assigning owners can leave workers idle.
In **pull mode**, Orchestrator leaves `Owner = -` for most tasks and workers claim the next READY task:

```bash
dasops claim-ready --change-id <change-id> --owner worker01
```

This claims the first TODO task whose dependencies are DONE and writes its lock file.

Inspect a structured lock:

```bash
dasops lock-status --change-id <change-id> --task-id T-001 --json
```

### Push-based dispatch

1) Create a branch + worktree + claim a task in one command:

```bash
dasops start-task --change-id <change-id> --task-id T-001 --owner worker01
```

2) Run the worker loop:

```bash
./scripts/run_worker_codex.sh <change-id> T-001 worker01
```

### Health check

Run `dasops doctor` (or `dasops doctor --strict`) before starting work to check
that the repo has valid configuration, required files, and consistent tooling
artifacts.

## Verification

```bash
bash ./scripts/verify
```

## Cooperative task-state upgrade

All participating writers in one local worktree must use the same new version.
Stop old workers before upgrading. Markdown and YAML stay readable in their
existing formats; `.dasops-local/` contains the ignored change guard and at most
one fixed-pair recovery record. Readers encountering pending recovery refuse with
`recovery_required`; the next mutating operation first rolls the recorded operation
forward exactly. After a lost reply, query current state before retrying. Manual
third-state bytes cause `recovery_conflict`: preserve the journal and both files,
stop writers and reconcile the recorded before/after against the manual change.
Do not delete a journal to force a claim. Separate clones and malicious writers
are not coordinated by this local protocol; use the protected path when needed.

`complete-task` runs the declared single-command gate for every supported task ID.
`--force` does not skip verification. Historical status import uses explicit
`--record-only --reason "..."`, records `verification=not_run`, and is not proof
that checks passed. Gate execution releases the coordination guard for heartbeats;
owner/token/task/gate are checked again before completion. Use a script for compound
gates, not shell operators. `claim-task`/`claim-ready` set IN_PROGRESS only;
`release-task` allows TODO/BLOCKED/PROPOSED, not IN_PROGRESS or DONE. Old DONE records
are preserved without inventing verification history.

### Standard 1.5 scaffold (explicit beta selection)

The default `create` target remains Standard 1.4. For 1.5, use a fixed synced
Suite combination containing this creator and the dual-lock Cadence reader:

```bash
dasops create --standard-release 1.5.0-beta.1 \
  --from-suite /path/to/suite --dest /path/to/new-product \
  --master-doc /path/to/master.md --headless-note /path/to/headless.md
```

The Master document declares the interaction and conformance profiles. Supply
`--ui-spec` for UI surfaces, `--context-pack` for L2, and
`--extension-manifest` only for real local extensions. Documents must already
reference their output paths under `docs/`. HFVI, nonempty destination merging,
and no-Git 1.5 creation are outside this first Linux implementation.

Creation imports documents, preserves the Suite originals and creates a product
lock. It does not install a runtime or certify project conformance. In the new
product, run `scripts/verify --scope scaffold` for structure; install with
`scripts/install_cadence_vendor.sh --from-suite /path/to/suite`, then use
`./cadencew doctor` and `./cadencew verify --profile dev`. The runtime is built
once from the fixed clean source and checked before execution. Default product
`scripts/verify` requests the finite full scope; unfinished documents, an absent
runtime or a required UI runner give a failure with specific pending work.
The existing frontend evidence-file checker does not perform visual UI tests.

The creator checks its loaded code and templates against the selected Suite
factory. A package installation must include those exact resources; a matching
version string alone is insufficient. Creation and installation failures are
reported separately; an install failure preserves the created project and old
runtime. Upgrading DASOps does not automatically migrate an existing 1.4 repo.

For UI projects, implement the actual product tests in the generated `scripts/verify-frontend`. The initial entry fails explicitly; full verification calls it and reports its exit separately from native core checks. It must not call the top-level verify script recursively. Passing that command is not a claim that DASOps itself evaluated the UI.
