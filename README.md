# dasops Factory

This repository is a CLI + GUI **Factory tool** that generates DAS-aligned product repos, change folders, and workflows in a separate **Product repository** scaffold.

Recommended usage:

- Clone **DAS Suite** (another repo das-suite) and let it pull this repo into `src/dasops`.
- Use `dassuite new-product` or `python -m dasops create` to scaffold your product repo.

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
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .

dassuite sync --tier oss
```

If you are using this repo directly:

```bash
git clone <this-repo> ~/tools/dasops
cd ~/tools/dasops
python -m pip install -r requirements.txt
```

### 2) Create a new product repo (CLI)

```bash
# Create a product repo in a *different* directory (physical isolation)
python -m dasops create \
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
python -m pip install -r requirements-gui.txt
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

### Push-based dispatch

1) Create a branch + worktree + claim a task in one command:

```bash
dasops start-task --change-id <change-id> --task-id T-001 --owner worker01
```

2) Run the worker loop:

```bash
./scripts/run_worker_codex.sh <change-id> T-001 worker01
```
