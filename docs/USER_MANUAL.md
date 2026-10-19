# DASOPS User Manual

Audience

This manual is written for an intern who is new to multi-branch development and AI-assisted coding.

What you will build

- A factory repository that generates product repositories
- A product repository scaffold that follows a deterministic Docs as Software layout
- A multi-worker flow where one Orchestrator plans and reviews while Workers implement tasks safely

Core rule

Factory and product repositories must be physically isolated.

If the tooling repo and the product repo share a folder, AI agents will eventually run the wrong code.

Recommended folders

```
~/tools/dasops
~/projects/<product>
```

The beginner-friendly approach

Use the GUI to create the product repo, then use the CLI for day-to-day development.

The GUI reduces setup errors. The CLI makes the workflow repeatable and scriptable.

Section 1. One-time setup

Step 1. Install the factory repo

```
git clone <FACTORY_REPO_URL> ~/tools/dasops
cd ~/tools/dasops

python3 -m venv .venv
source .venv/bin/activate

python3 -m pip install -r requirements.txt
python3 -m pip install -e .
```

Step 2. Install Codex

Orchestrator uses the Codex IDE extension.

Workers use Codex CLI non-interactive mode.

Install Codex CLI

```
npm i -g @openai/codex
```

Or use Homebrew:

```
brew install --cask codex
```

Verify:

```
codex --version
```

Authenticate

The first time you run `codex`, it will prompt you to sign in.

For server workflows, set an API key and run `codex` once to complete setup:

```
export OPENAI_API_KEY="<YOUR_KEY>"
codex
```

Section 2. Create a product repo

You need two input documents.

- `master_doc.md`
- `ui_spec.md`

Option A. GUI creation

```
cd ~/tools/dasops
python3 -m pip install -r requirements-gui.txt
streamlit run gui/app.py
```

Upload the two documents, choose an output folder under `~/projects/`, and click Create.

Option B. CLI creation

```
dasops create \
  --dest ~/projects/my-product \
  --master-doc /path/to/master_doc.md \
  --ui-spec /path/to/ui_spec.md \
  --change-id initial \
  --intent "Initial import"
```

After creation

```
cd ~/projects/my-product
./scripts/verify
```

Section 3. Deterministic truth paths

Do not allow AI tools to invent new truth file locations.

The only allowed paths are:

- System truth
  - `docs/master_doc.md`
  - `docs/ui_spec.md`
- Change truth
  - `openspec/changes/<change-id>/master_doc_delta.md`
  - `openspec/changes/<change-id>/contracts_plan.md`
  - `openspec/changes/<change-id>/verification_plan.md`
  - `openspec/changes/<change-id>/tasks.md`
- Coordination locks
  - `openspec/changes/<change-id>/task_locks/<task-id>.lock`

If any new `tasks.md` appears outside these folders, treat it as a failure.

Lock files are structured YAML. Inspect them through the CLI instead of grepping raw text:

```
dasops lock-status --change-id <change-id> --task-id T-001 --json
```

Section 3.5. Machine-readable standard lookup

Use the machine-readable indexes from `das-standard` instead of searching the full spec manually.

```bash
dasops standards search --query "closure"
dasops standards show --clause cl-2.5
dasops standards pack --for backend
```

These commands consume `chapter_index.json` and `clause_index.json` from the sibling `das-standard` repo.
Inside the standalone `DAS_TOOLS_v1_0_0` release package, standards commands use only the package-local `DAS_TOOLS_v1_0_0/das-standard` directory by default.
Pass `--standard-root /path/to/das-standard` only when you intentionally want an explicit DAS Standard override.

Section 4. Orchestrator workflow

Orchestrator owns the plan.

Orchestrator creates and maintains the change artifacts and the task plan.

Step 1. Create a change folder

```
dasops new-change --id add-login --intent "Add login"
```

If you want an automatic change id:

```
dasops new-change --id auto --intent "Add login"
```

Step 2. Use the Orchestrator prompt

Open this file and paste it into the Codex IDE agent chat.

`prompts/orchestrator.md`

Replace `{{CHANGE_ID}}` with your change id.

Step 3. Produce a stable tasks file

The tasks plan of record is:

`openspec/changes/<change-id>/tasks.md`

It must contain a single canonical task index table.

Task IDs are sequential and stable.

T-001, T-002, T-003.

Every task has a verify gate command.

Step 4. Assign owners

Orchestrator assigns owners in `tasks.md`.

Workers must not override an Orchestrator assignment.

Section 5. Worker workflow

Workers implement only the tasks assigned to them.

Step 1. Start a task

Pick the coordination mode from `tasks.md`.

Pull mode:

```
export DASOPS_OWNER=worker01
dasops claim-ready --change-id add-login
```

Push mode:

```
export DASOPS_OWNER=worker01
dasops start-task --change-id add-login --task-id T-001
```

This creates a feature branch, creates a worktree, and claims the task lock.

Step 2. Run the Codex worker loop

Inside the worktree:

```
./scripts/run_worker_codex.sh add-login T-001 worker01
```

This renders `prompts/worker.md` and runs `codex exec --full-auto`.

Codex should iterate until the task verify gate passes.

Option. Use Codex Cloud tasks

Use this when the task is long-running and you want Codex to work in a cloud environment.

Launch a cloud task:

```
codex cloud exec --env ENV_ID "Implement Task T-001 from openspec/changes/add-login/tasks.md. Run ./scripts/verify until it passes."
```

Then run `codex cloud`, select the task, and apply the diff to your worktree. After applying, run `./scripts/verify` locally.

Step 3. Complete the task

```
./scripts/verify
dasops complete-task --change-id add-login --task-id T-001

git add -A
git commit -m "T-001: <summary>"
git push -u origin HEAD
```

Open a pull request and let CI run the verify gates again.

Section 6. Git worktree basics

Worktrees let you check out multiple branches at the same time.

List worktrees

```
git worktree list
```

Add a worktree

```
git worktree add ../wt-T-002 -b feat/add-login/T-002 main
```

Remove a worktree

```
git worktree remove ../wt-T-002
git worktree prune
```

Section 7. Cadence integration

Cadence provides deterministic verification and evidence artifacts.

Step 1. Vendor Cadence

Preferred when you already have a DAS Suite checkout:

```
./scripts/install_cadence_vendor.sh --from-suite /path/to/das-suite --tier oss
```

Or clone from a Git base:

```
./scripts/install_cadence_vendor.sh --tier oss --git-base https://github.com/<org>
```

Clone mode is fail-closed: pass `--git-base`, `--org`, or set
`DAS_SUITE_GIT_BASE`.

Step 2. Verify Cadence itself

```
bash vendor/cadence/cadence-oss/scripts/verify
```

Step 3. Run Cadence on the product repo

Go is required if the cadence binary is not installed globally.

From the product repo root:

First provide the native CLI's required `closureRef`, `toolingLock`, `runtimeRef`,
`registryRef` and `sandboxRef` and their valid referenced artifacts. The default
1.4 Factory seed has only the legacy configuration: copying the binary/vendor
directory does not configure native execution or approve 1.5 adoption. Without
those inputs the native gate refuses the project. For a ready synthetic native
example, use the separate headless flow in [OSS quickstart](quickstart/OSS_15_MIN.md).

```
./cadencew verify --profile dev
```

Cadence host-local stays `mode=host-launcher`; non-host profiles use `mode=runtime-exec` and fail closed unless `CADENCE_SANDBOX_CONTAINER_ADAPTER` or `CADENCE_SANDBOX_MICROVM_ADAPTER` returns verified runtime proof.

If Cadence is vendored under `vendor/cadence`, `./scripts/verify` also runs this Cadence gate.

Evidence output is written to:

`.cadence/out/<run-id>/`

The latest alias is:

`.cadence/out/latest/`

Section 8. Troubleshooting

If a task is already claimed

```
dasops list-tasks --change-id <change-id>
```

If you see a stray `tasks.md`

- Move content into `openspec/changes/<change-id>/tasks.md`
- Delete the stray file
- Run `./scripts/verify`

Health check and quick diagnostics:

```
dasops doctor
dasops start-task --change-id <change-id> --task-id <task-id>
```

Sub-system verification scripts:

```
scripts/verify-backend
scripts/verify-frontend
```

For frontend repos, product UI tests should implement a visual regression
baseline ratchet. The shipped `scripts/verify-frontend` checks only `visualMatrix`
structure and non-empty evidence directories, not comparisons, review or approval.
Main verify selects it through boolean legacy `ui.enabled`; an explicit call forces
it once. The governed matrix schema is at
`templates/das-product/openspec/schemas/das-standard/visual_matrix.schema.json`.
The standard template runtime expects `artifacts/frontend/visualMatrix.json`
to match that schema,
`artifacts/frontend/baseline/`, and `artifacts/frontend/screenshots/`.
