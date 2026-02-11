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

python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
pip install -e .
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
pip install -r requirements-gui.txt
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

The safest intern flow is a single command.

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

Use a submodule when working in a team.

```
./scripts/install_cadence_vendor.sh submodule https://github.com/<org>/cadence.git
```

Step 2. Verify Cadence itself

```
cd vendor/cadence
bash ./verify_all.sh
```

Step 3. Run Cadence on the product repo

Go is required if the cadence binary is not installed globally.

From the product repo root:

```
./cadencew verify --profile dev
```

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
