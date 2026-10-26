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
- Install the selected DASOps component using the Quickstart below, then use `python3 -m dasops create` to scaffold your product repo. Suite syncs component sources; installing Suite alone does not install DASOps.

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

If you are using DAS Suite, set `SUITE_ROOT` to your clean, cloned Suite
repository. Keep the virtual environment outside that repository. Install from
committed source archives so package build files do not enter the locked source
workspaces; the temporary archives below can be removed after installation.

```bash
SUITE_ROOT=/absolute/path/to/das-suite
DASOPS_VENV="$HOME/.venvs/dasops-suite"
python3 -m venv "$DASOPS_VENV"
. "$DASOPS_VENV/bin/activate"

git -C "$SUITE_ROOT" archive --format=tar --output="$DASOPS_VENV/suite-source.tar" HEAD
python3 -m pip install "$DASOPS_VENV/suite-source.tar"
python3 -m dassuite sync --repo-root "$SUITE_ROOT"
python3 -m dassuite report --workspace --repo-root "$SUITE_ROOT"

# Install the factory selected by Suite, not an unrelated latest package.
FACTORY_ROOT="$SUITE_ROOT/src/dasops"
git -C "$FACTORY_ROOT" archive --format=tar --output="$DASOPS_VENV/dasops-source.tar" HEAD
python3 -m pip install "$DASOPS_VENV/dasops-source.tar"
rm -- "$DASOPS_VENV/suite-source.tar" "$DASOPS_VENV/dasops-source.tar"
python3 -m dasops --help
```

Stop if sync or the workspace report fails; resolve the reported mismatch before
installing DASOps. Reuse this activated environment for the CLI and GUI below.
This installs the creator, not the product's Cadence runtime.

If you are using this repo directly:

```bash
git clone https://github.com/AzzCraft/dasops.git
cd dasops
FACTORY_ROOT="$(pwd)"
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
dasops --help
```

### 2) Create a new product repo (CLI)

The following command keeps the default Standard **1.4** behavior. For **1.5**,
complete the Suite installation above and use the
[explicit beta selection](#standard-15-scaffold-explicit-beta-selection) instead.

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
./scripts/verify --scope scaffold
```

### 3) Create a new product repo (GUI)

With the same virtual environment activated, use the absolute `FACTORY_ROOT`
set by either installation path above. These commands also work after changing
into your product directory; GUI files belong to the factory, not the product.

```bash
python3 -m pip install -r "$FACTORY_ROOT/requirements-gui.txt"
python3 -m streamlit run "$FACTORY_ROOT/gui/app.py"
```

For 1.5 in the GUI, select `1.5.0-beta.1` and enter the same `SUITE_ROOT` as the
fixed synced workspace. GUI dependencies do not replace the DASOps installation.

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

The default `create` target remains Standard 1.4. For 1.5, complete the Suite
Quickstart above, including installing its selected DASOps in the active venv.
Use that same fixed `SUITE_ROOT` and actual 1.5 input documents:

```bash
python3 -m dasops create --standard-release 1.5.0-beta.1 \
  --from-suite "$SUITE_ROOT" --dest /path/to/new-product \
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
`scripts/install_cadence_vendor.sh --from-suite "$SUITE_ROOT"`, then use
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

Newly generated 1.4 templates now also require an explicit fixed installation:

```bash
# CADENCE_COMMIT is the complete 40-character commit you selected.
# On creation, pass --runtime-commit "$CADENCE_COMMIT" to dasops create.
./scripts/install_cadence_vendor.sh --from-suite /path/to/suite --commit "$CADENCE_COMMIT"
# Or use --git-base https://github.com/AzzCraft with the same --commit.
./cadencew version --json
./scripts/verify --scope full
```

The local source must be an independent Git checkout in `suite/src/cadence-oss`
or the legacy sibling `cadence-oss`; source-only archives without Git identity
are refused. The installer checks out the exact commit, builds and verifies its
binary before replacing the previous installation. Working-tree changes are not
copied. Git, Go, Python and Linux `flock` are required for installation. Only
registry-selected resources, licenses, VERSION and the binary are installed;
compiler sources, tests and Git databases stay in the temporary build checkout.
The wrapper checks the recorded resources, binary digest, native version identity and original
runtime declaration before executing; it never selects a PATH binary or rebuilds
silently. A changed resource, binary or runtime declaration requires explicit reinstall.
Execution holds a shared installation guard; replacement waits for it to finish.

For a new 1.4 project, `dasops create --runtime-commit "$CADENCE_COMMIT"` writes
the matching `verifyRuntime` into `tooling_lock.json` (with the usual creation
arguments). For an existing project, explicitly set that object to `kind: git`,
`uri: ./vendor/cadence/cadence-oss`, `pinType: commit`, `pinValue: <full SHA>`,
`floating: false`, preserving other product fields. The installer rejects a
missing or mismatched declaration without changing it. The 1.5 path continues
to use the selected Suite pin and rejects `--runtime-commit` overrides.
If replacement cannot restore an old installation because the destination is
occupied, the error identifies a preserved `previous` directory. Inspect both
trees and resolve the collision before restoring; do not delete that backup.

Default `scripts/verify` is full scope and fails without a verified installation
or when Cadence fails. `--scope scaffold` runs local checks and explicitly leaves
Cadence execution pending. Existing 1.4 native configuration still needs valid
inputs for the selected Cadence version; installation alone does not create them.
Configure the pinned install and native inputs before the product CI full gate.
Upgrading DASOps does not modify existing projects. To opt in, review and update
`scripts/install_cadence_vendor.sh`, `scripts/cadence_runtime.py`, `cadencew`,
`scripts/verify` and the `verify-frontend`, `verify-backend`, `verify-contracts`
sub-entrypoints together from the new template, preserving product-specific
checks, documents and locks. Sub-entrypoints must request scaffold for their local
prechecks; add local runtime outputs to `.gitignore`. Reinstall
with the chosen commit (use `--force` to replace old vendor contents). Old unrecorded
installations cannot be executed by the new wrapper. This changes installation
and verification behavior explicitly; it does not migrate project documents to 1.5.

For 1.5 documents, template wrapper titles and bold metadata formatting are optional;
required sections, metadata values and profile applicability remain checked.
Supported output aliases are `docs/ui_spec.md` or `docs/ui_spec_appendix.md`, and
`docs/context_pack.md` or `docs/context-pack.md`. Select one path per document type
in the Master references, and use the same UI Canonical doc path when declared.
A leading `./` and a link fragment do not change the selected local file.
Recommended filenames in unfilled template guidance do not select a document.


For UI projects, implement the actual product tests in the generated `scripts/verify-frontend`. The initial entry fails explicitly; full verification calls it and reports its exit separately from native core checks. It must not call the top-level verify script recursively. Passing that command is not a claim that DASOps itself evaluated the UI.
