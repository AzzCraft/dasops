# OSS Quickstart: independent source and product checks

Use Python 3.10+ and Git. From an independent DASOps checkout, follow the README
venv setup and run `python3 -m pip install -e .`. The installed `dasops` command
works outside this checkout. GUI use additionally requires its optional dependencies.

```bash
dasops --help
dasops doctor
DEMO_WORK="$(mktemp -d)"
dasops create --dest "$DEMO_WORK/product" \
  --master-doc templates/das-product/docs/master_doc.md \
  --ui-spec templates/das-product/docs/ui_spec.md \
  --change-id initial --intent "Synthetic OSS quickstart"
cd "$DEMO_WORK/product"
bash scripts/verify
```

`doctor` reports actual available/missing prerequisites; a nonzero result
requires reading those diagnostics, not assuming all optional tools are installed.
The default scaffold remains Standard 1.4.0 / core-v146-baseline. It is distinct
from the controlled Standard 1.5 adoption path. Frontend checks run when legacy
`ui.enabled` is true or `scripts/verify-frontend` is requested; they check matrix
structure and file presence, not a visual comparison.

## Optional native Cadence evidence round trip

In a separate [Cadence source checkout](https://github.com/AzzCraft/cadence-oss),
use its documented Go baseline (1.26.9 or newer) to build both public commands:

```bash
go -C cadence-core build -o ./cadence ./cmd/cadence
go -C cadence-core build -o ./evidence-verify ./cmd/evidence-verify
```

Set `CADENCE_SOURCE` to that checkout. The native example has the closure,
registry, runtime and sandbox references required by the native CLI. The default
Factory seed does not contain that native configuration; do not run the native
CLI against its shorter `cadence.yaml` or relabel it as approved 1.5 adoption.
Run the existing headless example separately:

```bash
cd "$CADENCE_SOURCE/cadence-examples/examples/headless-minimal"
"$CADENCE_SOURCE/cadence-core/cadence" verify --profile dev
"$CADENCE_SOURCE/cadence-core/evidence-verify" --profile cadence-run/v2 \
  --bundle .cadence/out/latest/evidence-bundle.json
```

For a separate inventory **schema** check, install Cadence's declared Python
verification dependencies, then run
`python3 "$CADENCE_SOURCE/cadence-protocol/tools/validate_artifacts.py" --profile native-inventory/v2 .cadence/out/latest`.
The helper's default `protocol/v1` checks historical protocol objects, whose
timestamp/budget fields differ from native run evidence. It does not guess a
weaker profile from the input. Neither check replaces full adoption qualification.

The native reader checks the specified inventory/chain profile and file integrity;
it grants no signer authentication, qualification or write authorization. Replay
packages are retained derived artifacts; this CLI has no `replay` subcommand.
No joint workspace, private evidence index or clean-room script is required.
Fresh run directories are immutable. A failed delivery never advances `latest`.
If upgrading an old directory-form `latest`, stop writers and move that directory
to a retained backup once; new versions publish a symlink atomically.
