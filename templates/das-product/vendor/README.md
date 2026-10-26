# Vendor folder

Use this folder for pinned third-party dependencies that are part of your build and verification.

Recommended path for Cadence:

`vendor/cadence/`

The canonical DAS standard entry remains `STANDARD_REF.md`; do not vendor or
copy a local `docs/standards/DAS_STANDARD.md` into this folder.

Install with Git, Go, Python and Linux `flock` available, and `CADENCE_COMMIT` set to the full
40-character commit you selected:

- `./scripts/install_cadence_vendor.sh --from-suite /path/to/suite --commit "$CADENCE_COMMIT"`
- `./scripts/install_cadence_vendor.sh --git-base https://github.com/<org> --commit "$CADENCE_COMMIT"`

Local mode reads an independent Git checkout at `suite/src/cadence-oss` or the
legacy sibling `cadence-oss`, checks out only committed files at the chosen SHA,
and builds/checks the binary before replacement. Archives without Git are refused.
Clone mode requires an explicit Git base or org and the same fixed commit.
Use `--force` for replacement; build/identity failures preserve the old installation.
The product lock's `verifyRuntime` must declare the same Git commit. New products
can select it with `dasops create --runtime-commit`; existing products must update
that declaration explicitly before installation. The wrapper checks the
installation record and never falls back to global Cadence. Replacement waits
for running local Cadence processes using the wrapper's shared guard. A backup
that cannot be restored remains at the recovery path printed by the installer.
`vendor/cadence` contains registry resources, legal files and the binary, not a
Git checkout or compiler/test sources, and is ignored by Git; retain the
selected source/commit in your product setup instructions and recreate it in CI.

Cadence host-local stays `mode=host-launcher`; non-host profiles use `mode=runtime-exec` and fail closed unless `CADENCE_SANDBOX_CONTAINER_ADAPTER` or `CADENCE_SANDBOX_MICROVM_ADAPTER` returns verified runtime proof.
