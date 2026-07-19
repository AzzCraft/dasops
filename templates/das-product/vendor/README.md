# Vendor folder

Use this folder for pinned third-party dependencies that are part of your build and verification.

Recommended path for Cadence:

`vendor/cadence/`

The canonical DAS standard entry remains `STANDARD_REF.md`; do not vendor or
copy a local `docs/standards/DAS_STANDARD.md` into this folder.

Install helper:

- `./scripts/install_cadence_vendor.sh --from-suite <release-root>/das-suite --tier oss`
- `./scripts/install_cadence_vendor.sh --tier oss --git-base https://github.com/<org>`

Release-package local mode copies only the public sibling module
`<release-root>/cadence-oss`.

Clone mode is fail-closed: pass `--git-base`, `--org`, or set
`DAS_SUITE_GIT_BASE`.

Cadence host-local stays `mode=host-launcher`; non-host profiles use `mode=runtime-exec` and fail closed unless `CADENCE_SANDBOX_CONTAINER_ADAPTER` or `CADENCE_SANDBOX_MICROVM_ADAPTER` returns verified runtime proof.
