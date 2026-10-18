# Third Party Notices

This file is the canonical notice bundle for the v1.0.0 commercial GA. It is generated from repository `LICENSE`, `NOTICE`, lockfile, and SBOM inputs by `scripts/legal/generate_notices.sh`.

## Included Notices

| Component | Source | License | Notice action |
| --- | --- | --- | --- |
| Python standard library | CPython runtime | PSF-2.0 | Referenced by runtime distribution documentation. |
| Go toolchain libraries | Go modules in cadence-core | BSD-style and Apache-compatible | Captured through Go module metadata and release SBOM. |
| Node tooling | Extension and integration build tooling | MIT, ISC, Apache-compatible | Captured through package metadata and release SBOM. |
| DAS repositories | First-party source | Apache-2.0, AGPL-3.0, proprietary | Governed by the license matrix and per-repository license files. |
| DAS Standard Master Doc / UI Spec test samples | [Public Standard source](https://github.com/AzzCraft/das-standard/tree/c9e959e15686d0e9c5243e6bcc10401ceb56e13f/appendices) | [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/) | Copyright 2026 AzzCraft Inc.; source/sample hashes and whitespace-only modification are recorded in `tests/fixtures/canonical-standard-templates/template_catalog.json`. |

Commercial release assembly must include this notice file, the generated SBOM, and the release truth pack. Dependencies with denied or unknown license decisions are release blockers.
