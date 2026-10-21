# Third Party Notices

This notice applies to the public DASOps source and package identified by
`VERSION`. Maintain it with `LICENSE`, `NOTICE`, the package dependency declarations
in `pyproject.toml` / `setup.py`, and the applicable distribution inventory.
It is a maintained source file; no notice-generation command is shipped here.

## Included source and sample material

DASOps first-party code is licensed as stated in [LICENSE](LICENSE); required
attribution is in [NOTICE](NOTICE). The Standard test samples retain their own
attribution and license below, rather than being relicensed as tool code.

| Component | Source | License | Notice action |
| --- | --- | --- | --- |
| DAS Standard Master Doc / UI Spec test samples | [Public Standard source](https://github.com/AzzCraft/das-standard/tree/c9e959e15686d0e9c5243e6bcc10401ceb56e13f/appendices) | [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/) | Copyright 2026 AzzCraft Inc.; source/sample hashes and whitespace-only modification are recorded in `tests/fixtures/canonical-standard-templates/template_catalog.json`. |

## Dependencies and other components

The Python package declares PyYAML, jsonschema, rfc3339-validator and rfc8785 as
runtime dependencies. They are separately installed distributions, not copied
into DASOps source by this package. Keep their distribution licenses/notices when
redistributing an environment or an archive that actually includes them; use the
corresponding lock and SBOM for the exact included versions and transitive set.
Python itself retains the notices in its runtime distribution.

Cadence, Node tooling and optional GUI dependencies are separate components or
optional installations. Their own source/package notices apply if included in a
particular assembled distribution. This file does not claim a commercial GA,
relicense those projects, or require a private release system for this public
source repository.
