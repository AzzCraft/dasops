# Adopting an Existing Repository

`audit-repo` is read-only. `adopt-repo` adds only safe missing baseline files;
it never overwrites owner content or chooses a product license.

```bash
python3 -m dasops audit-repo /path/to/repo --json
python3 -m dasops adopt-repo /path/to/repo --json
python3 -m dasops normalize-repo /path/to/repo --json
python3 -m dasops trace-check /path/to/repo --json
bash /path/to/repo/scripts/verify
```

Adoption can create `openspec/changes`, a fail-closed `scripts/verify`, build
and verify requirement stubs, NOTICE, and an `UNLICENSED` marker. Before any
distribution, the repository owner must replace that marker with an approved
license and complete the repository-specific documents. The JSON adoption
evidence records this human gate.

`normalize-repo` also rewrites known stale standard links. It does not add a
Cadence configuration or any suite closure artifacts.
