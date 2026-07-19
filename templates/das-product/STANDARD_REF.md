# DAS Standard Reference

This product repo does not vendor a writable copy of the DAS standard.

Canonical source of truth:

- Repo: `das-standard`
- Primary artifacts:
  - `standard_manifest.json`
  - `release_snapshot_manifest.json`
  - `SPECIFICATION.md`

Consumption rules:

- Treat `das-standard` as the only writable standard authority.
- Use `tooling_lock.json` and suite closure artifacts to pin the exact standard, runtime, and toolchain versions consumed by this repo.
- If you need local deviations, record them in `local_extension_manifest.json` rather than editing the standard.
