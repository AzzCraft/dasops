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
- This standalone scaffold does not declare a suite/runtime closure. Materialize
  governed closure artifacts only when the repository owner supplies real,
  immutable references that validate against the applicable standard schema.
- Record an approved local deviation only when it actually exists; do not add a
  placeholder extension manifest to a new product repository.
