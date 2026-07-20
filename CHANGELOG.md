# Changelog

## v1.0.0 — 2026-04-08

- Split the monolithic factory core into dedicated repo-factory, task, lock, doctor, adopt, and vendor modules.
- Added structured YAML task locks and the `dasops lock-status` CLI surface.
- Reseeded the product template to use `STANDARD_REF.md`, `tooling_lock.json`, and `local_extension_manifest.json`.
- Standardized the public Cadence vendor installer on named flags and the `vendor/cadence/cadence-oss` path.
- Replaced placeholder template sub-verifies with explicit fail-closed skeletons.
