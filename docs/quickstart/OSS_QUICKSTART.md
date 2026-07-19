# DAS-03-016 - dasops OSS Quickstart

1. Build or install the local wheel with `python3 -m pip wheel . --no-deps -w dist` and `python3 -m pip install dist/dasops-*.whl`.
2. Use `python3 -m dasops create --dest <repo> --master-doc <master_doc> --ui-spec <ui_spec>` to scaffold a new OSS product repo from the packaged `templates/das-product/`.
3. Use `python3 -m dasops new-change --id <change-id> --intent <intent> --repo-root <repo>` to create an OpenSpec change from the installed CLI.
4. Confirm the generated repo contains `cadence.yaml`, `tooling_lock.json`, and `scripts/verify`.
5. Run `./scripts/verify` from the generated product root and keep the resulting verification output with the change record.
6. If adopting an existing repo, run the adopt audit path first and repair missing governance or repo-shape files before verifying.
7. Register the verification output and repo bootstrap metadata in the same evidence bundle used for the product change.

The OSS path is fail-closed: missing required files, broken verify scripts, or unresolved repo-shape drift must block release preparation.
