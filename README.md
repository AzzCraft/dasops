# dasops

`dasops` is a Python 3.10+ command-line factory for standalone DAS/OpenSpec
product repositories. It creates a documented repository baseline, change
folders, and task locks; it does not publish, host, or operate product code.

## Install and verify

```bash
git clone https://github.com/AzzCraft/dasops.git
cd dasops
python3 -m pip install .
bash scripts/verify --full
```

## Create a product repository

Keep the factory and product directories separate.

```bash
dasops create \
  --dest ../my-product \
  --master-doc /path/to/master_doc.md \
  --ui-spec /path/to/ui_spec.md \
  --change-id initial \
  --intent "Initial bootstrap"
cd ../my-product
bash scripts/verify
```

The v1.0 scaffold is intentionally standalone. It does not invent a
Cadence/suite closure, a tooling lock, or a local-extension manifest. Add
those governed artifacts only when their owner supplies real immutable,
schema-valid references.

## Multi-worker flow

```bash
dasops claim-ready --change-id initial --owner worker01
dasops lock-status --change-id initial --task-id T-001 --json
dasops complete-task --change-id initial --task-id T-001 --owner worker01
```

Run `dasops doctor --repo-root .` before work and `bash scripts/verify --full`
before a release decision.
