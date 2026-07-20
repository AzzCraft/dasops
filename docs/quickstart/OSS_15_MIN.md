# OSS 15 Minute Quickstart

From a dasops checkout with Python 3.10 or newer:

```bash
python3 -m pip install .
dasops create --dest /tmp/das-demo-product \
  --master-doc templates/das-product/docs/master_doc.md \
  --ui-spec templates/das-product/docs/ui_spec.md \
  --change-id initial --intent "DAS demo bootstrap"
cd /tmp/das-demo-product
bash scripts/verify
dasops new-change --id follow-up --intent "Example follow-up"
```

This verifies the public standalone factory path. It does not claim Cadence
replay, suite evidence indexing, or a hosted release workflow.
