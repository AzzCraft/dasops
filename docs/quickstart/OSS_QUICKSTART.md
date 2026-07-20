# dasops OSS Quickstart

```bash
python3 -m pip install .
dasops create --dest ../product --master-doc /path/to/master_doc.md --ui-spec /path/to/ui_spec.md
cd ../product
bash scripts/verify
```

Create and manage a change with `dasops new-change`, `dasops claim-ready`, and
`dasops complete-task`. The generated product is a standalone baseline; its
owner must add any future suite or Cadence integration as a complete,
independently verified closure.
