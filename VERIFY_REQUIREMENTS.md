# Verify Requirements — dasops

```bash
./scripts/verify
```

## Prerequisites

- `python3` on PATH (3.10+)
- `bash` on PATH
- `git` on PATH
- Linux with `/usr/bin/bwrap` (the `bubblewrap` package), sealed memfd execution
  and enabled unprivileged user namespaces for the protected-launcher tests.
  A missing sandbox is a setup failure; those tests must retain real isolation.

The hosted verify and release jobs prepare these Linux test prerequisites.
Their user-namespace setting applies only to disposable CI runners. For local
verification, use a Linux host already configured for the launcher tests.
Canonical-template tests use the two pinned public Standard samples in
`tests/fixtures/canonical-standard-templates/template_catalog.json`; they do not
require a neighboring Standard checkout. The catalog records public provenance
and the exact sample hashes. Refresh these test samples deliberately when their
intended upstream version changes; they are not runtime template authors.

## What verify checks

1. Unit tests pass.
2. Product-repo template integrity.
3. Governed launcher surfaces use `python3`.
