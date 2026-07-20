# Product Repository Verify Policy

Generated product repositories fail closed on missing baseline documents,
invalid task-lock structure, stale in-progress locks, and malformed task-index
rows. They also reject copied standard text and stray `tasks.md` files.

The v1.0 template is standalone. A tooling lock, local extension manifest, or
Cadence configuration is not required and must not be fabricated merely to
make verification pass.

CLI help, product-template documentation, and verification scripts describe
the same supported standalone behavior.
