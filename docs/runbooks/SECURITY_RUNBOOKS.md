# Security Runbooks

## Suspected secret exposure

1. Stop sharing the affected repository revision or archive.
2. Remove the credential from the source history according to the owner's
   incident process and rotate it with its issuing provider.
3. Run `bash scripts/verify --full` and review the changed files before a new
   release decision.

## Vulnerability report

Follow [SECURITY.md](../../SECURITY.md). Do not disclose exploit details in a
public issue before the maintainers have acknowledged the report.
