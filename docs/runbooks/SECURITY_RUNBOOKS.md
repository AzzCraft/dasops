# Security Runbooks

## Secret Exposure

1. Stop distribution of the affected release artifact or support packet.
2. Run `das-suite/scripts/security/secret_scan.sh` over source, docs, fixtures, and release bundles.
3. Rotate the exposed credential through the owning provider.
4. Add a redaction regression fixture and attach the scan report to the evidence index.

## Signing Key Rotation

1. Generate the replacement key in the approved KMS or Vault namespace.
2. Publish new TUF root metadata with old and new keys during the overlap period.
3. Re-sign release checksums, provenance, and offline bundle manifests.
4. Run `das-suite/scripts/release/verify_signatures.sh` from a clean checkout.

## Vulnerability Response

1. Run OSV and image scans with `scripts/security/osv_scan.sh` and `scripts/security/image_scan.sh`.
2. Classify findings by exploitability, affected profile, and customer exposure.
3. Ship a patched artifact with SBOM, SLSA provenance, and customer release note.
4. Preserve the advisory, waiver, and remediation evidence for the configured retention period.

## Evidence Leakage

1. Revoke access to the shared evidence location.
2. Run `tools/security/check_redaction.py` against the exported packet.
3. Produce a replacement packet with redacted logs, paths, and license state.
4. Notify affected customers through the support channel defined in `docs/support/SUPPORT_PACKAGES.md`.

## Malicious Plugin

1. Remove the plugin from the trust index or mark it revoked.
2. Disable write tools for tenants that installed the plugin.
3. Export audit events for tool calls, approvals, and evidence access.
4. Require a patched signed manifest before the plugin can re-enter the registry.
