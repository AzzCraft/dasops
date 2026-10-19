# Security Runbooks

These instructions cover the public DASOps CLI and its reference libraries.
Run DASOps commands in the affected product checkout; run `bash scripts/verify`
in a DASOps source checkout only when checking the tool itself.

## Exposed credentials or evidence

Stop distributing the affected bytes and revoke access to the export location.
Rotate real credentials through their owning provider. Preserve an access-controlled
original and its SHA-256 for investigation; prepare a separate reviewed display copy.
This repository does not ship a universal secret scanner, export redactor or support
upload service. Inspect source snippets, logs, paths, configuration and URLs before
sharing. Do not describe a manually reviewed export as automatically sanitized.

## Signing or authorization incident

Stop affected protected operations through the installation's configured authority.
Revoke compromised subjects/keys with that authority and retain original receipts.
Follow the selected component's actual signing policy and `docs/RELEASE_PROCESS.md`
for a replacement release. This CLI does not publish TUF metadata or provision
KMS/Vault keys. A registered key and mathematically valid signature do not prove
current approval, hardware custody or the historical execution source.

## Vulnerability or malicious input

Record the affected version, entry point, fixed input and actual refusal or failure.
Use `dasops doctor` for its human-readable diagnostics, then reproduce the
specific path in an owned test directory. Existing source `bash scripts/verify`
checks the component's declared gates; it is not a universal image or OSV scanner.
After a fix, retain the old failure and new exact-input result. Revoke a malicious
plugin in the installation's real trust policy; do not claim this CLI administers
a tenant control plane. Public support contact and limits are in
[`SUPPORT_PACKAGES.md`](../support/SUPPORT_PACKAGES.md).
