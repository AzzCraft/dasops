# DAS Tools v1.0.0 Threat Model

This threat model covers the CLI, private control plane, plugin/MCP integrations, CI templates, airgap installer, evidence storage, update channel, and support bundle workflow.

## STRIDE Coverage

| Area | Spoofing | Tampering | Repudiation | Information disclosure | Denial of service | Elevation of privilege |
| --- | --- | --- | --- | --- | --- | --- |
| CLI and local verifier | Signed closure and release metadata | Canonical hashes and EvidenceBundle verification | Local audit event IDs | Redaction policy for logs and support | Offline mode and bounded replay | No shell execution through MCP read tools |
| Control plane | Signed license and OIDC SSO | Append-only audit chain | Tenant-scoped audit export | Support bundle redaction | Rate limits and quota ledger | RBAC policy and approval gates |
| Plugins and MCP | Signed plugin manifests | Registry trust index and revocation | Every tool call emits an audit event | SecretStorage and no plaintext token logging | Per-tool timeout and sandbox profile | Write tools require simulation, approval, and lock token |
| CI and release | SLSA provenance and artifact signatures | SHA256SUMS and release truth pack | CI logs attached to evidence index | SBOM and notices omit customer data | Hermetic fixtures and mirror mode | Release jobs run least-privilege tokens |
| Airgap and updates | TUF root and target roles | Snapshot and timestamp metadata | Installer audit log | No outbound telemetry by default | Offline retryable installer stages | KMS or Vault for release keys |

The release gate fails closed when signatures, provenance, license policy, audit chain, evidence index, or task coverage checks do not pass.

## Finite candidate HTTP acquisition reference

`dasops.protected.candidates.http_reference.receive_candidate_http` receives a
pinned artifact through an installation-provided, already-connected HTTP(S)
connection and then calls the existing complete `CandidateStore.receive`.
The installation selects/authenticates the origin, request target, expected
content encoding and full HTTP representation SHA-256 independently of the
response. Worker inputs and response Digest headers do not approve those pins.
HTTP content bytes, decoded archive bytes and archive-expanded files retain
their separate approved identities; storing an object grants no write authority
or task qualification.

The reference accepts complete Content-Length-framed 200 responses, or a 206
finishing an approved prefix with the exact strong ETag and Content-Range.
A 200 after Range starts a whole new object. Prefix plus incoming content,
bounded decoding and atomic store publication share the installed byte/time
limits of this call. The caller remains responsible for cumulative budgets
across separate calls and current task/source authorization. The connection is
closed on success or refusal; there is no redirect, URL discovery or cache.
304, chunked responses, required trailers and other content encodings refuse
before publication. TLS/origin deployment approval, full cache/trailer adapters
and final installed reference qualification require their own evidence; local
loopback tests do not provide it.
