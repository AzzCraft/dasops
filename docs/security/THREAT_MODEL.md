# DASOps OSS Threat Model

Scope: the public source CLI/GUI, generated legacy product files and protected
reference libraries. This distribution does not implement a hosted identity,
tenant RBAC, billing, TUF-update, airgap or universal support-redaction platform.

| Boundary | Actual control and limitation |
|---|---|
| Factory vs product | Explicit output directory; overwriting remains an operator action |
| Cooperative task state | One worktree's change guard and fixed-pair recovery; malicious/manual writers and separate clones are outside that protocol |
| Verification gates | Commands run without a shell, outside the state mutex; identity/token/gate is rechecked before completion |
| Protected operations | Current installed authorization, exact candidates, SQLite CAS/budgets and original receipts; installation must protect its authority and evidence |
| Candidate execution | Use the selected real restricted runtime; host-local diagnostics do not establish isolation |
| Evidence and exports | Exact hashes/signatures have their stated purpose; no automatic redaction or authenticated approval from self-reported metadata |

Untrusted candidates, external inputs and arbitrary local files do not supply
trusted policy or approval. Synthetic TEST identities are not installation trust
roots. See the [candidate boundaries](../../dasops/protected/candidates/README.md)
and [data handling](DATA_BOUNDARY.md). Actual deployment permissions, identities,
key custody and incident response belong to the installing operator. Existing
source CI does not prove a whole production deployment.

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
