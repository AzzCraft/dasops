# Bootstrap authority driver upgrade

The beta development driver retains `bootstrap-cli-invocation/v1` and the
existing signed authority records. Its constructor and acceptance policy have
changed. This page describes the Python driver integration; it does not enable
a production service or qualify a deployment.

## Install identity bindings before restarting

`BootstrapAuthorityDriver` now requires `peer_actors`, a mapping from each
allowed host UID to its independently installed actor identity. Its keys must
equal `allowed_peer_uids`; empty allowlists, missing bindings and extra bindings
are rejected. Omitting the new argument fails construction rather than trusting
the request's `owner` field.

The service reads the connected Unix peer through Linux `SO_PEERCRED`. Both the
installed UID binding and the existing `(changeId, taskId, owner, registryId)`
subject allowlist must match. Keep the socket, registry roots, verifier,
handlers and configuration outside the candidate's write authority. Several
actors sharing one UID cannot establish independent identities through this
mapping; use distinct protected principals and explicitly approved topology.

Upgrade the existing installation as follows:

1. Drain in-flight calls and retain their original operation identities and
   records. A timeout requires reconciliation, not an automatic new operation.
2. Through the independent administrative channel, resolve actual host UIDs and
   approved actor names. Do not derive this map from an invocation, candidate
   configuration, account display label or `os.getuid()` fallback.
3. Supply the complete map with the existing pinned authority verifier,
   operation handlers, registry-root and subject allowlists. The service owner
   supplies these arguments; the request cannot select Python callbacks.
4. Reconnect using each approved peer. Verify a legitimate operation against a
   controlled resource; then verify a mismatched `owner`, disallowed UID,
   subject and registry root fail before a handler runs.
5. Confirm the service's socket ownership and routing. Retain the old records
   for their original contract; do not rewrite them with invented actor facts.

The corresponding construction has this shape; the values must come from the
installed configuration, not from the request:

```python
driver = BootstrapAuthorityDriver(
    authority_verifier=installed_verifier,
    handlers=installed_handlers,
    allowed_peer_uids=installed_peer_actors.keys(),
    peer_actors=installed_peer_actors,
    allowed_registry_roots=installed_registry_roots,
    allowed_subjects=installed_subjects,
    trusted_clock=installed_clock,
)
```

## Time and transport acceptance

The client still sends matching `requestedAt` and `effectiveAt` fields, but
these fields do not set verification time. The service obtains a timezone-aware
UTC time from its installed clock and requires the request time to be within
30 seconds in either direction, including the endpoints. Signature, root and
operation checks use that server time; handlers receive the same verified time.
Historical requests outside this window require a fresh authorized request and
reconciliation of the original action, never backdating the service clock.

Without an injected clock, the development driver uses the host UTC clock. It
refuses observed clock rollback within the process. This in-memory floor does
not survive restart or backup restoration. Persistent trusted-time / recovery
epoch handling remains an activation prerequisite; successful source tests do
not establish it. Synchronize approved clocks before serving requests; a naive
datetime or unavailable trusted clock must fail closed.

The Linux IPC reference accepts one bounded frame with at most 4,194,304 payload
bytes. Connection transfers share one `CLOCK_BOOTTIME` deadline of at most
30 seconds; partial reads do not renew it. A denied peer's connection is shut
down even if an alias to its descriptor remains open. Truncation, timeout and
lost responses do not prove a resource action did not commit. Use the original
operation records and an independent resource observation before retrying.

## Verification and remaining activation work

Source checks live in `tests/bootstrap/test_authority_driver.py` and
`tests/bootstrap/test_ipc_bounds.py`, with legal handler tests in
`test_operation_handlers.py`. Run them with real Unix sockets; sandbox skips
are not upgrade evidence. The existing constructor call sites in those tests
show the new arguments, but their fixture identities are not deployment owners.

Before activation, complete independently installed ownership, persistent
revocation/time state, old-writer fencing and the approved support matrix.
Preserve the exact peer binding during migration; no compatibility switch may
restore trust in a caller-supplied owner or time.
