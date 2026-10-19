# Candidate reception and version-tree staging

## Controlled whole-file template adoption

The installer can attach `dasops.adopt.GovernedAdoption` to the existing
`GovernDriver(adoption=...)`. It fixes one native resolver, a destination-to-docType
mapping and the sorted C-to-I source selection. The authenticated `govern plan`
operation verifies received I against actual B/C and the installed selection;
this preflight is read-only. The trusted service can call `prepare()` before
independent verification to compose I in the immutable artifact store.
It checks `canonical_full` entries against their complete pinned author bytes.
For Appendix M `minimal_governed` entries, it extracts exactly the catalog's
section and replaces every angle-bracket placeholder with explicit literal
values installed in `template_values`. Missing/extra/empty values, unresolved
placeholders, ambiguous anchors and multiline metadata reject. No template code
executes; body values may preserve multiline project text. Copying the whole
shared appendix cannot satisfy a PRD/runbook destination. Pack generation is
outside candidate trees, avoiding a candidate/Bundle/Pack digest cycle.

For example, the trusted service may install:

```python
adoption = GovernedAdoption(resolver,
    templates={'tree/docs/ui_spec.md': 'ui_spec'},
    source_paths=['tree/docs/ui_spec.md'])
driver = GovernDriver(adoption=adoption, ...)  # other installed dependencies required
```

The same installer-fixed `source_paths` may include `materials/dependency`,
using the existing flat material-ID contract. Template destinations remain
`tree/` files from the pinned Standard; a supporting material is not a template.
All selected paths must be sorted and unique. For example, selecting
`['materials/dependency', 'tree/docs/ui_spec.md']` replaces that received
dependency from C while retaining unselected B materials. The existing
integration plan must bind its exact `mode=data`, size and SHA256 pre/postimage,
installed ownership, native verification and purpose-specific authorization.
There is no implicit dependency fetch, local pathname or permission to execute
an installer. CandidateStore maps the selected bytes into the read-only
`.das-external-materials/<id>` execution view; its mapping and actual native
snapshot belong in the original verification evidence.

For a PRD, the installed service can use `templates={'tree/docs/prd.md': 'prd'}`
with `source_paths=['tree/docs/prd.md']` and `template_values` keyed by that exact
destination. The inner mapping supplies all nine markers in the pinned PRD
section: `stable-prd-id`, `owner`, `YYYY-MM-DD`, `product or capability scope`,
`repo-relative canonical Master Doc path`, `outcomes`, `explicit exclusions`,
`primary user or operator workflows`, and `testable completion criteria`.
`render_section_template(author, source_bytes, values)` prepares the proposed
bytes; it grants no trust to its inputs. `prepare()` independently reloads and
checks the physically pinned Standard author and installed values before use.
Both mappings are copied and read-only. Context Packs cannot be template destinations.

For `master_doc` or `ui_spec`, omit `template_values` to retain the exact full
author copy. To fill project fields, supply explicit values at the same installed
destination, for example:

```python
template_values = {'tree/docs/master_doc.md': {
    'DOC_ID': 'MASTER-existing-project', 'OWNER': 'project-owner',
    'STATUS': 'draft', 'PROJECT_NAME': 'Existing project',
    'USER_OUTCOME': 'Approved existing project outcome.\nSecond line stays.',
}}
```

`render_full_template(author, source_bytes, values)` replaces only the named
`{{required}}` / `[[optional]]` prose/table fields in the pinned full author.
Unknown, empty, NUL or whole unfilled placeholder values reject. Fenced examples,
HTML anchors and inserted values remain literal. Document Control metadata must
occupy one line; a project outcome bullet can contain approved multiline prose.
Drafts can retain unfilled fields. `STATUS=active` requires all required prose
fields filled and an exact status token; it does not prove approval, contracts,
HFVI/Context Pack readiness or any other normative active-document condition.
Each destination accepts at most256 explicit fields and64KiB of values; rendered
authors are bounded to64KiB. No automatic extraction/merge of old local documents
is performed. The installer must approve preserved fields/content and any change.

The example is service configuration, not a client-selected backend or a complete
deployment. The service's `NativeQualification` must use that same resolver and
its independently verified adoption Bundle. Submit C with the existing receiver;
prepare/submit the exact integration plan through authenticated `govern plan`;
then use ordinary integrate/complete and `inspect(view=context-pack)`. Neither
`prepare()` nor a Pack authorizes a write or completes a task. Native action
grants, qualification, ownership, budgets, CAS and unique Completion remain
mandatory. Unselected B files are retained. A selected document is an explicitly
approved whole-file change, with exact before/after images; this profile does not
silently merge local edits. Preserve required existing fields/body in the proposed
values or obtain explicit approval for their change. Concurrent later edits
require replanning. Preparation recomputes reading input
without replacing the action's exact native preparation, and checks target/Task
before and after composition/resolution. Concurrent changes require replanning.

The actual template consumer is tested with real native execution, authenticated
IPC/CLI, a preserved local file, refusal inputs, two independent SQLite writer
races and original-receipt recovery. These are development TEST controls; full
template kinds/variants and installed deployment qualification remain part of beta
closeout. For a compensation plan the same installed adoption adapter also accepts
`das-version-tree-plan/v1` with a retained non-null `rollbackOf`. It checks the
current epoch/target, the original forward receipt and the complete historical
snapshot identity, then recomputes the newly approved candidate/baseline Bundle.
It does not apply the current template over the historical snapshot. The ordinary
version manager still requires a current compensation Task/lease, separately
signed rollback verification/Decision/grants, budget and final CAS. An ordinary
version apply cannot bypass the integration-only template path. This does not
reopen or erase the original Task/Completion and is not deployment qualification.

## Preapproved analysis Completion (original A01.2)

The analysis path uses the existing `complete` operation in `GovernDriver` and the
same SQLite Completion key. It is not an integration waiver. Before any lease
claim, the installed control plane calls `add_task(..., analysis_binding=...)`.
The exact `das-analysis-task-binding/v1` object fixes the task key, revision,
cycle, obligation, policy and analysis mode. Its `verificationScopeDigest`
hashes the plan's `planId`, `actions`, `slots`, `aggregation` and
`requireOverallSuccessForActions`; runtime bindings are excluded to avoid a
self-referential digest. The task-creation audit retains this approval. Legacy
tasks cannot acquire analysis mode later, and approval actors cannot claim the
analysis task they approved.

The authenticated `complete` request carries exactly `analysisPlan` and
`qualificationRefs` as parameters. The separately named analysis plan, signed
Evidence and signed Decision bind the immutable approval and actual C, B,
lineage, environment, inputs, resource instance and generation. Native Go checks
the original reports, fixed required slots, independent principal, all attempt
history and the complete purpose. Current native grants are checked before and
after evidence consumption within the existing total deadline. The public probe
and staging Completion remain `authority=false`, `qualification=false`.

`VersionTreeManager.complete_analysis` verifies the task/cycle, C and unchanged B
inside the existing writer transaction. Exact request retention, every budget
reservation, the confirmed native SQL effect, resource observation, unique
Completion and audit commit together. It performs no target switch or external
dispatch and creates no Integration Receipt. Repeated identical requests return
the original bytes and cost; changed requests or a conflicting completion reject.
An unresolved reserved/dispatched/unknown business action blocks completion.

After completion, `rework(..., analysis_binding=...)` requires the installed
`approve_analysis_rework` authorization as well as ordinary rework authorization.
It preserves mode/task/obligation/policy and approves the next cycle's check
scope before a claim. Omitting fresh approval allows ordinary rework but gives
no analysis-complete eligibility. Fresh C, grant, Evidence and Decision bind the
new cycle; old Decisions reject. Historical exact reads retain old bytes and
confer no current qualification. No table/schema-version migration is introduced.

Published local source checks are in `tests/protected/test_completion.py`,
`tests/protected/test_candidate_store.py` and `tests/protected/test_version_trees.py`.
These do not establish independent installed cross-component qualification or a
production signing service. Integration v1 identities and wire bytes remain
separate and unchanged.

`CandidateStore` receives fixed bytes;
`VersionTreeManager` prepares plans and switches a SQL reference to complete
trees. Neither library is an authenticated service, release acceptance runner,
integration qualifier, signer or installed beta deployment. Every mechanism
receipt sets `authority=false` and `qualification=false`. Existing protected v1
materialization/request digests and legacy readers are unchanged.

The single contract authors are Cadence Protocol's `schemas/das_v1_5/` files
`candidate_binding.schema.json`, `version_tree_plan.schema.json` and
`version_switch_receipt.schema.json`. Installed copies are generated. New JSON
uses the exact parser and RFC 8785 JCS, separate from the historical canonical
digest. Do not edit a generated copy or use these receipts as full signed Action
Receipts: native authorization references are retained in the original audit,
while final service admission and installed qualification remain unfinished.

## Prepare complete inputs

1. The control administrator installs one private candidate root, current policy,
   tool identity, per-file ownership/origin registry and authority DB. RPC bodies
   cannot choose the root or supply these dependencies. Keep Worker, candidate
   execution, driver, signer and state owner as separate actual principals at
   activation. A same-UID development test cannot establish their separation.
2. Open an already created, normalized absolute root with `CandidateStore`.
   Every path component opens with a directory handle and `O_NOFOLLOW`; the root
   must belong to the service UID and have no group/world access. The open inode
   is pinned and rechecked against the installed pathname before returning.
3. Select the complete required source/material closure under the approved Task.
   This receiver accepts **complete committed regular-file Git trees only**. It
   never scans, signs or implicitly includes a changing worktree. The future
   low-privilege importer must reject relevant dirty/untracked content, or first
   create an independently frozen approved source. A commit-only receive result
   cannot certify that no required worktree input was omitted.
4. Import untrusted Git objects/configuration in the separate low-privilege domain.
   This receiver invokes no Git command, hooks, filters, metadata backend, pytest
   discovery, package import or cleanup program. Do not run a host clone or
   checkout merely because the repository is owner controlled. The importer
   and its binding to the native runtime are still pending.
5. Supply the exact commit payload (Git `cat-file commit` bytes), object format,
   exact commit/tree OIDs and SHA-256 of that payload. The receiver reconstructs
   every blob and directory object and verifies the commit's root tree. Removing
   a test/config/file while retaining the old commit cannot pass tree closure.
6. List every source file in sorted order with path, regular Git mode, exact size,
   blob OID and content SHA-256. Only `100644` and `100755` are supported. Symlinks,
   gitlinks/submodules, special files and unexpanded LFS pointers reject this
   profile. Required submodules/LFS need their future explicit approved expansion
   mapping; rejection does not remove that obligation from beta scope.
7. Paths use strict UTF-8/NFC, normalized relative POSIX segments. Traversal,
   control characters, backslashes, colon, `.git`, Windows device names, trailing
   dot/space, case aliases and file/directory conflicts reject the whole input.
   Files are never silently renamed. The same rules apply to external material IDs.
8. Supply a single USTAR archive containing exactly the declared regular files,
   with their declared modes and no implicit root prefix. PAX/GNU extensions,
   directory/link/device members, base-256 sizes and unsupported formats reject.
   Source `.gitattributes` remains a literal input: export-ignore/subst is not
   applied. A separate approved release export may filter files later, with its
   own explicit source/output mapping.
9. `tar-ustar` identifies raw uncompressed bytes. `gzip-tar-ustar` identifies one
   complete gzip member. Pin **both** raw and decoded SHA-256; concatenated
   members, ignored trailers, bad CRC/ISIZE and incomplete EOF reject. USTAR
   checks each header, size, zero padding and two-block termination, and allows
   only zero record padding after it. No member rejection is downgraded to a skip.
10. Pin actual dependency/model/prompt/preprocessing/build-input bytes as external
    materials with unique ordered IDs, role, media type, size and SHA-256. Pass
    exactly that ID-to-bytes set. URLs, moving branches or package names alone
    are insufficient. The receiver does not recursively decode these blobs; a
    consuming adapter must obtain any additional format/expansion qualification.
11. Use installed limits, never candidate-requested overrides. The wire ceiling
    is 2048 source files, 64 external materials, 16 MiB per file/material, 64 MiB
    total material bytes, 80 MiB each raw/decoded archive and 1 MiB manifest.
    Paths have at most 16 segments and 240 UTF-8 bytes. Smaller local limits are
    supported. Security counters validate exact numbers before JCS conversion.
12. A cumulative Linux CLOCK_BOOTTIME deadline covers decode, inventory, writes
    and readback. This synchronous library detects expiry between operations;
    it cannot preempt a stalled kernel filesystem call. The installed supervisor
    must enforce the outer resource/time boundary. This is not a runtime adapter.

## Store and reconcile publication

13. Call `receive(binding_bytes, commit_bytes=..., archive_bytes=...,
    external_materials=...)`. Its digest is SHA-256 of the entire canonical
    binding; Task, revision/cycle, obligation, policy, commit, archive byte domains,
    file modes and all external bytes therefore participate. Future validation,
    integration and Completion fields are forbidden in the closed binding.
14. The store validates all input before creating `.pending-<random>` in the fixed
    root. It writes only exclusive/no-follow regular files through directory
    handles. Layout is `binding.json`, `commit.bin`, `archive.bin`, `tree/` and
    `materials/`. Raw archive/commit bytes are retained alongside the materialized
    view. There is no caller-controlled destination or privileged output FD.
15. File bytes/modes and every parent directory synchronize before Linux
    `renameat2(RENAME_NOREPLACE)` publishes the whole tree under the digest. The
    storage root then synchronizes. Even an empty competing directory cannot be
    replaced. Missing native support causes failure, not a check/rename fallback.
16. All files use `0400` (`0500` for executable source files); tree directories
    use `0500`. These modes reduce mistakes and permit drift detection. They
    alone do not prove immutability against the same UID, root, existing writable
    handles, writable submounts or directory replacement. Activation must prove
    those actual boundaries; ordinary editable workspaces are never apply targets.
17. `verify(candidate_digest)` rereads exact control/raw/materialized inventories,
    sizes, modes, links and digests. The name or cached receipt cannot substitute
    for the content. Root/tree replacement, alias/link injection, missing bytes,
    extra files or content drift rejects consumption and preserves the objects.
    Directory versions and parent-relative inode checks reject entries added or
    replaced after enumeration. Publication rereads the final named object before
    returning success, including when a competing receiver published it.
18. Before a new DB reference, `confirm_for_registration` performs complete
    verification, synchronizes stored files/directories/root again and rechecks
    the identity. `register_candidate` invokes this inside its authorized DB
    transaction. A sync failure returns no successful registration; retries
    reconcile the same digest. Never reconstruct different bytes under it.
19. Interrupted stages stay `.pending-*`, never valid references. A name published
    before an API/root-sync failure may be reconciled by exact readback and sync.
    Existing verified objects are reused without accumulating duplicate stages.
    Competing race stages and failures remain available for controlled recovery;
    this code runs no arbitrary recursive cleanup. Disposal needs the future
    installed recovery/retention policy and proof that no active writer remains.

## Plan, switch and rollback

20. Construct `VersionTreeManager` with the same `CoordinationDatabase`, candidate
    store, exact policy/tool digests and a fixed mapping of `tree/<path>` or
    `materials/<id>` to `(owner, originDigest)`. Only trusted installed code supplies
    the mapping. Register complete candidates against the current approved Task
    obligation/revision/cycle/policy, then install a resource ID/instance once.
21. Call `create_plan` with the exact current target generation and after-candidate
    digest. Every changed file records preimage/postimage mode, size, SHA-256,
    owner and origin; each deletion requires an explicit nonempty reason.
    Unknown ownership or unrelated deletion reasons reject the whole transaction.
    Planning changes no target files/reference. Plans persist as immutable JCS.
22. Reserve a `das-resource-action-intent/v1` through the durable outbox. Parameters
    for this resource are exactly `{"planDigest": "sha256:..."}`. Commit the
    original dispatch intent **before** calling the resource point. The current
    service-authenticated actor, trusted time, authorization/fencing predicate and
    resource instance must be supplied by the installed service, not the candidate.
23. `switch` supports legacy apply/rollback and a separately qualified integrate
    plan. It rechecks the original intent, exact
    plan, current tool/policy/task, parent, actual candidate bytes, ownership and
    target generation inside `BEGIN IMMEDIATE`. The target reference CAS, next
    generation, exact native receipt and audit append commit together. A failed
    receipt/audit insert rolls back the CAS. No file in either tree is rewritten.

## Current integration and native evidence consumption

The unpublished integration path is part of the original T-009. It adds no
second database, outbox or Completion implementation. `create_integration_plan`
binds the current obligation, C, actual I, B/generation and the exact approved
verification plan/evidence/action Decision references. `switch(action=integrate)`
requires the installed qualification dependency again at the actual target CAS.
Without it the operation fails. Original apply receipts do not qualify integration.

Install `NativeQualification` from `qualification.py` with the exact Cadence
binary hash/version, a local current-control reader and `NativeActionAuthorization`
from `authorization.py`, then pass it as the
manager's predicate. The adapter seals the actual executable in an anonymous
descriptor and consumes the sole Go DSSE/qualification implementation. Requests
cannot select roots, control state, trust keys, executables or original stores.
The reader must obtain the complete collected run/attempt history independently,
including failed runs; do not derive its expected digest from the submitted
envelope. Original records use content digest **and** run ID/attempt, preserving
identical bytes from different genuine runs. Current context, source kind,
assertions/config/shard, original bytes and collection/termination evidence are
checked separately. The original report is retained unchanged. Only an approved
safe observation exception may be nonblocking; shared collection errors and an
explicit overall-success requirement still block.

For the current complete-mapping development bridge, install the same
`NativeBundleResolver` and its resolved `adoption_bundle` as fixed
`NativeQualification` dependencies. Set `verification_inputs` to the exact
Standard artifact, Bundle, approved facts, acceptance and environment digests.
Use `resolver.standard_artifact_digest`, `bundleDigest` and the approved-facts
digest for the first three; the actual
candidate/baseline must equal the manager's plan. Request fields cannot select
this resolver or replace these pins. The earlier explicit TEST profile uses
the raw installed snapshot digest. With installer-only `standard_archive` and
`standard_archive_sha256` supplied together, `standardDigest` binds the raw
distribution ZIP; `snapshot_sha256` separately pins the installed raw snapshot.
The flat data ZIP must contain exactly the snapshot and its declared regular
members, with matching bytes; only stored/deflate compression is supported.
No extraction, hook or network runs. Raw archive/member limits stay 4 MiB and
total members 32 MiB within the existing deadline. Links, duplicates, extra
members, encryption, changed content and wrong digest domains reject.
This finite TEST/reference content profile is not the public builder's
prefixed source tar, production signing or final distribution qualification.

Prepare outside the writer through the existing resolver. At each plan/CAS/
Completion predicate, the same transaction confirms current metadata, actor,
original signed facts, trust, policy, revocations, generations, scope/target,
validity and actual physical Standard bytes. Only three freshly checked
observation timestamps may differ. A loader write aborts and rolls back;
changed originals require a new native preparation outside the writer. The
resolver retains only its latest exact action preparation in memory; another preparation,
failure, unresolved result or close invalidates previous use. This single
preparation is neither durable authority nor a reusable approval. Confirmation,
grant and evidence share the original two-second total; do not rerun the whole
native catalog under a long writer lock or increase that limit. Keep derived
Context Pack bytes outside the candidate digest they cite. Protected template/
Context Pack replacement, all original variants and final deployment admission
remain separate unfinished exits.

The fixed current reference profile is all-attempts-pass with no reuse. Other
approved aggregation/reuse profiles, authenticated service installation, real
collector/signer/runtime separation and other integration transformations remain
unfinished. The public `contracts check-action --probe` accepts caller-selected
diagnostic context and returns no authority or qualification. Supplying a TEST
loader to the library does not establish a production control plane.

Install the grant consumer from the **same** exact native binary hash/version
and a fixed approved audience. Its trusted loader supplies exactly
`grantEnvelope`, `parentEnvelopes`, `trust`, `current`, `representedSubject`;
no supplied request is accepted. In the existing writer transaction the consumer
derives actor, task/revision/cycle, current lease generation/owner/expiry, current
resource instance/generation and original intent parameters independently.
The original child/parent DSSE grants must match all these fields, current epoch,
revocation/generation, exact action digest and budget. This reference profile
supports one grant budget root; multiple roots reject without weakening the
existing SQL shared-budget reservation. Independent approval excludes the
proposing actor's own key even if its installed role is misconfigured.

`NativeQualification(action_authorizer=...)` requires this dependency at
integrate/complete. Omitting it can prepare a verification-bound plan, but cannot
commit either effect. Both native checks share its original cumulative two-second
deadline. The trusted interval must cover the entire remaining consumption
window; the actual lease must outlive that interval. Trusted readers must perform
only bounded local reads, not signing, candidate execution, network access or
SQL writes. The deployment supervisor still enforces the outer runtime boundary.

The finite Unix driver also checks **read disclosure** at the actual send, after
socket backpressure. Inspect, current Context Pack, plan preview and original
audit recheck the installed current read policy/time and original subject before
each nonblocking send attempt. A prepared/cached response grants no later read
permission. Denial or unavailable authority closes the connection; bytes already
sent remain in flight. The same frame stays at most 4 MiB plus its eight-byte
header and within the original 30-second request/response deadline. Context Pack
rechecks current SQL/authorization without rerunning its native resolver for
each fragment; plan preview rechecks read scope/trees without minting another
qualification. Read snapshots reuse the existing owner-managed approval guard:
callbacks cannot commit/rollback, implicitly commit via executescript or change
the connection policy, even if they swallow the violation and return an older
allow decision. Violations fail as CoordinationError; no business SQL changes.
No writer is held while waiting for the peer. Write-operation
receipts keep their existing original-key recovery semantics. This is one bounded
Unix response, not a subscription, remote revocation-confirmation service or
signed-URL gateway. Trusted local `dispatch` returns data to its authorized
caller; subsequent publication is the caller's responsibility.

Integration grant `requestDigest` covers the exact retained intent. Completion
grant `requestDigest` covers action `complete`, the original intent digest, actual
integration receipt digest and complete qualification references; an integrate
grant cannot replace it. The manager appends checked grant IDs/generations,
independent principals/fingerprints, canonical envelope/parent digests and the
exact control/request digest to the existing audit chain in the SAME commit as
the target CAS or unique Completion. Denial or storage failure rolls back that
event; historical replay creates none. These are retained staging facts, not a
new public authority token or a substitute for the unfinished authenticated
service installation. The finite `contracts check-authorization --probe` command
also returns `authority=false`, `qualification=false` for supplied contexts.

After independently confirming the native integration receipt in the original
outbox, `complete_integration` requires a **complete** Decision bound to the
current I/generation and exact original integration receipt. It commits the
existing unique `(taskKey, cycle)` row and immutable native binding atomically.
An insert failure leaves confirmed integration intact for lookup-only recovery.
Authorized historical replay returns original completion bytes and creates no
new qualification, budget or business effect. Current source tests exercise
two writers and real process exits; they do not prove power-loss durability,
installed beta qualification or the original 136 product cases.

`compose_integration(B, C, source_paths=..., deleted_paths=..., tool_digest=...)`
prepares I in the same private candidate store. Select exact sorted paths under
`tree/` or `materials/`; deletions are explicit. The fixed whole-file profile
preserves every unselected B path, takes selected bytes/modes/material metadata
from C, rejects collisions/empty views/limits, and creates a deterministic Git
commit with B/C parents. It never executes Git, candidate hooks, merge drivers or
build code, and never modifies a target. Registration remains separately authorized.
Textual conflict resolution and arbitrary generated merge output are unsupported;
do not label this profile as supporting every merge/rebase workflow.

`integration_lineage` reconstructs the relationship from actual immutable B/C/I
bytes. The manager performs this at plan, integrate and complete; even an installed
TEST predicate cannot admit unrelated I. `NativeQualification` also compares its
semantic digest with the independently approved plan/evidence/Decision bindings.
Lineage alone grants no permission. Preserve its exact paths, unused source paths,
output inventory, tool/policy and input/output digests with the verification record.
This adds no backend, public exchange schema or second writer.

The adapter requires the trusted interval to cover the bounded native call and
checks real UTC/boot-time again afterwards. Installed clock uncertainty and the
complete service's time/fencing guarantee at its transaction linearization point
still require deployment qualification; TEST time records do not supply it.
24. The native receipt retains the stable action/request, before/after candidates
    and generations, executing actor, current authority epoch and trusted commit
    time. Response loss/process death is reconciled through `lookup` on the
    original resource/instance/action/business key. Same-key execution returns the
    original bytes; changed requests reject. Native absence alone does not prove
    the prior dispatch is terminated. Outbox reservations and unknown outcomes
    remain intact; no automatic redispatch, refund or Completion occurs.
25. `create_rollback_plan` needs the retained forward receipt and **both** its exact
    after-candidate and after-generation as current postimage. A subsequent A→B→A
    or user edit invalidates reuse, even if a hash matches again. Legal rollback
    switches to the prior verified tree at a new generation; it retains receipts,
    budgets, audit and prior generations. It does not roll back security state.
26. Use `read_target` to read an authorized reference after verifying its bytes.
    Consumers must use the protected reference/tree as one consistent snapshot;
    copying files into a live workspace does not inherit these CAS guarantees.
    No in-place apply/rollback endpoint exists. Foreign writers and existing
    writable handles in an ordinary user directory therefore retain their edits.

## Bridge to the native Python reference

27. `prepare_reference_view(candidate_digest)` is an installed-library operation
    after current purpose/read authorization; it is not an unauthenticated RPC.
    It requires a committed root `run.py` for the existing fixed Python profile.
    Unsupported entrypoints are rejected, not replaced with caller-supplied code.
28. Stored candidate files remain `0400`/`0500`. The new complete execution view
    copies the same bytes into a fresh child of the fixed private artifact root,
    with `0444` data, `0555` executable files and `0555` directories. That child can
    be mounted read-only for actual UID 65532 without making the original storage
    writable/readable to Worker. No original object is chmodded or replaced.
29. Source files map directly to their relative paths; every pinned external
    material maps to `.das-external-materials/<materialId>`. A source collision
    with this namespace rejects the whole view. The returned exact mapping records
    source/destination, byte SHA-256 and declared storage/execution modes, with its
    own JCS digest. No source/required material is silently omitted.
30. Readback, original candidate revalidation, all directory synchronization and
    atomic no-replace publication precede returning the fresh `.reference-*`
    view. Incomplete `.reference-pending-*` objects remain ineligible. This view
    is a derivative input, not a final package, approval or trusted build output.
    Readback rejects undeclared directories, including empty ones, and checks
    file/directory identities during traversal. A second readback opens the
    published name and verifies the full inventory. If publication/readback fails,
    retain the object but consume no view: a `.reference-*` name alone is never
    eligibility evidence. These observations do not prevent a later same-UID
    writer; installed mount/owner/handle exclusion remains required.
31. The installed native controller's own `snapshot` function binds the actual
    returned path and modes. Supply that fixed digest to `Controller.run`; keep
    engine/image/daemon config outside the candidate. The driver checks actual
    preparation, Worker UID/caps, namespaces/cgroup and whole-domain termination.
    Integrating this library into a formal govern service and final builder still
    requires authenticated topology, approved read scope and package identity.
32. The public source tests demonstrate their local library mechanisms only.
    Actual installed runtime/identity and whole-domain termination need separate
    evidence; a parent-workspace test path is not an executable public reference.

The staging SQL author has changed. An older unpublished staging DB fails its
author-digest check; there is no silent upgrade and no change to released protected
v1 data. Migration, authenticated govern deployment, final owner/mount/handle proofs,
OS importer/builder integration, approved material completeness, durable volume
fault evidence, actual C→I qualification, installed package acceptance and
publication remain separate conditions before claiming complete beta.1 qualification.

Run focused source checks from the dasops component:

```bash
python3 -B -m pytest -q -p no:cacheprovider \
  tests/protected/test_candidate_store.py tests/protected/test_version_trees.py \
  tests/protected/test_sqlite_coordination.py tests/protected/test_sqlite_outbox.py
```

These include independent Git plumbing, SHA-1/SHA-256 trees, real tar/gzip, native
no-replace filesystem publication, writer races, genuine deadline expiry, actual
process death on both sides of CAS COMMIT, response loss and sync/receipt faults.
Process faults do not simulate power loss. The frozen product-case IDs remain
not_run until the installed independent acceptance chain executes them.

## Authenticated finite govern entry

`GovernDriver` reuses Bootstrap's connected Unix stream authentication and
bounded framing. It starts no listener. The installed supervisor supplies a
connected fd; the kernel's SO_PEERCRED UID selects an installed actor. The
service installer fixes the full TaskKey allowlist, resource/instance, current
authorization/clock, manager factory and sealed native consumers. No request
selects a database, artifact root, binary, adapter, trust key or clock.

The reference exposes all eight original operations: `inspect`, plan creation/
preview, `apply`, complete-candidate registration through `submit`, `integrate`,
`complete`, `rollback` and `audit`.
Small complete candidates can be received through the existing submit frame,
as described below. Complete supported-input/deployment closure remains open;
larger transport is required only where that approved closure needs it.
Requests use the existing closed
`resource-action-intent/v1`, capped at 64 KiB. One thirty-second CLOCK_BOOTTIME
deadline covers the frame exchange; the native checks retain their original
shared two-second budget. The installed supervisor must also bound callbacks
and filesystem calls, which Python deadlines cannot preempt.

`integrate` consumes the already dispatched immutable intent at the original
SQL CAS. `complete` compares the ENTIRE request with the retained integration
intent, actual receipt/generation and complete qualification references inside
the same writer transaction, including historical replay. Changed cost,
budget, actor, task, scope or generation cannot be ignored as extra context.
The effect entry requires NativeQualification with NativeActionAuthorization and installed verification input pins; a
staging boolean predicate cannot enable it.

`submit` has two closed parameter forms. The existing
`{"candidateDigest":"sha256:..."}` registers an already fully received object.
For a small object not yet received, supply exactly `candidateDigest`, `binding`,
`commitBase64`, `archiveBase64` and `externalMaterials`. `binding` is the existing
complete Candidate Binding; its semantic digest must equal `candidateDigest`.
The two byte strings use canonical ASCII base64. `externalMaterials` maps every
declared materialId to its complete canonical base64 bytes, with no missing or
additional IDs. The entire original intent, including encoded materials and JSON
overhead, must fit the unchanged 64 KiB frame before decoding. This is not a
chunked uploader: larger objects need the still-open installed transport.
Neither form accepts a filesystem path, repository, executable, decoder or
caller-selected output root. Original nested counters are validated before JCS
rounding; a raw frame cannot bypass the client-side check.

The independently signed **submit** grant binds the entire intent, including all
inline bytes. Current approved Task/obligation/revision/cycle, installed
tool/policy, lease, epoch, target and shared-budget checks precede reception.
An integrate grant does not cover this action. After reserving and committing
the original dispatch, the existing CandidateStore reconstructs raw Git commit
and tree, checks the complete archive and external materials, and publishes with
its existing no-replace/fsync rules outside the SQL writer. The earlier outbox
deadline also bounds reception; a new receiver call cannot reset that budget.
Syntax and binding checks alone never establish physical material integrity.

The original outbox reserves the exact intent and budget once, commits dispatch,
then registers the complete candidate in the same existing authority DB. After
full readback/fsync, the actual registration rechecks current native authority
and the retained dispatched/unknown intent with its exact budget reservations;
an otherwise valid signed request cannot skip the outbox. Grant references and
registration commit together in the original audit. Denial/INSERT failure
leaves no successful registration authorization. Submission changes no target,
Integration Receipt or Completion; its result is the existing candidate binding.
If reception finishes but current authority is revoked before registration, the
complete store object can remain while SQL registration is refused. Do not
delete it as a refund, manufacture success from its presence, or retry an unknown
original dispatch. The original reservation and recovery rules below still apply.

Exact confirmed replay returns the original verified binding with no new budget
or registration audit. Dispatched/unknown recovery only looks up actual original
registration, never dispatches it again. Missing registration remains unknown;
it is not proof of execution closure. A confirmation lost after registration
can be reconciled without repeating the effect. Revocation can also deny
settlement, leaving dispatched unresolved; new current authority can record
unknown without refund or re-execution. Original IDs and budgets are preserved.

Ordinary `inspect` takes exactly `parameters={"candidateDigest":"sha256:..."}` and returns
the existing candidate binding only after actual target instance/generation,
full TaskKey/revision/cycle, installed tool/policy and current scoped read
authorization match. It needs no write activation. The client checks both the
semantic digest and complete requested subject, including when a valid response
hash accompanies another Task. The digest must be supplied from an independently
known target; this reference does not discover or adopt an arbitrary workspace.

For a current reading use the same authenticated `inspect` with exactly
`parameters={"candidateDigest":"sha256:...","view":"context-pack"}`. Its full
task/resource/generation/actor/tool/policy fields still bind the actual target.
The installed resolver and scope come from the native qualification configuration;
the caller cannot choose roots, loaders, baseline or scope. Baseline comes from
the verified receipt at the current generation (or the initial target).
Short SQL snapshots bracket native resolution and Context Pack rendering;
target, Task, epoch or read-authorization drift denies the response. Unknown
applicability remains in the reading obligations. The client checks the closed
Pack v2, its digest, current candidate and policy. The existing 4 MiB response
bound stays unchanged; only this explicit view uses the bounded catalog codec.
No SQL/budget/receipt/Completion, file or candidate changes occur. This reading
does not replace the resolver's action preparation, grant permissions or claim
protected template replacement. Missing installed read dependencies reject this
view while ordinary inspect remains available under its original policy.

`plan` takes exactly `parameters={"planDigest":"sha256:..."}`. It previews an
already registered integration plan; it does not create, approve or execute one.
The service rechecks current target/preimage, active parent, unfinished cycle,
complete B/C/I and ownership, then consumes actual current native evidence/Decision
with the installed five input pins. Changed scope, revocation or missing write
dependencies reject. Both reads use SQL query_only, create no audit/lease/action
or budget reservation, and return the unchanged existing closed contract. Read
responses grant no permission to integrate; the distinct original write grant
and reservation remain required at CAS. Native/filesystem work may hold the
staging read snapshot; these bounded source tests do not prove production latency.

For creation use exactly `parameters={"plan": FULL_INTEGRATION_PLAN}` with the
existing closed `das-integration-plan/v1`. Nested revision/cycle/generation and
image-size counters are validated before JCS: tiny fractions, booleans and
unsafe integers cannot become valid counters through rounding. This is a data
proposal, not permission or an executable recipe.

An independently signed **plan** grant permits this exact request. The existing
outbox reserves its budget and original dispatch. The actual writer independently
reconstructs all B/C/I preimages/postimages, installed ownership/origin and deletion
reasons, and requires the proposal and full request scope to match. A genuine
grant over an untrue owner/image cannot make that claim valid. Native grant and
current evidence/Decision checks share the original two-second budget. After
evidence consumption, grant is rechecked at the effect boundary; final original
references and plan commit together. Revocation/failure rolls back both.

Confirmed replay, response loss and post-commit interruption preserve one plan,
authorization event and original budget. Unknown recovery is lookup-only.
Creation does not switch a target, issue Integration Receipt or create Completion;
the separate integrate/complete grants and current qualification remain required.
Old trusted local planning and readonly preview keep their behavior. A historical
created/cached plan is not current action qualification.

`audit` is an explicitly authorized short read snapshot. Its request must equal
the original intent except action and the originalRequestDigest parameter. It
returns the original native integration bytes, creates no audit event, budget
or retry, and cannot interpret a missing row as proof of no late effect.
Outbox confirmation still follows the original independently checked
observation protocol; this lookup does not silently settle unknown state.

For submission audit, use exactly `originalRequestDigest`,
`originalAction="submit"` and `candidateDigest` in parameters, preserving all
other original intent fields. The currently authorized read compares the entire
original request, confirmed observation and actual registered bytes. It needs
no installed write consumer or live old submit grant. Current read revocation
still denies disclosure; it does not rewrite or re-authorize the old action.

For creation audit, use exactly `originalRequestDigest`, `originalAction="plan"`
and original `planDigest`, keeping every other original intent field unchanged.
It reads the confirmed retained plan without planning/charging or write-consumer
configuration. Historical audit does not replace current-evidence preview.

The unprivileged finite client is:

```text
dasops govern inspect   --driver-fd CONNECTED_FD --server-uid APPROVED_SERVICE_UID
dasops govern plan      --driver-fd CONNECTED_FD --server-uid APPROVED_SERVICE_UID
dasops govern apply     --driver-fd CONNECTED_FD --server-uid APPROVED_SERVICE_UID
dasops govern submit    --driver-fd CONNECTED_FD --server-uid APPROVED_SERVICE_UID
dasops govern integrate --driver-fd CONNECTED_FD --server-uid APPROVED_SERVICE_UID
dasops govern complete  --driver-fd CONNECTED_FD --server-uid APPROVED_SERVICE_UID
dasops govern rollback  --driver-fd CONNECTED_FD --server-uid APPROVED_SERVICE_UID
dasops govern audit     --driver-fd CONNECTED_FD --server-uid APPROVED_SERVICE_UID
```

Each reads one bounded JSON intent from stdin and validates the native response
against its exact original request before emitting stdout. The expected server
UID must come from independent installation configuration. A user-provided UID
is not a service approval. Transport loss returns unknown and no automatic
retry; reconcile the original business key before another execution.

Source tests use actual Unix sockets, OpenSSL TEST signatures, the sealed Go
checker and the original SQL writer. Same-UID sockets, synthetic trusted clock
and TEST control loaders prove source routing only. Approved owner/mount/handle
exclusion, independent installed current control and signing/collection,
complete approved scenarios for all eight operations and the final installed
136 cases remain required.

### Installed verification inputs and read-only recovery

The installer supplies exactly `standardDigest`, `bundleDigest`, `factsDigest`,
`acceptanceDigest` and `environmentDigest` to NativeQualification. The adapter
copies these into an immutable map and rejects control bindings that differ,
including otherwise valid signed materials. Missing pins permit only the older trusted plan preparation/readonly preview;
authenticated plan creation, apply/rollback, integration and completion reject. These comparisons bind the
installed context; they do not themselves establish full StandardArtifact asset
closure or complete adoption. Source TEST pins are not production asset proof.

An authorized exact-original `audit` remains available through a read-only
manager when native write dependencies are unavailable. Task/resource/instance,
actual UID, current epoch/read permission, time floor and complete retained
request binding still apply. Successful audit cannot enable a write operation
or change the original checkpoint. This is reconciliation, not qualification.

## Completion projection

`completion_projection(database, full_task_key, actor=..., now=..., authorize=...)`
reads the actual current revision/cycle in a short read-only snapshot. Its
installed reader receives the full TaskKey and current epoch. Same local task IDs
in different Changes cannot share a projection. Generic coordination rows without
the exact native Completion binding reject; native bytes, original integration
receipt, I/generation and retained references must agree.

`render_projection` emits deterministic Markdown from those records. It reads
no `tasks.md` and writes no file. Hand-editing the display cannot add, remove or
replace a Completion. Rework creates a new current cycle's TODO while preserving
the older Completion. The original hashes remain unchanged. DONE describes the
recorded history for that cycle; current qualification is explicitly
`not_evaluated` and requires its own fresh check.

The authenticated client can format the exact verified complete response with
`dasops govern complete --driver-fd FD --server-uid UID --projection markdown`.
JSON remains the default. Markdown is stdout for an optional non-authoritative
workspace display. Do not automatically commit it into the protected candidate
or feed it back as completion evidence; a protected metadata change needs a
separate approved action. These internal projection helpers introduce no public
exchange schema or second state store.

## Controlled HTTP reference

`http_reference.handler_for` requires installed manager/authentication/current
local authorization/time and a fixed resource instance. It starts no listener,
allows no arbitrary destination and supplies no default credentials/permission.
The HTTP/1.1 loopback profile enforces exact strong If-Match at the same original
SQL switch boundary; native instance/generation and I qualification remain.
Raw request lines require CRLF and reject every C0/DEL control byte before
stdlib parsing or URL normalization. A leading NUL/0x01 must not become a valid
`/integrations` route: reject with 400 and close before authentication/effect,
leaving target, native receipts and authoritative audit unchanged. The original
driver A19.6 exercises those real requests together with ambiguous framing,
truncation, cumulative deadline and legal chunked/connection-reuse controls.
It covers this selected loopback profile; proxy/TLS deployment variants remain open.
`ReferenceHTTPAdapter` plugs into the existing DurableOutbox with no automatic
retry/redirect. 202, missing replies and null lookup stay unknown; confirmation
requires independent verification of the original native receipt. Completion
continues through the existing current-evidence/unique-cycle transaction.

See the controlled Cadence example for supported framing/projection limits.
TEST mappings and source-built binaries do not qualify actual authenticated
installation, TLS/proxy chains or beta acceptance.
## Governed version-reference apply and rollback

The authenticated registry now supports the original eight operations. Apply
and rollback consume a retained `das-version-tree-plan/v1` through parameters
`planDigest` and `qualificationRefs` (the exact verification plan, evidence and
Decision digests). Installer dependencies stay outside requests. Version
verification has three distinct `das-version-*/v1` identities/DSSE purposes;
integration and analysis evidence cannot be relabeled to permit a switch.

Authenticated plan creation accepts `plan` plus `qualificationRefs` for this
profile. The manager reconstructs actual preimages, postimages, ownership and
deletion reasons before comparing the complete approved plan. Rollback creation
and the final switch both verify `rollbackOf` against a retained native forward
receipt and the current target generation/postimage; later changes are preserved.

Apply/rollback use the existing outbox, stable action key, shared reservation,
actual SQL CAS and native receipt. They verify current action grants before
reservation/dispatch and before and after evidence consumption at the effect
boundary. A failed effect retains unresolved intent/budget; it does not prove
absence or permit automatic redispatch. Confirmation failure is reconciled by
native original lookup, without checking an obsolete preimage grant or doing
another switch. Exact confirmed replay is an authorized read with no charge or
new effect. Explicit audit uses `originalAction=apply|rollback` and
`originalRequestDigest`; the historical integration audit form stays compatible.

These operations change only the installed SQL version reference. A separate
editor's later workspace bytes remain untouched. The current reference does
not enable in-place filesystem replacement, compensate arbitrary external
effects, undo Completion or activate a production deployment. Original A23
source drivers cover this profile and real process-death recovery; physical
power loss, deployment isolation and final installed acceptance remain open.
The plan's task/revision/cycle comes from the after candidate and must remain
current and unfinished; the before candidate may be a historical baseline.
The original restore candidate's stale/completed task binding still rejects.
An independently approved compensation task can instead receive/register a new
candidate binding for the **exact original snapshot**: only `taskKey`,
`taskRevision`, `taskCycle`, `obligationDigest` and current `policyDigest` may
differ. Git commit/tree/object format, raw/decoded archive identity, every file
and mode, and all external material bytes/roles/media types must remain equal.
Copying files into a new Git commit or repacking the archive is not that identity.
The original binding is immutable; a new candidate digest records the new task.

Use the original authenticated `submit` with its own action key/current grant to
receive the rebound candidate, then authenticated `plan` with `rollbackOf` set
to the retained forward receipt digest and `afterCandidateDigest` set to this
new registered candidate. The installer must permit the compensation task for
that resource. Planning and actual rollback both recheck snapshot identity and
current forward postimage/generation. Use fresh purpose-specific verification
and plan/rollback grants; the old task's evidence or Completion confers none.
The rollback gets a new business action key, retains the original action and
Completion, consumes its current shared budget and advances the target generation.
Original-key recovery still replays its exact receipt without another effect.

Source tests cover authenticated creation/rollback/CLI, wrong snapshot, identical
files with a different commit or archive, task drift, revocation and commit-time
identity refusal. A separate staging test starts from an actual completed
integration and checks retained Completion/history; it is not a fully deployed
native completion-to-compensation qualification run.
