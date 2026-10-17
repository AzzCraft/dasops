# Coordination database kernel

Original A01.2 analysis Completion reuses this database and its unique task/cycle
row. `add_task` optionally retains a preapproved analysis binding in the existing
immutable audit; an ordinary task cannot become analysis-only later. The binding
fixes the check scope before claiming. Its approving actor cannot claim that
task. `analysis_task_binding` reads only a current transaction on this database;
historical reads select an established cycle and cannot authorize a new effect.
Analysis rework requires separate installed `approve_analysis_rework` approval
and a next-cycle binding while preserving the original task/obligation/policy.
No new table, schema author, backend or automatic migration is added.

`_reserve` is the shared transaction-local reservation used by ordinary outbox
reservation and native analysis completion. Callers cannot supply a connection
or callback through IPC. Analysis completion atomically retains the exact
request, budget, native effect and the original unique Completion. Final INSERT
failure rolls all of these back. Original integration Completion still requires
its actual native integration receipt; analysis has a separate protocol identity
and never fabricates that receipt. See the candidate README and A01.2 source
driver for the execution boundary and production limitations.

This is a staging kernel, not an activated resource gateway. No CLI or RPC maps
candidate requests directly to these methods. The existing protected v1 writer
continues its own contract. Finite SQLite-to-SQLite stop-write/import/forward
activation and finite quiescent legacy-v1 history import are implemented below; full old-state windows, production fencing and
installed deployment qualification remain unfinished.

## Installed writer route and forward migration

`AuthorityRoute` uses one owner-controlled route/watermark file outside the DB
backup directory, reusing the existing atomic file publisher and audit tables.
It adds no business-state database, schema author, service, CLI or RPC. The
installer supplies the route and a current independent approval predicate:

```python
from dasops.protected.sqlite import AuthorityRoute

route = AuthorityRoute(control_directory / "authority-route.json", authority_domain=domain)
route.enroll(database, actor=administrator, now=trusted_now, approve=approve)
# Existing installed drivers/managers use this same database object, or:
current_database = route.open_current()
```

`approve(connection, operation, actor, epoch, subject)` must return exactly True
only after independently checking current administrative authority and the exact
subject. It is an installed local dependency; candidates cannot supply it.
For freeze it must additionally establish old dispatch domains cannot produce
late effects and reconcile each unresolved original action with the actual
external resource. Retained unknown actions stay unknown, keep their original
identity/budget, and cannot be redispatched. Two names in a fixture are not
production independence evidence.

Freeze with a fresh destination in the DB artifact directory, a new instance ID
and stable migration ID. `route.stage(database)` backs up only the frozen current
source, checks all tables/columns/bytes against it, and checks an existing stage
on retry without overwriting it. `route.activate(actor=..., now=..., approve=...)`
requires current approval of the exact retained import intent, advances the
epoch, expires old leases and publishes the unique new writer. Old handles and
unbound restored copies reject at the shared transaction/read entry. Install
new managers against `route.open_current()`; existing stale managers stay fenced.

Every participating transaction takes the route lock before its SQL snapshot;
lock contention fails after 250 ms and requires a complete operation retry.
Before SQL COMMIT the independent watermark is published/fsynced. Publication
or commit uncertainty never lowers it to match an old DB. Normal-transaction
uncertainty remains fenced unless it is a finite verified-outbox settlement
described below; no general repair or refund is provided. Enrollment and freeze retain their exact original
administrative intent and result before COMMIT, in `enrolling`/`freezing` phases.
After either operation is interrupted, the installed administrator calls:

```python
route.reconcile(actor=administrator, now=trusted_now, approve=approve)
```

`authority_reconcile` requires fresh independent approval of the installed route
and entire retained record. It accepts only the exact original SQL preimage,
the exact committed administrative result, or its exact retained reconciliation
result. It recreates the original enrollment/freeze event with the original actor
once, and records the first reconciliation actor/time once in `authority_reconciled`.
Retries retain that intent. All tables, metadata and audit bytes remain bound;
only the time floor may advance between the original intent and the independent
watermark. A second interruption on either side of COMMIT remains recoverable.
Final publication activates enrollment or leaves the source frozen for stage/
activate. Stage/activate reject an unreconciled `freezing` route. Missing original
intent, changed state, current approval denial or clock rollback stays fenced.
The approver cannot modify its subject or SQL state for enrollment, freeze,
reconciliation or activation.

Before first enrollment, the installer must independently stop **all unbound
handles and raw/old writers**, and keep the installation inactive through any
failed enrollment. Those entrances cannot discover a newly published route from
an uncommitted SQL row; `reconcile` does not establish OS-level fencing for them.
Historical active records and frozen/activating records retain their reader;
records without retained administrative intents are never retroactively repaired.
An ordinary business transaction with a watermark ahead of rolled-back SQL is
explicitly unsupported by administrative `reconcile`. The installed
`DurableOutbox.reconcile` additionally supports one typed `settling` route:
confirmation or independently closed absence of a dispatched/unknown original action with immutable full intent
and independently verified original native bytes. Before COMMIT, the route binds
its stable key, request/fingerprint/native digest, original actor/time and exact
whole-database pre/postimage. Native bytes remain at the independent resource and
in SQL once committed; the route does not duplicate arbitrary payloads or SQL.

Recovery authorizes lookup in the actual fenced snapshot, releases SQL and route
locks for the installed resource's lookup (never execute), verifies exact original
receipt bytes, then rechecks the route/state and current outcome permission.
Only the exact original preimage, committed settlement or retained recovery result
is accepted. A preimage replays that fixed outcome once with the original
actor/time; recovery appends one event retaining the first recovery actor/time.
Repeated failure before/after recovery COMMIT retains those same facts. The clock
floor advances within the independent watermark; no watermarks are lowered.
Budget, action keys, unknown unrelated actions and Completion remain intact.
Concurrent or revoked recovery, changed native receipt, drift or insufficient
original history stays fenced. Old active records retain their format; old
uncertainty without this intent is never retroactively repaired. Other arbitrary
write uncertainties remain unsupported. Production native provenance and OS/runtime isolation
remain deployment requirements; this trusted installed API adds no candidate RPC.

Three fixed public writer operations additionally retain a `committing` route:
outbox payload reservation, outbox `reserved -> dispatched`, and public
`record_completion`. The existing SQL writers still enforce their constraints.
`businessIntent` binds operation, exact arguments, original actor/time, source
checkpoint/full SQL state; `business_committed` binds the complete intent digest.
The route retains the full result digest before COMMIT. It contains no arbitrary
SQL, replay function, adapter, qualification result or duplicated request payload.

Resume reservation with the **same canonical input** to `DurableOutbox.submit`;
resume a dispatch intent through `DurableOutbox.reconcile`, never `dispatch`;
resume Completion with the exact original `record_completion` arguments and
current independently validating authorization. Use the installed database path
and original bound route to open a recovery connection; `open_current` deliberately
refuses while pending. A rolled-back reservation has no SQL payload, so recovery
requires the original caller input matching the retained digest. Old uncertainties
without this intent cannot be converted into this format by signing current SQL.

Recovery rechecks the actual physical schema/constraints and integrity inside
its SQL snapshot, including already-open handles; row digests alone do not bind
sqlite_master triggers. Recovery accepts only exact original preimage, committed result or retained
recovery result, checks current owner authorization and SQL connection policy,
and preserves the original mutation/audit actor. `business_reconciled` records the
first recovery actor/time once across repeated failures; the time floor advances.
Committed recovery metadata must match its immutable recovery audit. Rebuilt
recovery must equal the previously retained result before its digest is updated;
it cannot adopt a changed first actor/time by signing another result. Existing
administrative and confirmed/absence recovery use these same audit/result checks;
administrative original actor/checkpoint also binds its actual original event.
An explicit null/empty/wrongly typed recovery record is rejected, rather than
treated as absent. Integer identities exclude booleans; structured audit binding
uses canonical bytes, not Python's True/1 equality.
No second reservation, native effect, qualification or Completion is invented.
Dispatch recovery only rebuilds the durable intent, then independently looks up
the original key. Empty lookup without execution closure remains unknown. A
competing lookup's stale CAS may refuse; retry only reconciliation of that key.
Completion recovery may be denied after the original commit if current independent
qualification is revoked, leaving the database fenced. It never converts a native
confirmation alone into a qualified Completion.

These finite APIs do not cover arbitrary enclosing integration transactions,
reservation without immutable outbox payload, old pending formats, raw writers,
system/power/sync faults, WAL or remote queue closure. The fixed TEST source and
installed process-death consumers establish development behavior, not deployment
or beta qualification. No new SQL schema, service, backend or callback extension.

New retained intents include `auditBinding='intent-sha256-v1'`; absence also adds
`target='not_executed'`. The original action audit binds the complete intent's
digest, original actor, target, native bytes and exact checkpoint. A matching SQL
postimage alone does not establish those recovery metadata facts: changing the
original actor/source digest/checkpoint refuses. The earlier fixed confirmed
format retains its exact reader and original actor/checkpoint checks; historical
digests are not manufactured. Removing the new marker cannot downgrade a current
event, whose audit still requires its settlement digest. Every absence recovery, including an
already committed result and repeated recovery failures, calls the installed
`execution_closed` predicate again outside SQL/route locks with the exact original
intent. It must return the literal `True` without changing that intent. It must
establish monotone closure of **all execution capable of producing that original
effect**, including queued/remote work where applicable. Empty lookup, process
timeout, an old successful check or a different closed process is insufficient.
The independent native absence bytes must also match the retained digest. Fresh
`action_lookup` and final `action_not_executed` authority are both required.
Absence preserves the original reservation and cannot mint Completion or send
again. Only the existing explicitly authorized `not_executed -> reserved` retry
of the same key may dispatch later; it does not reserve budget again.

The finite TEST consumer owns a fixed synchronous SQLite dispatcher with no
children/queued transport. It binds that real process using a kernel pidfd before
allowing send, refuses empty-resource reconciliation while it is still alive,
waits for its actual exit, and rechecks the same handle during recovery. The TEST
witness checks the handle is still a pidfd and requires POLLIN without an invalid
or error event; a closed descriptor reused for a readable SQLite file is refused. The
installed collector separately observes the retained PID/start-time identity and
actual resource/authority SQL. This demonstrates the bounded TEST profile, not
production termination, remote queue drainage or arbitrary process-tree fencing.

Activation separately retains an exact intent and
phase: after interruption re-enter `activate` to finish that same import or
confirm its original SQL commit. All ordinary writers remain fenced until final
active-route publication. Recovery checks both the SQL and independently retained
time floors; an uncommitted SQL intent cannot permit a clock rewind. No return to
the old writer occurs after activation.

The record directory must have a separately protected lifetime and privileges;
different directory names alone do not prove this. Its file/lock are private,
regular, nonaliased objects. Cooperating flock, fsync and DELETE-mode process
death tests do not prove a hostile same-UID deployment, power-loss durability,
approved WAL or shared-filesystem behavior. Those remain original T-006/T-008
acceptance requirements. Existing databases are never silently enrolled or
schema-migrated; enrolled records cannot omit their original installed route.

The schema author is `schema_v1.sql`, packaged with dasops. The kernel stores
complete task identities, immutable obligations, current revision/cycle, fenced
leases, shared budgets, stable business actions, receipts, unique completions
and an append-only audit chain in one database. It never uses REPLACE/IGNORE or
`executescript` in its authority transaction path.

Integration instructions for the installed service:

1. Resolve the authority domain and project/change/task identities through the
   independently installed namespace. Do not infer identity from a candidate
   directory or display label. Retain old identities and mappings permanently.
2. Use a private control directory outside the candidate workspace. Install the
   service, interpreter, schemas and dependencies independently. A mode 0700
   directory alone does not isolate two processes using the same host identity.
3. Create a fresh staging database with `CoordinationDatabase.create`. It refuses
   existing files and never replaces an active state store. Initialization must
   be part of the administrative installation or migration protocol.
4. Bind runtime approval to the process's SQLite version/source ID, driver hash,
   actual loaded library hashes and compile options. WAL requires separately
   validated approval and exact fix provenance. `admit_wal` checks an already
   approved binding; it does not authenticate a claimed approval object.
5. Use the verified WAL-reset fix or an independently validated backport before
   enabling a multiple connection WAL deployment. The system CLI is not the
   process library. Development DELETE tests do not qualify a WAL installation.
6. Every writer connection enables and reads back foreign keys, CHECK support,
   FULL synchronization, trusted_schema OFF and recursive triggers ON. The last
   setting also makes attempted REPLACE encounter retained-row delete triggers.
7. Supply only an installed bounded local `authorize` predicate. It receives the
   actual connection after BEGIN IMMEDIATE and the current authority epoch. It
   must use the authenticated peer and independently verified current grant,
   resource, lease, budget and purpose. A candidate-supplied callback is forbidden.
8. Do not perform network calls, external side effects or long verification inside
   that predicate or the database transaction. SQL failures roll back the whole
   operation. Busy errors fail explicitly; retry the entire method and current
   authorization, rather than an isolated UPDATE from an old snapshot.
9. Keep the stable business key `(domain,resource,action,business ID)` across
   credential, epoch and actor changes. The immutable fingerprint separately
   binds the original actor, task/cycle, exact request, cost and shared budgets.
10. Reserve every applicable shared budget atomically. Existing equal fingerprints
    return the original state; different fingerprints reject. Neither unknown
    results nor a lease handoff refund or duplicate the reservation.
11. Before actual dispatch, recheck current resource authorization/fencing and
    persist the dispatch intent. Timeout does not prove no resource commit.
    `unknown` cannot be redispatched. Independently confirmed no-execution may
    continue the original key under new authorization with its retained budget.
12. Receipt hashes supplied by a caller are insufficient. The installed receipt
    consumer must verify the actual resource result and original action binding
    before authorizing the confirmed transition.
13. The Completion predicate must verify required action slots, actual integration
    candidate, decision purpose and current resource result. The kernel then
    checks parent/cycle/revision, confirmed action relation and unique cycle.
    A digest string or database row alone is not executed acceptance evidence.
14. Enter closing with a fixed task set and generation. It blocks new tasks and
    rework. Existing included work may settle, but close requires every current
    cycle complete and no reserved/dispatched/unknown resource effects. Rework
    happens only while active and preserves original completions.
    A completed Task cycle also blocks new business reservations, lease claims
    and renewals, fresh candidate registration/plans, dispatch and target CAS.
    The check reads the existing full `(taskKey, cycle)` Completion in the same
    transaction; it adds no terminal-state table. Exact original replays retain
    their original cost and fact. Current-authorized inspect/audit and factual
    reconciliation of already-sent requests remain possible; even confirmed
    absence cannot re-enable sending in the completed cycle. Explicit rework
    creates a new cycle without refunding or deleting the old history. A new
    verification-service run needs its own current authority and budget; these
    kernel read exceptions do not implement or approve that service.
    `withdraw_closing(project, change, generation, ...)` withdraws a current
    closing plan under its own installed authorization. It advances generation
    and retains the old plan in audit; it cannot reopen a terminal parent.
    `terminate_change(..., status='cancelled'|'superseded', successor=...)`
    requires current generation and independent approval of the exact outcome
    and successor. Supersession atomically creates a fresh successor identity;
    cancellation can later use `create_change(..., predecessor=...)`. The latter
    only accepts an existing terminal predecessor. Lineage is retained in the
    original append-only audit, with predecessor status/generation.
    Termination changes reserved actions to `not_executed` in the same SQL
    transaction as the parent state. The dispatch writer uses that transaction
    boundary: cancellation first means no send; dispatch first means an in-flight
    request whose actual outcome must be reconciled. Dispatched/unknown actions
    are not erased or guessed absent. Reservations are never refunded; successor
    work must receive its own approval and obey the same cumulative budgets.
    `rescind_closure(..., impact_evidence_digest=..., verify_no_impact=...)` is
    an installation-only administrative exception for an exact `closed` event.
    The approver must differ from the closer. The bounded read-only predicate
    must check independently retained facts, bound to that closure and evidence
    digest, proving no deployment, migration, external dependency impact or
    downstream consumption. False/unknown, a modified review, callback writes,
    stale generations and cancelled/superseded parents refuse. Keep those facts
    outside Worker control; a user flag or `lambda: True` is not a fact service.
    The `closureRescinded` event retains both digests and advances generation;
    original closure, Completion and cycle remain unchanged. Older closure events
    lacking exact generation are not inferred eligible. Actual impact collection
    and current approval belong to the installation, not this local SQL kernel.
    None of these methods adds a Worker RPC, CLI status flag, schema or backend.
15. Use the online backup API. Verify physical schema, integrity, foreign keys,
    budget totals and audit sequence. Check an independent protected watermark
    before restoration or activation. Opening an old valid backup is insufficient.
16. Keep failed or orphaned backup artifacts private and unregistered. The backup
    path is a fresh same-directory object, never a caller's arbitrary privileged
    output destination. Database and directory synchronization are separate.
17. Use the finite SQLite migration above for an enrolled current-schema source.
    Complete the original legacy-v1 importer and independently approved external
    dispatch drain/fence before a production migration. Exercise namespace import,
    independent checkpoint, epoch approval and actual installed authority routing.
    After activation recover forward; never roll back
    revocation, budget, deduplication or completed business history.

The current tests cover real DELETE connections, concurrency, process exit and
backup watermarks and finite installed TEST forward migration. They do not claim
power-loss durability, approved WAL patch provenance, legacy-v1 migration,
production resource fencing or installed beta qualification.

### Candidate verification currently holds the writer

`VersionTreeManager` registration, plan creation, switching and target readback
currently verify candidate bytes while holding `BEGIN IMMEDIATE`. Registration
also synchronizes the complete tree and repeats readback. This deliberately
keeps current authorization and the observed candidate in one transaction, but
does **not** meet the short-transaction installation guidance above. These are
staging operations; do not route production traffic on the assumption that all
transactions are short.

The near-limit version-tree regression uses a compressed complete Git tree
only 512 bytes below the 64 MiB cumulative limit and a separate actual writer.
It checks bounded busy failure, no partial reservation, and successful retry
with fresh authorization after registration commits. Its elapsed timings are
development observations, not a throughput guarantee or physical durability
qualification. Readback has multiple bounded passes; the 10-second per-pass
candidate deadline is not an overall transaction-latency guarantee.

Before activation, establish the protected store's actual owner / mount / handle
immutability boundary and measure the supported workload and competing writers.
Only then move safe preparation outside the transaction while retaining current
authorization, exact candidate binding and generation CAS at the commit point.
Do not omit full readback, trust mode bits as immutability, or retry an isolated
UPDATE with stale authorization to shorten this lock period.

## Durable outbox integration

The unpublished staging schema now includes immutable action payloads and native
resource observations. Opening a staging database made against an older schema
revision fails its author-digest check; this is not an automatic migration.

1. Construct `DurableOutbox` only inside the installed protected service. Supply a
   fixed `(resourceId, resourceInstance, action)` adapter map, a separate native
   observation verifier and an independent prior-dispatch termination witness.
   Neither an RPC body nor candidate imports may supply these dependencies.
2. Build a `das-resource-action-intent/v1` object from the authorized task, actual
   resource instance, target generation, approved operation parameters and tool /
   policy digests. Shared budget IDs have canonical order. The request digest
   covers the entire bounded JCS object, including the original actor and cost.
3. Call `submit` with the server-authenticated actor, trusted current time and the
   installed current-state predicate. It persists the action, exact intent and
   every ancestor reservation in one transaction. A changed task revision, failed
   second budget or same stable key with changed parameters rejects the whole
   reservation. Identity handoff uses the original immutable intent.
4. Supply exact per-operation parameter validation inside each installed adapter.
   Adapters implement a fixed native API / argv contract and enforce authorization
   and fencing at the resource's actual linearization point. There is no shell,
   arbitrary program path or candidate plugin selection in the outbox interface.
5. `dispatch` rechecks current authority in the `reserved -> dispatched`
   transaction. That COMMIT occurs before the native call. Transport adapters
   must enforce the supplied CLOCK_BOOTTIME deadline and their own I/O limits;
   this synchronous kernel cannot preempt a blocking trusted adapter or certify
   termination of its descendants.
6. An independently verified native observation may record `confirmed`. Original
   receipt bytes and their SHA-256 commit atomically with the action state and
   audit event. Candidate PASS JSON, a transport return code, wrong instance,
   wrong request digest or an unverified hash cannot settle this path.
7. A timeout or lost reply leaves `unknown`; process death can leave `dispatched`.
   Both states prohibit another dispatch. Run `reconcile` using a current read
   authority and the original business key. It calls the adapter's lookup API,
   never its execution API. Neither case refunds the retained reservation.
8. Positive nonexecution needs verified native absence **and** independent proof
   that the prior dispatch domain can no longer issue a late write. A not-found
   lookup alone cannot establish that fact. Both `dispatched` and `unknown` may
   settle to `not_executed` under those same checks, retaining the original native
   absence bytes. In particular, process death after intent COMMIT but before
   sending must not require another execution or a fabricated intermediate event.
   Only then may the service explicitly
   authorize `not_executed -> reserved` with the same original key and budget.
9. Record late confirmed in-flight facts during `closing` through the separately
   authorized settlement path. New dispatch still requires an active parent.
   A confirmed resource action does not produce Completion: the independent I,
   required-slot and decision verification contract must also close.
10. Test restart and concurrency with an independent native resource observer.
    The public source verifier includes two writer connections, real process exit
    before sending and after a separate fixture resource commits, response loss, exact original-byte
    retention, forged observations and denied absence without domain closure.
    These tests do not establish production identity separation, remote resource
    fencing, filesystem power-loss durability or installed beta qualification.


The current integration kernel also uses immutable `completion_bindings` in the
same staging database. It retains exact native Completion bytes alongside the
existing unique `(taskKey, cycle)` Completion row, committing both in one writer
transaction. INSERT failure cannot erase a confirmed native integration, and
historical replay cannot issue current qualification or a second completion.
The schema author hash changes with this unpublished staging extension. Existing
staging databases with another author hash are rejected, not silently migrated,
reset or deleted. T-006 still requires approved import/history/epoch/writer
cutover evidence. Released protected v1 Git formats and digests are unchanged.

## Finite protected-v1 import

`import_legacy(store, database, project_id=..., mappings=..., actor=..., now=...,
approve=...)` is an installation-only primitive. It uses the existing SQL schema
and append-only audit, with one permanent `das-task-state/migration.json` fence.
It does not expose a CLI/RPC, accept candidate-selected paths or infer approval
from an old format. The finite profile supports **released/reclaimed, expired
active and completed tracked histories**. A live active lease is refused. Pending
release/completion must first recover with the original v1 key and original Git
outcome; importing a renamed status is not recovery. Historical DONE retains its
original bytes and does not create a current Completion or authorization.
Old route histories and unspecified layouts still have no import profile.

Installation order:

1. Independently stop old binaries, direct Git/filesystem writers and external
   dispatch domains. Install the updated v1 library in all cooperating entrances.
   Its shared `writer_guard` encloses whole change operations and direct state,
   WAL, receipt and challenge writes. Migration takes that barrier exclusively;
   an in-flight writer causes a bounded refusal and whole-operation retry.
   This cooperative lock cannot revoke an old binary's OS capabilities.
2. Create a private, fresh inactive SQLite DB outside the old bare repository.
   Supply the new domain/instance/project explicitly. Map **every tracked state**
   with exactly `changeId`, `taskId`, `obligationDigest`, `revision`, `cycle`.
   The installed approval checks original Git head, policy, complete retained
   JSON, mappings and target identity, including whether the old task definition
   has an equivalent obligation. Unclaimed Git task definitions are retained by
   the source commit, not automatically created as current tasks.
3. Call `import_legacy` with current trusted time. It validates schema/self-digest,
   original completed claim/WAL and terminal receipt, or original activation and
   consumed completion request/decision/result, exact Git Task transitions and
   current canonical Task identity, canonical ancestry, private
   regular files and complete mapping. Limits: 1 MiB per original, 1,000 original
   files, 8 MiB raw namespace, and the existing 4 MiB encoded audit-reader limit.
   Unsupported layouts or objects refuse before publishing the fence.
4. The fence is synced before SQL COMMIT and must remain after interruption.
   Tasks, expired leases and original bytes commit atomically. Old lease generation,
   owner and token hash are retained; the next separately authorized claim advances
   generation. No budgets, actions, native receipts, qualification or Completion
   are manufactured. A failed import's empty target remains private staging and
   must never be exposed as an active service. After successful import, ordinary
   DB reads/writes refuse until independent route enrollment.
5. Retry the same source/mapping/target after uncertain publication or commit;
   current approval is checked again. Inspect actual SQL facts as well as the
   original import audit; drift, extra facts or a changed mapping refuse. Never
   remove the fence, reset history or choose another DB to evade an interrupted
   import. Once independently enrolled, use the existing freeze/stage/activate
   route for the approved new epoch. Retain old originals for historical reading;
   do not resume v1 writes after activation.

Tests cover actual original writers, completion publish/abort and lost post-CAS
state/readback, unresolved/live/source-drift refusal, old-entry refusal, the
two-thread barrier, original-byte retention and read-only approval. Five history
profiles also execute actual process exits after fence, before COMMIT and after
COMMIT. The fixed A24.1 installed recipe uses the isolated package and independent
parent SQL/Git/original-byte observations. These are TEST control observations;
they do not close the full supported-version matrix, hostile-UID deployment,
external dispatch fencing, power-loss/WAL or final installed beta acceptance.


### Approval and interrupted activation result binding

Installed approval callbacks execute in a read-only interval on the owning SQL
transaction. Queries retain the owner's existing authorizer; SQL writes, transaction/
savepoint control, attached databases, policy changes and authorizer replacement
refuse before execution. A caught SQL denial still rejects approval. The interval
ends on success or exception and restores the owner's policy, including Python3.10.
This is a programming constraint for trusted installed callbacks, not a sandbox for
hostile Python or independent raw database/OS access.

An `activating` route now retains `activationResultDigest` over all SQL rows/columns,
with only metadata time normalized to the original activation time. Recovery checks
the retained checkpoint and exact result, bounds actual time by the independent
record, and preserves the original activation actor/event and lease expiry. Current
recovery time can advance the time floor; business state cannot drift. Existing
active/frozen records retain their read contract. Historical pending activation
without that result digest refuses automatic recovery; do not derive a new digest
from the database under recovery or replace its route to bypass missing evidence.

The connection retains its installed journal policy. Ordinary writes and integrity checks reject later journal-mode drift; FULL alone cannot approve an OFF/MEMORY journal or a new WAL runtime. The writer does not silently convert an active database.

## Task clarification and verification of completed work

`add_task(..., predecessor=TaskKey(...))` creates a distinct task with retained
lineage for materially changed obligations. `clarify_task` instead requires the
exact current revision/cycle and unchanged obligation, an independent readonly
review of the clarification and review digests, and a quiescent active parent.
An active lease or unresolved action blocks revision; closing must first be
withdrawn. The append-only rebinding records the original Completion/evidence
when present. It advances revision and parent generation, never cycle or budget.
Analysis tasks additionally require an explicit next-revision analysis binding;
an ordinary task cannot gain an analysis exemption. Both analysis rework approvals
run under the transaction's readonly guard.

Current candidate admission still rejects old revision bytes. `current_completion`
and the display/parent-close consumers follow the explicit contiguous mapping to
the immutable original Completion. A projection may include `revisionBindings`;
its current revision and the Completion's historical revision are deliberately
different. Rendering validates that chain and still grants no current qualification.

`VersionTreeManager` optionally installs `check_reverification`. This is a
separate, bounded readonly service control predicate, not the Worker's existing
integration/complete qualifier and not a request-supplied callback. It must check
the exact current plan, independent verifier role/authorization, bounded test
space, evidence originals, action-specific Decision, time and trust. The default
is disabled. No Worker CLI/RPC or ordinary native complete Decision enables it.

1. Call `start_reverification` against an exact native Completion/current target,
   approved plan digest and finite shared budgets. Inspect the returned
   `newlyDispatched`: only True permits the first execution. Repeated starts return
   the original intent/state without new execution permission or a second debit.
2. Run the approved verification in its restricted test space outside the SQL
   transaction. A crash, failure or loss of the response preserves the reservation;
   a False `newlyDispatched` never authorizes replay. Reconcile retained originals.
3. Call `record_reverification` with the same intent and current qualification
   references. The consumer rechecks task/rebinding, current target and service
   approval; it stores an immutable audit result referencing the original
   Completion. It does not modify the target, parent, cycle or Completion count.
   Refusal preserves the already spent budget and pending action. Changed-result
   replay is rejected; exact replay is subject to current service checks.

This finite profile supports completed integration tasks under active/closing/
closed parents; cancelled/superseded parents and missing/moved targets refuse.
It does not supply a production signer/collector/test-space adapter, verify-only
native wire contract, or analysis-only reverification profile. Installed TEST
predicates exercise the boundary, not deployment approval. Ordinary business
reservations/dispatch remain restricted to active, unfinished tasks. No schema,
new database or general replay service was introduced.
