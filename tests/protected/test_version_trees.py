"""Real multi-tree/SQL CAS and recovery fixtures, not product qualification."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path
import os
import sqlite3
import subprocess
import sys
import threading
import time

import pytest

from dasops.protected.candidates import CandidateError, CandidateLimits, CandidateStore
from dasops.protected.candidates.versions import VersionTreeManager
from dasops.protected.sqlite.store import CoordinationDatabase, CoordinationError, TaskKey
from dasops.protected.sqlite.outbox import DurableOutbox, Observation, encode_intent
from dasops.standards_contracts import exact_json as codec
from tests.protected.test_candidate_store import fixture, receive, sha, D

OWNERS = {path:('fixture-owner', D) for path in ('tree/README.md', 'tree/src/run.py',
    'tree/tests/test_source.txt', 'tree/config.json', 'materials/dependency')}
DELETIONS = {'tree/tests/test_source.txt':'explicitly retired fixture assertion'}
KEY = TaskKey('domain', 'project', 'change', 'task')


def authorized(connection, operation, actor, epoch):
    return connection.in_transaction and actor in ('admin', 'worker', 'successor') and epoch == 1


def manager(db, store, **overrides):
    options = dict(ownership=OWNERS, tool_digest=D, policy_digest=D)
    options.update(overrides)
    return VersionTreeManager(db, store, **options)


@pytest.fixture
def setup(tmp_path):
    root = tmp_path/'artifacts'; root.mkdir(mode=0o700)
    control = tmp_path/'control'; control.mkdir(mode=0o700)
    before = tmp_path/'before'; before.mkdir()
    after = tmp_path/'after'; after.mkdir()
    values = fixture(before)
    changed = fixture(after, content={'README.md':(b'new committed revision\n', False),
        'src/run.py':(b'print("legal")\n', False), 'config.json':(b'{"fixed":true}\n',False)})
    with ExitStack() as resources:
        store = resources.enter_context(CandidateStore(root))
        db = CoordinationDatabase.create(control/'state.db', authority_domain='domain', instance_id='installed-writer')
        resources.callback(db.close)
        db.create_change('project', 'change', actor='admin', now=100, authorize=authorized)
        db.add_task(KEY, D, actor='admin', now=100, authorize=authorized)
        db.create_budget('shared', 100, actor='admin', now=100, authorize=authorized)
        kernel = manager(db, store)
        pre = receive(store, values)['candidateDigest']; post = receive(store, changed)['candidateDigest']
        for digest in (pre, post): kernel.register_candidate(digest, actor='worker', now=100, authorize=authorized)
        kernel.install_target('target', 'instance', pre, actor='admin', now=100, authorize=authorized)
        yield db, store, kernel, pre, post


def plan(setup, **overrides):
    options = dict(deletion_reasons=DELETIONS, actor='worker', now=101, authorize=authorized)
    options.update(overrides)
    return setup[2].create_plan('target', 'instance', 1, setup[4], **options)


def intent(plan_digest, plan_value, business='forward', action='apply'):
    return dict(contractIdentity='das-resource-action-intent/v1', taskKey=plan_value['taskKey'],
        taskRevision=plan_value['taskRevision'], taskCycle=plan_value['taskCycle'], resourceId='target', resourceInstance='instance',
        targetGeneration=plan_value['expectedGeneration'], action=action, businessActionId=business, originalActor='worker',
        parameters={'planDigest':plan_digest}, toolDigest=D, policyDigest=D, budgetIds=['shared'], cost=1)


def durable_dispatch(db, value):
    raw = encode_intent(value)
    db.reserve(KEY, resource_id=value['resourceId'], action_class=value['action'], business_id=value['businessActionId'],
        original_actor='worker', request_digest=sha(raw), budget_ids=['shared'], cost=1, cycle=1,
        actor='worker', now=101, authorize=authorized, payload=raw)
    db.transition_action(value['resourceId'], value['action'], value['businessActionId'],
        expected='reserved', target='dispatched', actor='worker', now=101, authorize=authorized)


def target(db):
    return tuple(db.connection.execute('SELECT generation,candidate_digest FROM version_targets').fetchone())


def switch(setup, value):
    durable_dispatch(setup[0], value)
    return setup[2].switch(value, actor='worker', now=101, authorize=authorized)


def test_plan_contains_exact_preimages_postimages_ownership_deletion_and_mode_change(setup):
    db, store, kernel, pre, post = setup
    before_audit = db.checkpoint()
    digest, value = plan(setup)
    assert digest == sha(codec.canonical(value))
    assert value['beforeCandidateDigest'] == pre and value['afterCandidateDigest'] == post
    changes = {item['path']:item for item in value['changes']}
    assert list(changes) == ['tree/README.md', 'tree/config.json', 'tree/src/run.py', 'tree/tests/test_source.txt']
    assert changes['tree/config.json']['preimage'] is None
    assert changes['tree/tests/test_source.txt']['postimage'] is None
    assert changes['tree/tests/test_source.txt']['deletionReason'] == DELETIONS['tree/tests/test_source.txt']
    assert changes['tree/src/run.py']['preimage']['mode'] == '100755'
    assert changes['tree/src/run.py']['postimage']['mode'] == '100644'
    assert all(item['owner'] == 'fixture-owner' and item['originDigest'] == D for item in changes.values())
    assert target(db) == (1, pre) and db.checkpoint() != before_audit
    assert not db.connection.execute('SELECT * FROM completions').fetchall()
    db.check_integrity()


@pytest.mark.parametrize('reasons', [{}, {'tree/tests/test_source.txt':''}, {'tree/tests/test_source.txt':'  '},
    dict(DELETIONS, **{'tree/README.md':'not deleted'})])
def test_missing_or_unrelated_deletion_reasons_abort_plan_atomically(setup, reasons):
    db, _, _, pre, _ = setup
    checkpoint = db.checkpoint()
    with pytest.raises(CandidateError, match='deletion'): plan(setup, deletion_reasons=reasons)
    assert target(db) == (1, pre) and db.checkpoint() == checkpoint
    assert not db.connection.execute('SELECT * FROM version_plans').fetchall()


def test_missing_installed_owner_prevents_plan_not_silent_ownership_claim(setup):
    db, store, _, pre, post = setup
    kernel = manager(db, store, ownership={'tree/README.md':('owner', D)})
    with pytest.raises(CandidateError, match='ownership'):
        kernel.create_plan('target','instance',1,post,deletion_reasons=DELETIONS,actor='worker',now=101,authorize=authorized)
    assert target(db) == (1, pre)


def test_reference_switch_and_native_receipt_commit_together_without_editing_trees(setup):
    db, store, kernel, pre, post = setup
    digest, value = plan(setup); request = intent(digest, value)
    before = (store.root/pre[7:] / 'tree/README.md').read_bytes()
    raw = switch(setup, request); receipt = codec.parse(raw)
    assert target(db) == (2, post)
    assert receipt['beforeGeneration'] == 1 and receipt['afterGeneration'] == 2
    assert receipt['committed'] and not receipt['authority'] and not receipt['qualification']
    assert (receipt['executingActor'],receipt['authorityEpoch'],receipt['committedAt']) == ('worker',1,101)
    assert (store.root/pre[7:] / 'tree/README.md').read_bytes() == before
    assert store.verify(pre) and store.verify(post)
    assert kernel.lookup('target','instance','apply','forward',actor='successor',now=101,authorize=authorized) == raw
    assert kernel.switch(request,actor='successor',now=101,authorize=authorized) == raw
    assert kernel.read_target('target','instance',actor='successor',now=101,authorize=authorized)['candidateDigest'] == post
    assert target(db) == (2, post) and not db.connection.execute('SELECT * FROM completions').fetchall()
    db.check_integrity()


@pytest.mark.parametrize('mutation', ['not-reserved','not-dispatched','instance','generation','task','policy','tool','extra-parameter','plan','integrate','rollback-purpose'])
def test_resource_point_rejects_bad_or_uncommitted_action_without_switching(setup, mutation):
    db, _, kernel, pre, _ = setup
    digest, value = plan(setup); request = intent(digest, value)
    if mutation == 'instance': request['resourceInstance'] = 'other'
    if mutation == 'generation': request['targetGeneration'] = 2
    if mutation == 'task': request['taskRevision'] = 2
    if mutation == 'policy': request['policyDigest'] = 'sha256:'+'2'*64
    if mutation == 'tool': request['toolDigest'] = 'sha256:'+'2'*64
    if mutation == 'extra-parameter': request['parameters']['destination'] = '/outside'
    if mutation == 'plan': request['parameters']['planDigest'] = 'sha256:'+'2'*64
    if mutation == 'integrate': request['action'] = 'integrate'
    if mutation == 'rollback-purpose': request['action'] = 'rollback'
    if mutation != 'not-reserved':
        durable_dispatch(db, request)
        if mutation == 'not-dispatched':
            db.connection.execute("UPDATE business_actions SET state='reserved'")
    checkpoint = db.checkpoint()
    with pytest.raises((CandidateError, ValueError)):
        kernel.switch(request, actor='worker', now=101, authorize=authorized)
    assert target(db) == (1, pre) and db.checkpoint() == checkpoint
    assert not db.connection.execute('SELECT * FROM version_switch_receipts').fetchall()


def test_current_authorization_revocation_and_cycle_drift_are_checked_at_actual_cas(setup):
    db, _, kernel, pre, _ = setup
    digest, value = plan(setup); request = intent(digest, value); durable_dispatch(db, request)
    calls = []
    def denied(connection, operation, actor, epoch):
        calls.append((connection.in_transaction,operation)); return False
    with pytest.raises(CoordinationError, match='authorization'):
        kernel.switch(request,actor='worker',now=101,authorize=denied)
    assert calls == [(True,'version_apply')] and target(db) == (1,pre)
    db.connection.execute('UPDATE tasks SET revision=revision+1')
    with pytest.raises(CandidateError, match='current approved task'):
        kernel.switch(request,actor='worker',now=101,authorize=authorized)
    assert target(db) == (1,pre)


def test_protected_tree_drift_preserves_user_bytes_and_refuses_switch(setup):
    db, store, kernel, pre, post = setup
    digest, value = plan(setup); request = intent(digest,value); durable_dispatch(db,request)
    edited = store.root/post[7:] / 'tree/README.md'
    edited.chmod(0o600); edited.write_bytes(b'keep user edit'); edited.chmod(0o400)
    with pytest.raises(CandidateError, match='content or mode'):
        kernel.switch(request,actor='worker',now=101,authorize=authorized)
    assert edited.read_bytes() == b'keep user edit' and target(db) == (1,pre)


def test_changed_installed_ownership_cannot_reuse_an_old_file_plan(setup):
    db,store,_,pre,_ = setup
    digest,value = plan(setup); request = intent(digest,value); durable_dispatch(db,request)
    owners = dict(OWNERS); owners['tree/README.md'] = ('different-owner','sha256:'+'2'*64)
    kernel = manager(db,store,ownership=owners)
    with pytest.raises(CandidateError,match='ownership'):
        kernel.switch(request,actor='worker',now=101,authorize=authorized)
    assert target(db) == (1,pre)


def test_receipt_insert_failure_rolls_back_target_cas_and_audit_together(setup):
    db, _, kernel, pre, _ = setup
    digest,value = plan(setup); request = intent(digest,value); durable_dispatch(db,request)
    db.connection.execute("CREATE TRIGGER injected_receipt_failure BEFORE INSERT ON version_switch_receipts BEGIN SELECT RAISE(ABORT,'receipt failure'); END")
    checkpoint = db.checkpoint()
    with pytest.raises(sqlite3.IntegrityError,match='receipt failure'):
        kernel.switch(request,actor='worker',now=101,authorize=authorized)
    assert target(db) == (1,pre) and db.checkpoint() == checkpoint and not db.connection.in_transaction
    db.connection.execute('DROP TRIGGER injected_receipt_failure'); db.check_integrity()


def test_two_real_connections_cannot_both_commit_same_expected_generation(setup):
    db, store, _, pre, post = setup
    digest,value = plan(setup)
    requests = [intent(digest,value,business=name) for name in ('one','two')]
    for request in requests: durable_dispatch(db,request)
    barrier = threading.Barrier(2)
    def writer(request):
        connection = CoordinationDatabase(db.path,authority_domain='domain',busy_ms=2000)
        local_store = CandidateStore(store.root)
        try:
            kernel = manager(connection,local_store)
            barrier.wait(timeout=5)
            try:
                kernel.switch(request,actor='worker',now=101,authorize=authorized)
                return 'committed'
            except CandidateError: return 'conflict'
        finally: local_store.close(); connection.close()
    with ThreadPoolExecutor(2) as pool: results = list(pool.map(writer,requests))
    assert sorted(results) == ['committed','conflict'] and target(db) == (2,post)
    assert len(db.connection.execute('SELECT * FROM version_switch_receipts').fetchall()) == 1
    db.check_integrity()


def rollback_plan(setup, generation=2):
    return setup[2].create_rollback_plan('target','instance','apply','forward',generation,
        deletion_reasons={'tree/config.json':'return to verified previous tree'}, actor='worker',now=101,authorize=authorized)


def test_exact_postimage_rollback_advances_generation_and_retains_original_receipts(setup):
    db, _, kernel, pre, post = setup
    digest,value = plan(setup); forward = switch(setup,intent(digest,value))
    rollback_digest,rollback = rollback_plan(setup)
    assert rollback['rollbackOf'] == sha(forward)
    rolled_back = switch(setup,intent(rollback_digest,rollback,business='rollback',action='rollback'))
    assert target(db) == (3,pre)
    assert codec.parse(rolled_back)['afterGeneration'] == 3
    assert kernel.lookup('target','instance','apply','forward',actor='worker',now=101,authorize=authorized) == forward
    assert len(db.connection.execute('SELECT * FROM version_switch_receipts').fetchall()) == 2
    db.check_integrity()


def test_aba_reference_and_later_user_edits_cannot_reuse_old_rollback(setup):
    db, store, kernel, pre, post = setup
    digest,value = plan(setup); switch(setup,intent(digest,value))
    rollback_digest,rollback = rollback_plan(setup)
    switch(setup,intent(rollback_digest,rollback,business='rollback',action='rollback'))
    # A -> B -> A -> B has the first B's candidate hash, a new generation.
    next_digest,next_plan = kernel.create_plan('target','instance',3,post,deletion_reasons=DELETIONS,actor='worker',now=101,authorize=authorized)
    switch(setup,intent(next_digest,next_plan,business='later'))
    assert target(db) == (4,post)
    with pytest.raises(CandidateError,match='postimage/generation conflict'): rollback_plan(setup,4)
    edit = store.root/post[7:] / 'tree/README.md'
    edit.chmod(0o600); edit.write_bytes(b'later user edit'); edit.chmod(0o400)
    with pytest.raises(CandidateError,match='content or mode'):
        kernel.create_plan('target','instance',4,pre,deletion_reasons={'tree/config.json':'rollback'},actor='worker',now=101,authorize=authorized)
    assert edit.read_bytes() == b'later user edit' and target(db) == (4,post)


def test_retained_native_facts_can_be_looked_up_during_closing_without_new_mutation(setup):
    db, _, kernel, pre, post = setup
    digest,value = plan(setup); raw = switch(setup,intent(digest,value))
    generation = db.connection.execute('SELECT generation FROM changes').fetchone()[0]
    db.begin_closing('project','change',generation,actor='admin',now=101,authorize=authorized)
    assert kernel.lookup('target','instance','apply','forward',actor='successor',now=101,authorize=authorized) == raw
    with pytest.raises(CoordinationError,match='parent'): rollback_plan(setup)
    assert target(db) == (2,post)


@pytest.mark.parametrize('cut', ['before-commit', 'after-commit'])
def test_process_death_at_cas_commit_is_reconciled_without_second_switch(setup,tmp_path,cut):
    db, store, kernel, pre, post = setup
    digest,value = plan(setup); request = intent(digest,value); durable_dispatch(db,request)
    path = tmp_path/'intent.json'; path.write_bytes(codec.canonical(request))
    program = '''import os,sys
from pathlib import Path
from dasops.protected.candidates import CandidateStore
from dasops.protected.candidates.versions import VersionTreeManager
from dasops.protected.sqlite.store import CoordinationDatabase
from dasops.standards_contracts import exact_json as codec
from tests.protected.test_version_trees import OWNERS,D,authorized
db=CoordinationDatabase(Path(sys.argv[1]),authority_domain='domain')
store=CandidateStore(Path(sys.argv[2]))
kernel=VersionTreeManager(db,store,ownership=OWNERS,tool_digest=D,policy_digest=D)
if sys.argv[4]=='before-commit':
    original=db._audit
    def cut(connection,event,actor,value):
        if event=='version_reference_switched': os._exit(31)
        return original(connection,event,actor,value)
    db._audit=cut
kernel.switch(codec.parse(Path(sys.argv[3]).read_bytes()),actor='worker',now=101,authorize=authorized)
os._exit(29)
'''
    result = subprocess.run([sys.executable,'-c',program,str(db.path),str(store.root),str(path),cut],
                            cwd=Path(__file__).resolve().parents[2], timeout=15)
    assert result.returncode == (31 if cut=='before-commit' else 29)
    assert target(db) == ((1,pre) if cut=='before-commit' else (2,post))
    raw = kernel.lookup('target','instance','apply','forward',actor='successor',now=101,authorize=authorized)
    if cut=='before-commit':
        assert raw is None
        raw = kernel.switch(request,actor='successor',now=101,authorize=authorized)
    else:
        assert raw and kernel.switch(request,actor='successor',now=101,authorize=authorized) == raw
    assert target(db) == (2,post)
    assert len(db.connection.execute('SELECT * FROM version_switch_receipts').fetchall()) == 1
    db.check_integrity()


def test_outbox_response_loss_reconciles_original_native_commit_without_redispatch(setup):
    db, _, kernel, pre, post = setup
    digest,value = plan(setup); request = intent(digest,value)
    class FixtureAdapter:
        calls = 0
        def execute(self,intent,*,deadline):
            self.calls += 1
            kernel.switch(intent,actor='worker',now=101,authorize=authorized)
            raise TimeoutError('lost response after actual version CAS')
        def lookup(self,intent,*,deadline):
            raw = kernel.lookup('target','instance','apply','forward',actor='successor',now=101,authorize=authorized)
            return Observation('confirmed',sha(encode_intent(intent)),'instance',raw)
    adapter = FixtureAdapter()
    def independently_read(intent, observation):
        row = db.connection.execute("SELECT native_bytes,request_digest FROM version_switch_receipts WHERE resource_id='target' AND business_id='forward'").fetchone()
        return bool(row and row['native_bytes'] == observation.native_receipt and row['request_digest'] == observation.request_digest)
    box = DurableOutbox(db,adapters={('target','instance','apply'):adapter},verify_observation=independently_read,execution_closed=lambda intent:True)
    box.submit(request,actor='worker',now=101,authorize=authorized)
    assert box.dispatch('target','apply','forward',actor='worker',now=101,authorize=authorized)['state'] == 'unknown'
    assert target(db) == (2,post)
    assert box.reconcile('target','apply','forward',actor='successor',now=101,authorize=authorized)['state'] == 'confirmed'
    assert adapter.calls == 1 and not db.connection.execute('SELECT * FROM completions').fetchall()
    db.check_integrity()


def test_orphan_or_missing_candidate_cannot_become_registered_reference(setup):
    db, store, kernel, pre, post = setup
    (store.root/post[7:]).rename(store.root/'quarantined-candidate')
    checkpoint = db.checkpoint()
    with pytest.raises(FileNotFoundError): plan(setup)
    assert target(db) == (1,pre) and db.checkpoint() == checkpoint


def test_publication_sync_failure_prevents_new_database_reference(setup,tmp_path,monkeypatch):
    db, store, kernel, pre, post = setup
    extra = tmp_path/'extra'; extra.mkdir()
    values = fixture(extra,content={'README.md':(b'third version fixture',False)})
    digest = receive(store,values)['candidateDigest']
    sync = os.fsync
    def fail_directory(descriptor):
        if descriptor == store._root_fd: raise OSError('registration root sync failed')
        return sync(descriptor)
    checkpoint = db.checkpoint()
    monkeypatch.setattr(os,'fsync',fail_directory)
    with pytest.raises(OSError,match='root sync failed'):
        kernel.register_candidate(digest,actor='worker',now=101,authorize=authorized)
    assert db.checkpoint() == checkpoint and target(db) == (1,pre)
    assert not db.connection.execute('SELECT * FROM candidate_objects WHERE candidate_digest=?',(digest,)).fetchall()
    monkeypatch.setattr(os,'fsync',sync)
    assert kernel.register_candidate(digest,actor='worker',now=101,authorize=authorized) == digest


def test_schema_history_and_generation_lineage_cannot_be_silently_rewritten(setup):
    db, _, _, pre, post = setup
    digest,value = plan(setup); switch(setup,intent(digest,value))
    for sql in ('DELETE FROM candidate_objects', 'DELETE FROM version_plans', 'DELETE FROM version_switch_receipts',
                "UPDATE version_targets SET resource_instance='alias'", "UPDATE version_plans SET payload_json='{}'"):
        with pytest.raises(sqlite3.IntegrityError): db.connection.execute(sql)
    db.connection.execute('UPDATE version_targets SET generation=4')
    with pytest.raises(CoordinationError,match='lineage'): db.check_integrity()
    db.connection.execute('UPDATE version_targets SET generation=2'); db.check_integrity()


def test_near_limit_registration_blocks_second_writer_then_recovers(setup, tmp_path, monkeypatch):
    """Real full-size readback and a second connection, with no weakened checks."""
    db, store, kernel, _, _ = setup
    limits = CandidateLimits()
    payload = b'x' * (limits.max_file_bytes - 128)
    content = {name: (payload, False) for name in ('README.md', 'src/run.py',
               'tests/test_source.txt', 'config.json')}
    assert limits.max_total_bytes - sum(len(value[0]) for value in content.values()) == 512
    source = tmp_path / 'near-limit'; source.mkdir()
    values = fixture(source, content=content, encoding='gzip-tar-ustar')
    digest = receive(store, values)['candidateDigest']
    ready, verifying, committed = threading.Event(), threading.Event(), threading.Event()
    original = store.confirm_for_registration

    def confirm(value):
        verifying.set()
        return original(value)

    monkeypatch.setattr(store, 'confirm_for_registration', confirm)

    def contender():
        other = CoordinationDatabase(db.path, authority_domain='domain', busy_ms=20)
        try:
            ready.set()
            assert verifying.wait(30)
            started = time.monotonic()
            with pytest.raises(sqlite3.OperationalError, match='locked'):
                other.create_budget('contended', 1, actor='admin', now=101, authorize=authorized)
            waited = time.monotonic() - started
            assert not other.connection.in_transaction
            assert not other.connection.execute("SELECT * FROM budgets WHERE budget_id='contended'").fetchall()
            assert committed.wait(30)
            checks = []
            def current(connection, operation, actor, epoch):
                checks.append(epoch)
                return authorized(connection, operation, actor, epoch)
            other.create_budget('contended', 1, actor='admin', now=102, authorize=current)
            assert checks == [1]  # Retry invokes current authorization, not an old snapshot.
            other.check_integrity()
            return waited
        finally:
            other.close()

    with ThreadPoolExecutor(max_workers=1) as workers:
        future = workers.submit(contender)
        assert ready.wait(30)
        started = time.monotonic()
        try:
            assert kernel.register_candidate(digest, actor='worker', now=101, authorize=authorized) == digest
        finally:
            committed.set()
        registration_seconds = time.monotonic() - started
        busy_seconds = future.result(timeout=30)
    assert db.connection.execute('SELECT candidate_digest FROM candidate_objects WHERE candidate_digest=?',
                                 (digest,)).fetchone()[0] == digest
    assert tuple(db.connection.execute("SELECT ceiling,reserved FROM budgets WHERE budget_id='contended'").fetchone()) == (1, 0)
    db.check_integrity()
    print(f'near-limit registration={registration_seconds:.3f}s; second-writer busy={busy_seconds:.3f}s')
