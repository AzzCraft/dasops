"""Real old claim/release -> fenced import -> installed current writer controls."""
from datetime import datetime, timezone, timedelta
from pathlib import Path
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from .test_lifecycle import active_claim, authorize
from dasops.protected import canonical_bytes, with_self_digest
from dasops.protected.claim import claim_ready
from dasops.protected.lifecycle import release_claim, reclaim_expired_claim
from dasops.protected.state_store import StateStoreError
from dasops.protected.sqlite import AuthorityRoute, CoordinationDatabase, CoordinationError, TaskKey, import_legacy
from dasops.standards_contracts.exact_json import parse
from dasops.protected.completion import abort_completion, publish_completion
from . import test_completion as completion

D1 = 'sha256:'+'1'*64


@pytest.fixture
def legacy(tmp_path):
    repo,store,worker = active_claim(tmp_path)
    challenge,response = authorize(store,worker,'release_authorization')
    result = release_claim(repo=repo,store=store,change_id='demo',task_id='T-002',owner='worker-01',
        worker_lock_path=worker,challenge_id=challenge['challengeId'],response=response,
        idempotency_key='legacy-import-release-0001')
    control = tmp_path/'new-authority'; control.mkdir(mode=0o700)
    db = CoordinationDatabase.create(control/'state.db',authority_domain='domain',instance_id='staged')
    mappings = [{'changeId':'demo','taskId':'T-002','obligationDigest':D1,'revision':3,'cycle':4}]
    now = int(datetime.now(timezone.utc).timestamp())+5
    try: yield repo,store,worker,result,db,mappings,now
    finally: db.close()


def granted(c,o,a,e,subject):
    assert c.in_transaction and subject
    return a=='admin' and e in (1,2)


def run_import(legacy, **overrides):
    repo,store,worker,result,db,mappings,now = legacy
    kwargs = dict(project_id='project',mappings=mappings,actor='admin',now=now,approve=granted)
    kwargs.update(overrides)
    return import_legacy(store,db,**kwargs)


def assert_inactive(db, now):
    with pytest.raises(CoordinationError,match='inactive'):
        db.create_budget('bypass',1,actor='admin',now=now,authorize=lambda *args:True)
    with pytest.raises(CoordinationError,match='inactive'):
        with db.read_snapshot(): pass


def test_real_released_import_retains_originals_fences_old_entries_and_activates_once(legacy,tmp_path):
    repo,store,worker,result,db,mappings,now = legacy
    head = repo.head(); original = store.read_state('demo','T-002')
    receipt = store.receipt_path(result['operationId'],'release-result').read_bytes()
    fence = run_import(legacy)
    assert run_import(legacy)==fence
    imported = parse(db.connection.execute("SELECT body FROM audit WHERE event='legacy_import_staged'").fetchone()[0].encode())
    assert imported['source']['canonicalCommit']==head
    assert imported['source']['originals'][f"receipts/{result['operationId']}/release-result.json"].encode()==receipt
    assert imported['source']['originals']['states/demo/T-002.json'].encode()==canonical_bytes(original)
    for table in ('business_actions','budgets','completions'):
        assert db.connection.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]==0
    assert db.connection.execute('SELECT revision,cycle FROM tasks').fetchone()[:]==(3,4)
    assert_inactive(db,now)
    with pytest.raises(StateStoreError,match='fenced'):
        claim_ready(repo=repo,store=store,change_id='demo',owner='worker-02',
                    worker_lock_path=worker,idempotency_key='legacy-import-next-claim')
    with pytest.raises(StateStoreError,match='fenced'): store.write_state(original)
    with pytest.raises(StateStoreError,match='fenced'):
        store.write_receipt(result['operationId'],'release-result',result)
    assert repo.head()==head and store.read_state('demo','T-002')==original
    witness = tmp_path/'independent-route'; witness.mkdir(mode=0o700)
    route = AuthorityRoute(witness/'route.json',authority_domain='domain')
    route.enroll(db,actor='admin',now=now+1,approve=granted)
    route.freeze(db,destination=db.path.parent/'next.db',new_instance='active-new',migration_id='legacy-forward',
                 actor='admin',now=now+2,approve=granted)
    route.stage(db); route.activate(actor='admin',now=now+3,approve=granted)
    active = route.open_current()
    try:
        key = TaskKey('domain','project','demo','T-002')
        generation = active.claim(key,D1,actor='new-worker',expires_at=now+100,now=now+4,
                                  authorize=lambda c,o,a,e:e==2)
        assert generation==original['leaseGeneration']+1
        assert active.connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0]==0
        assert parse(active.connection.execute("SELECT body FROM audit WHERE event='legacy_import_staged'").fetchone()[0].encode())==imported
        active.check_integrity()
    finally: active.close()


@pytest.mark.parametrize('fault',['missing-field','foreign-task','duplicate','denied','future-source','unsafe-generation','pending','active','completed','missing-receipt','unfinished-wal','symlink'])
def test_unsupported_legacy_input_refuses_before_fencing_or_import(legacy,fault):
    repo,store,worker,result,db,mappings,now = legacy
    options = {}
    if fault=='missing-field': del mappings[0]['cycle']
    if fault=='foreign-task': mappings[0]['taskId']='other'
    if fault=='duplicate': mappings.append(dict(mappings[0]))
    if fault=='denied': options['approve']=lambda *args:False
    if fault=='future-source': options['now']=1
    if fault=='unsafe-generation':
        state=store.read_state('demo','T-002');state['leaseGeneration']=9007199254740992
        store.write_state(with_self_digest({k:v for k,v in state.items() if k!='recordDigest'}))
        receipt=dict(result);receipt['leaseGeneration']=state['leaseGeneration'];receipt.pop('recordDigest')
        store.receipt_path(result['operationId'],'release-result').write_bytes(canonical_bytes(with_self_digest(receipt)))
    if fault in ('pending','active','completed'):
        state=store.read_state('demo','T-002');state['status']='release_pending' if fault=='pending' else fault
        store.write_state(with_self_digest({k:v for k,v in state.items() if k!='recordDigest'}))
    if fault=='missing-receipt': store.receipt_path(result['operationId'],'release-result').unlink()
    if fault=='unfinished-wal': (store.operation_dir(result['operationId'])/'readback_complete.json').unlink()
    if fault=='symlink':
        path=store.state_path('demo','T-002'); other=path.with_name('original');path.rename(other);path.symlink_to(other)
    with pytest.raises((CoordinationError,ValueError,KeyError)): run_import(legacy,**options)
    assert not (store.root/'migration.json').exists()
    assert db.connection.execute('SELECT COUNT(*) FROM tasks').fetchone()[0]==0
    assert db.connection.execute('SELECT COUNT(*) FROM audit').fetchone()[0]==0


@pytest.mark.parametrize('boundary',['before-fence','after-fence','before-commit'])
def test_interrupted_import_retains_fence_and_exact_retry(legacy,monkeypatch,boundary):
    import dasops.protected.sqlite.legacy as module
    repo,store,worker,result,db,mappings,now = legacy
    original_write=module.atomic_write; original_audit=db._audit
    def write(*args,**kwargs):
        if boundary=='before-fence': raise OSError('injected fence publication failure')
        original_write(*args,**kwargs)
        if boundary=='after-fence': raise OSError('injected durable fence response loss')
    def audit(*args,**kwargs):
        original_audit(*args,**kwargs)
        if boundary=='before-commit': raise OSError('injected SQL commit interruption')
    monkeypatch.setattr(module,'atomic_write',write);monkeypatch.setattr(db,'_audit',audit)
    with pytest.raises(OSError): run_import(legacy)
    assert db.connection.execute('SELECT COUNT(*) FROM tasks').fetchone()[0]==0
    assert (store.root/'migration.json').exists() == (boundary!='before-fence')
    if boundary!='before-fence':
        with pytest.raises(StateStoreError): store.write_state(store.read_state('demo','T-002'))
    monkeypatch.setattr(module,'atomic_write',original_write);monkeypatch.setattr(db,'_audit',original_audit)
    run_import(legacy)
    assert db.connection.execute("SELECT COUNT(*) FROM audit WHERE event='legacy_import_staged'").fetchone()[0]==1
    mappings[0]['cycle']+=1
    with pytest.raises(CoordinationError,match='different'): run_import(legacy)
    assert_inactive(db,now)


def test_real_legacy_writer_must_finish_before_global_fence(legacy):
    repo,store,worker,result,db,mappings,now = legacy
    entered=threading.Event(); release=threading.Event()
    def writer():
        with store.change_lock('demo'):
            entered.set(); assert release.wait(5)
            store.write_state(store.read_state('demo','T-002'))
    with ThreadPoolExecutor(max_workers=1) as pool:
        future=pool.submit(writer)
        try:
            assert entered.wait(5)
            with pytest.raises(StateStoreError,match='busy'): run_import(legacy)
            assert not (store.root/'migration.json').exists()
        finally: release.set()
        future.result(timeout=5)
    run_import(legacy)
    with pytest.raises(StateStoreError):
        with store.change_lock('different-change'): pass


@pytest.mark.parametrize('target',['subject','sql','source'])
def test_approval_cannot_mutate_approved_import(legacy,target):
    repo,store,worker,result,db,mappings,now = legacy
    def mutate(c,o,a,e,subject):
        if target=='subject': subject['mappings'][0]['obligationDigest']='sha256:'+'2'*64
        if target=='sql': c.execute("INSERT INTO budgets VALUES ('domain','injected',1,0)")
        if target=='source':
            state=store.read_state('demo','T-002');state['owner']='changed'
            store.state_path('demo','T-002').write_bytes(canonical_bytes(with_self_digest({k:v for k,v in state.items() if k!='recordDigest'})))
        return True
    with pytest.raises(CoordinationError): run_import(legacy,approve=mutate)
    assert db.connection.execute('SELECT COUNT(*) FROM tasks').fetchone()[0]==0
    assert db.connection.execute('SELECT COUNT(*) FROM budgets').fetchone()[0]==0


def test_import_refuses_nonempty_destination_before_fencing(legacy):
    repo,store,worker,result,db,mappings,now = legacy
    db.create_budget('unrelated',1,actor='admin',now=now,authorize=lambda *args:True)
    with pytest.raises(CoordinationError,match='empty'):run_import(legacy)
    assert not (store.root/'migration.json').exists()


@pytest.mark.parametrize('fault',['task','lease','extra-fact'])
def test_exact_retry_refuses_changed_staged_facts(legacy,fault):
    repo,store,worker,result,db,mappings,now = legacy
    run_import(legacy)
    if fault=='task':db.connection.execute('UPDATE tasks SET cycle=cycle+1')
    if fault=='lease':db.connection.execute('UPDATE leases SET expires_at=?',(now+100,))
    if fault=='extra-fact':db.connection.execute("INSERT INTO budgets VALUES ('domain','injected',1,0)")
    with pytest.raises(CoordinationError):run_import(legacy)
    assert_inactive(db,now)


@pytest.mark.parametrize('boundary',['after-fence','before-commit','after-commit'])
def test_real_import_process_exit_recovers_exact_original_without_new_authority(legacy,boundary,tmp_path):
    repo,store,worker,result,db,mappings,now = legacy
    code = '''
import json,os,sys
from dasops.protected.git_canonical import BareCanonicalRepo
from dasops.protected.state_store import ProtectedStateStore
from dasops.protected.sqlite import CoordinationDatabase,import_legacy
import dasops.protected.sqlite.legacy as module
store=ProtectedStateStore(BareCanonicalRepo(__import__('pathlib').Path(sys.argv[1])))
db=CoordinationDatabase(sys.argv[2],authority_domain='domain');boundary=sys.argv[3]
write=module.atomic_write;audit=db._audit
def failed_write(*args,**kwargs):
 write(*args,**kwargs)
 if boundary=='after-fence':os._exit(71)
def failed_audit(*args,**kwargs):
 audit(*args,**kwargs)
 if boundary=='before-commit':os._exit(72)
def committed():os._exit(73)
module.atomic_write=failed_write;db._audit=failed_audit;db.check_integrity=committed
import_legacy(store,db,project_id='project',mappings=json.loads(sys.argv[4]),actor='admin',now=int(sys.argv[5]),approve=lambda *args:True)
'''
    run = subprocess.run([sys.executable,'-B','-c',code,str(repo.path),str(db.path),boundary,
                          canonical_bytes(mappings).decode(),str(now)],capture_output=True,timeout=20)
    (tmp_path/'process.stdout').write_bytes(run.stdout);(tmp_path/'process.stderr').write_bytes(run.stderr)
    assert run.returncode=={'after-fence':71,'before-commit':72,'after-commit':73}[boundary],run.stderr.decode()
    with pytest.raises(StateStoreError): store.write_state(store.read_state('demo','T-002'))
    run_import(legacy,now=now+1)
    assert db.connection.execute('SELECT COUNT(*) FROM tasks').fetchone()[0]==1
    assert db.connection.execute("SELECT COUNT(*) FROM audit WHERE event='legacy_import_staged'").fetchone()[0]==1
    assert_inactive(db,now+1)


def test_real_reclaimed_import_keeps_generations_and_original_independent_role_receipt(tmp_path,monkeypatch):
    repo,store,worker = active_claim(tmp_path)
    state = store.read_state('demo','T-002')
    future = datetime.fromisoformat(state['leaseExpiresAt'].replace('Z','+00:00'))+timedelta(seconds=1)
    monkeypatch.setattr('dasops.protected.lifecycle._now',lambda:future)
    authorization = with_self_digest(dict(schema='protected-reclaim-authorization/v1',
        authorizationId='RECLAIM-IMPORT-001',authorityRef='test-root/epoch-1',approvalSetDigest=D1,
        changeId='demo',taskId='T-002',expectedOwner=state['owner'],claimGeneration=state['claimGeneration'],
        leaseGeneration=state['leaseGeneration'],canonicalCommit=state['canonicalCommit'],
        priorStateDigest=state['recordDigest'],reason='lease_expired',
        requiredRoles=['anchor_owner','task_governance','verifier'],issuedAt='2020-01-01T00:00:00Z',expiresAt='2099-01-01T00:00:00Z'))
    receipt = reclaim_expired_claim(repo=repo,store=store,change_id='demo',task_id='T-002',
        prior_owner=state['owner'],worker_lock_path=worker,authorization=authorization,
        authorization_verifier=lambda *args:dict(anchor_owner='a',task_governance='b',verifier='c'),
        idempotency_key='legacy-import-reclaim-0001')
    control=tmp_path/'new-authority';control.mkdir(mode=0o700)
    db=CoordinationDatabase.create(control/'state.db',authority_domain='domain',instance_id='staged')
    try:
        import_legacy(store,db,project_id='project',mappings=[dict(changeId='demo',taskId='T-002',
            obligationDigest=D1,revision=1,cycle=1)],actor='admin',now=int(future.timestamp())+1,approve=granted)
        body=parse(db.connection.execute("SELECT body FROM audit WHERE event='legacy_import_staged'").fetchone()[0].encode())
        assert body['source']['originals'][f"receipts/{receipt['operationId']}/reclaim-result.json"].encode()==canonical_bytes(receipt)
        assert db.connection.execute('SELECT generation FROM leases').fetchone()[0]==state['leaseGeneration']
        assert db.connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0]==0
    finally:db.close()


@pytest.mark.parametrize('fault',['commit','rollback','script','caught-write'])
def test_import_approval_cannot_end_transaction_or_publish_a_fence(legacy,fault):
    from .test_sqlite_authority import bad_sql_approval, _state_digest
    _,store,_,_,db,_,_=legacy
    before=_state_digest(db.connection)
    with pytest.raises(CoordinationError,match='approval modified'):
        run_import(legacy,approve=lambda c,*args:bad_sql_approval(c,fault))
    assert _state_digest(db.connection)==before and not (store.root/'migration.json').exists()
    run_import(legacy)


def real_history(path, status):
    """Real original v1 writers, including recovery; never rename a status."""
    if status=='released-after-cas':
        repo,store,worker = active_claim(path)
        challenge,response = authorize(store,worker,'release_authorization')
        kwargs=dict(repo=repo,store=store,change_id='demo',task_id='T-002',owner='worker-01',
                    worker_lock_path=worker,challenge_id=challenge['challengeId'],response=response,
                    idempotency_key='legacy-window-release-0001')
        append=store.append_wal
        def failed(value):
            if value['phase']=='cas_applied':raise OSError('original release readback interrupted')
            return append(value)
        store.append_wal=failed
        with pytest.raises(OSError):release_claim(**kwargs)
        assert store.read_state('demo','T-002')['status']=='release_pending'
        before=(repo.head(),canonical_bytes(store.read_state('demo','T-002')))
        store.append_wal=append
        def recover():return release_claim(**kwargs)
    else:
        repo,store,worker=completion.active_claim(path)
        before=None
        if status!='expired-active':
            request=completion.prepare(repo,store,worker,'legacy-window-completion-0001')
            verification=completion.verification_for(request)
            approval=completion.approval_for(request,'publish',request['baseCommit'],verification['recordDigest'])
            kwargs=dict(repo=repo,store=store,operation_id=request['operationId'],approval=approval,
                        verification=verification,approval_verifier=completion.role_verifier)
            if status=='completed':publish_completion(**kwargs)
            elif status=='aborted-before-cas':
                before=(repo.head(),canonical_bytes(store.read_state('demo','T-002')))
                def recover():
                    return abort_completion(repo=repo,store=store,operation_id=request['operationId'],
                        approval=completion.approval_for(request,'abort',repo.head(),None),
                        approval_verifier=completion.role_verifier)
            else:
                write=store.write_state
                def failed(value):
                    if value['status']=='completed':raise OSError('original completed state interrupted')
                    return write(value)
                store.write_state=failed
                with pytest.raises(OSError):publish_completion(**kwargs)
                assert repo.head()==request['candidateCommit']
                before=(repo.head(),canonical_bytes(store.read_state('demo','T-002')))
                store.write_state=write;kwargs['approval_verifier']=None
                def recover():return publish_completion(**kwargs)
    state=store.read_state('demo','T-002')
    now=int(datetime.fromisoformat(state['leaseExpiresAt'].replace('Z','+00:00')).timestamp())+5
    return repo,store,worker,now,before,(recover if before else None)


@pytest.mark.parametrize('status',['expired-active','completed','aborted-before-cas','completed-after-cas','released-after-cas'])
def test_real_legacy_windows_recover_original_then_import_history_without_current_done(tmp_path,status):
    repo,store,worker,now,pending,recover=real_history(tmp_path/'old',status)
    directory=tmp_path/'new';directory.mkdir(mode=0o700)
    db=CoordinationDatabase.create(directory/'state.db',authority_domain='domain',instance_id='staged')
    mapping=[dict(changeId='demo',taskId='T-002',obligationDigest=D1,revision=3,cycle=4)]
    try:
        kwargs=dict(project_id='project',mappings=mapping,actor='admin',now=now,approve=granted)
        if pending:
            with pytest.raises(CoordinationError):import_legacy(store,db,**kwargs)
            assert not (store.root/'migration.json').exists()
            assert repo.head()==pending[0] and canonical_bytes(store.read_state('demo','T-002'))==pending[1]
            assert db.connection.execute('SELECT COUNT(*) FROM audit').fetchone()[0]==0
            receipt=recover();assert recover()==receipt
            if status.endswith('after-cas'):assert repo.head()==pending[0]
        original=store.read_state('demo','T-002');head=repo.head()
        fence=import_legacy(store,db,**kwargs);assert import_legacy(store,db,**kwargs)==fence
        body=parse(db.connection.execute("SELECT body FROM audit WHERE event='legacy_import_staged'").fetchone()[0].encode())
        assert body['source']['originals']['states/demo/T-002.json'].encode()==canonical_bytes(original)
        assert_inactive(db,now)
        witness=tmp_path/'route';witness.mkdir(mode=0o700);route=AuthorityRoute(witness/'route.json',authority_domain='domain')
        route.enroll(db,actor='admin',now=now+1,approve=granted)
        route.freeze(db,destination=directory/'active.db',new_instance='next',migration_id='original-history',actor='admin',now=now+2,approve=granted)
        route.stage(db);route.activate(actor='admin',now=now+3,approve=granted)
        active=route.open_current()
        try:
            for table in ('budgets','business_actions','completions','completion_bindings','reservations','action_payloads'):
                assert active.connection.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]==0
            assert active.claim(TaskKey('domain','project','demo','T-002'),D1,actor='new-worker',now=now+4,
                expires_at=now+100,authorize=lambda c,o,a,e:e==2)==original['leaseGeneration']+1
            active.check_integrity()
        finally:active.close()
        with pytest.raises(StateStoreError):store.write_state(original)
        assert repo.head()==head and store.read_state('demo','T-002')==original
    finally:db.close()


@pytest.mark.parametrize('fault',['live-lease','activation','challenge','canonical-task','completed-result','decision','consumption','request-subject','request-git','denied','coupled-token','coupled-git','claim-kind','completed-claim-kind'])
def test_real_legacy_history_refuses_live_or_mismatched_originals_before_fencing(tmp_path,fault):
    import json
    completed=fault not in ('live-lease','activation','challenge','canonical-task','coupled-token','claim-kind')
    repo,store,worker,now,_,_=real_history(tmp_path/'old','completed' if completed else 'expired-active')
    state=store.read_state('demo','T-002')
    if fault=='live-lease':now=int(datetime.now(timezone.utc).timestamp())+1
    paths=list((store.root/'receipts').rglob('*.json'))
    schemas={'activation':'protected-activation-receipt/v1','completed-result':'protected-completion-result/v1',
             'decision':'protected-completion-decision-intent/v1','consumption':'protected-challenge-consumption/v1',
             'request-subject':'protected-completion-request/v1','request-git':'protected-completion-request/v1'}
    if fault in schemas:
        p=next(p for p in paths if json.loads(p.read_text())['schema']==schemas[fault]);v=json.loads(p.read_text())
        if fault=='activation':v['tokenHash']=D1
        elif fault=='completed-result':v['canonicalReadback']=repo._run('rev-parse',repo.head()+'^').stdout.decode().strip()
        elif fault=='decision':v['approvalDigest']=D1
        elif fault=='consumption':v['inputDigest']=D1
        elif fault=='request-subject':v['owner']='other'
        else:v['changedPaths']=['other.txt']
        v.pop('recordDigest');p.write_bytes(canonical_bytes(with_self_digest(v)))
    if fault=='challenge':
        p=next((store.root/'challenges').glob('*.json'));v=json.loads(p.read_text());v['owner']='other';v.pop('recordDigest');p.write_bytes(canonical_bytes(with_self_digest(v)))
    if fault=='canonical-task':
        state['canonicalCommit']=repo._run('rev-parse',repo.head()+'^').stdout.decode().strip();state.pop('recordDigest');store.write_state(with_self_digest(state))
    if fault=='coupled-token':
        state['tokenHash']=D1;state.pop('recordDigest');store.write_state(with_self_digest(state))
        p=next(p for p in paths if json.loads(p.read_text())['schema']=='protected-activation-receipt/v1')
        value=json.loads(p.read_text());value['tokenHash']=D1;value.pop('recordDigest');p.write_bytes(canonical_bytes(with_self_digest(value)))
    if fault=='coupled-git':
        p=next(p for p in paths if json.loads(p.read_text())['schema']=='protected-completion-request/v1')
        value=json.loads(p.read_text());value['changedPaths']=['openspec/changes/demo/tasks.md'];value.pop('recordDigest')
        request=with_self_digest(value);p.write_bytes(canonical_bytes(request))
        for p in paths:
            value=json.loads(p.read_text())
            if value['schema'] in ('protected-completion-result/v1','protected-completion-decision-intent/v1'):
                value['requestDigest']=request['recordDigest'];value.pop('recordDigest');p.write_bytes(canonical_bytes(with_self_digest(value)))
    if fault in ('claim-kind','completed-claim-kind'):
        p=store.receipt_path(state['operationId'],'claim-result');value=json.loads(p.read_text())
        value.pop('recordDigest');value.pop('workerLockSha256')
        value.update(schema='protected-release-result/v1',outcome='released',claimOperationId=state['operationId'],
            releasedAt=state['updatedAt'],workerLockDisposition='deleted_with_filesystem_residuals_unclaimed',
            authorizationChallengeDigest=D1,authorizationResponseDigest=D1)
        value=with_self_digest(value);store.registry.validate(value);p.write_bytes(canonical_bytes(value))
    directory=tmp_path/'new';directory.mkdir(mode=0o700)
    db=CoordinationDatabase.create(directory/'state.db',authority_domain='domain',instance_id='staged')
    try:
        head=repo.head();original=store.state_path('demo','T-002').read_bytes()
        with pytest.raises(CoordinationError):
            import_legacy(store,db,project_id='project',mappings=[dict(changeId='demo',taskId='T-002',obligationDigest=D1,revision=3,cycle=4)],
                actor='admin',now=now,approve=(lambda *args:False) if fault=='denied' else granted)
        assert not (store.root/'migration.json').exists()
        assert db.connection.execute('SELECT COUNT(*) FROM audit').fetchone()[0]==0
        assert db.connection.execute('SELECT COUNT(*) FROM tasks').fetchone()[0]==0
        assert repo.head()==head and store.state_path('demo','T-002').read_bytes()==original
    finally:db.close()


@pytest.mark.parametrize('status',['expired-active','completed','aborted-before-cas','completed-after-cas','released-after-cas'])
@pytest.mark.parametrize('boundary',['after-fence','before-commit','after-commit'])
def test_real_history_import_process_exit_keeps_original_key_and_no_current_done(tmp_path,status,boundary):
    repo,store,worker,now,pending,recover=real_history(tmp_path/'old',status)
    if recover:recover()
    directory=tmp_path/'new';directory.mkdir(mode=0o700)
    db=CoordinationDatabase.create(directory/'state.db',authority_domain='domain',instance_id='staged')
    mappings=[dict(changeId='demo',taskId='T-002',obligationDigest=D1,revision=3,cycle=4)]
    try:
        original=store.state_path('demo','T-002').read_bytes();head=repo.head()
        test_real_import_process_exit_recovers_exact_original_without_new_authority(
            (repo,store,worker,None,db,mappings,now),boundary,tmp_path)
        assert store.state_path('demo','T-002').read_bytes()==original and repo.head()==head
        for table in ('budgets','business_actions','completions','completion_bindings'):
            assert db.connection.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]==0
    finally:db.close()


@pytest.mark.parametrize('boundary', ['lock','candidate_prepared','pending-state','cas','cas_applied',
                                     'final-lock','final-state','receipt','readback_complete'])
def test_real_recovered_claim_activates_imports_history_and_new_claim_once(tmp_path,boundary):
    from .test_claim import interrupted_claim
    from dasops.protected.claim import issue_activation_challenge, activation_response, activate_claim, read_worker_lock
    import base64
    repo,store,worker,claim_kwargs=interrupted_claim(tmp_path/'old',boundary)
    lock=read_worker_lock(worker,store);result=claim_ready(**claim_kwargs)
    assert claim_ready(**claim_kwargs)==result
    assert all(read_worker_lock(worker,store)[k]==lock[k] for k in
               ('tokenBase64','tokenHash','claimGeneration','leaseGeneration','leaseExpiresAt'))
    challenge=issue_activation_challenge(store=store,change_id='demo',task_id='T-002',owner='worker-01')
    activate_claim(store=store,change_id='demo',task_id='T-002',owner='worker-01',worker_lock_path=worker,
        challenge_id=challenge['challengeId'],response=activation_response(base64.urlsafe_b64decode(lock['tokenBase64']+'='),challenge))
    original=store.read_state('demo','T-002');head=repo.head()
    now=int(datetime.fromisoformat(original['leaseExpiresAt'].replace('Z','+00:00')).timestamp())+5
    data=tmp_path/'new';data.mkdir(mode=0o700)
    db=CoordinationDatabase.create(data/'staged.db',authority_domain='domain',instance_id='staged')
    try:
        options=dict(project_id='project',mappings=[dict(changeId='demo',taskId='T-002',obligationDigest=D1,revision=3,cycle=4)],
                     actor='admin',now=now,approve=granted)
        fence=import_legacy(store,db,**options);assert import_legacy(store,db,**options)==fence
        assert_inactive(db,now)
        witness=tmp_path/'route';witness.mkdir(mode=0o700)
        route=AuthorityRoute(witness/'route.json',authority_domain='domain')
        route.enroll(db,actor='admin',now=now+1,approve=granted)
        route.freeze(db,destination=data/'active.db',new_instance='next',migration_id='recovered-claim',actor='admin',now=now+2,approve=granted)
        route.stage(db);route.activate(actor='admin',now=now+3,approve=granted)
        active=route.open_current()
        try:
            assert active.claim(TaskKey('domain','project','demo','T-002'),D1,actor='new-worker',now=now+4,
                expires_at=now+100,authorize=lambda c,o,a,e:e==2)==original['leaseGeneration']+1
            for table in ('budgets','business_actions','completions','completion_bindings','reservations','action_payloads'):
                assert active.connection.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]==0
            audit=parse(active.connection.execute("SELECT body FROM audit WHERE event='legacy_import_staged'").fetchone()[0].encode())
            assert audit['source']['originals'][str(store.receipt_path(result['operationId'],'claim-result').relative_to(store.root))]==canonical_bytes(result).decode()
            active.check_integrity()
        finally:active.close()
        with pytest.raises(StateStoreError):claim_ready(**claim_kwargs)
        assert repo.head()==head and store.read_state('demo','T-002')==original
    finally:db.close()


def expired_unactivated_claim(tmp_path, monkeypatch, boundary='cas'):
    """Original process loss; advance TEST time, never edit the persisted lease."""
    from .test_claim import interrupted_claim
    import dasops.protected.claim as claim_module
    import dasops.protected.lifecycle as lifecycle_module
    repo,store,worker,claim_kwargs=interrupted_claim(tmp_path/'old',boundary)
    policy=store.policy()
    (store.root/'policy.json').write_bytes(canonical_bytes({**policy,
        'allowedOperations':['activate','claim','reclaim']}))
    lock=claim_module.read_worker_lock(worker,store)
    now=datetime.fromisoformat(lock['leaseExpiresAt'].replace('Z','+00:00'))+timedelta(seconds=5)
    monkeypatch.setattr(claim_module,'_now',lambda:now)
    monkeypatch.setattr(lifecycle_module,'_now',lambda:now)
    result=claim_ready(**claim_kwargs)
    assert claim_ready(**claim_kwargs)==result
    assert all(claim_module.read_worker_lock(worker,store)[k]==lock[k] for k in
        ('tokenBase64','tokenHash','claimGeneration','leaseGeneration','leaseExpiresAt'))
    state=store.read_state('demo','T-002')
    authorization=with_self_digest(dict(schema='protected-reclaim-authorization/v1',
        authorizationId='TEST-EXPIRED-UNACTIVATED',authorityRef='TEST/root',approvalSetDigest=D1,
        changeId='demo',taskId='T-002',expectedOwner='worker-01',
        claimGeneration=state['claimGeneration'],leaseGeneration=state['leaseGeneration'],
        canonicalCommit=state['canonicalCommit'],priorStateDigest=state['recordDigest'],reason='lease_expired',
        requiredRoles=['anchor_owner','task_governance','verifier'],issuedAt='2020-01-01T00:00:00Z',expiresAt='2099-01-01T00:00:00Z'))
    def roles(document,subject):
        assert document==authorization
        assert subject=={k:authorization[k] for k in ('changeId','taskId','expectedOwner','claimGeneration',
            'leaseGeneration','canonicalCommit','priorStateDigest','reason')}
        return dict(anchor_owner='TEST-owner',task_governance='TEST-governance',verifier='TEST-verifier')
    kwargs=dict(repo=repo,store=store,change_id='demo',task_id='T-002',prior_owner='worker-01',
        worker_lock_path=worker,authorization=authorization,authorization_verifier=roles,
        idempotency_key='expired-unactivated-reclaim-0001')
    return repo,store,worker,result,state,now,kwargs


@pytest.mark.parametrize('boundary',['cas','receipt','readback_complete'])
def test_expired_unactivated_original_claim_reclaims_imports_and_new_claim(tmp_path,monkeypatch,boundary):
    from dasops.protected.claim import issue_activation_challenge, ProtectedClaimError
    repo,store,worker,claim_result,prior,clock,kwargs=expired_unactivated_claim(tmp_path,monkeypatch,boundary)
    with pytest.raises(ProtectedClaimError,match='lease expired'):
        issue_activation_challenge(store=store,change_id='demo',task_id='T-002',owner='worker-01')
    original_wal={str(p):p.read_bytes() for p in store.operation_dir(claim_result['operationId']).glob('*.json')}
    reclaimed=reclaim_expired_claim(**kwargs)
    assert reclaim_expired_claim(**kwargs)==reclaimed
    terminal=store.read_state('demo','T-002')
    assert terminal['status']=='reclaimed' and not worker.exists()
    assert all(terminal[k]==prior[k] for k in ('leaseExpiresAt','claimGeneration','leaseGeneration','tokenHash'))
    assert reclaimed['baseCommit']==prior['canonicalCommit'] and reclaimed['candidateCommit']==repo.head()
    assert repo._run('rev-parse',repo.head()+'^').stdout.decode().strip()==prior['canonicalCommit']
    assert {p:Path(p).read_bytes() for p in original_wal}==original_wal
    data=tmp_path/'new';data.mkdir(mode=0o700)
    db=CoordinationDatabase.create(data/'staged.db',authority_domain='domain',instance_id='staged')
    now=int(clock.timestamp())+5
    try:
        options=dict(project_id='project',mappings=[dict(changeId='demo',taskId='T-002',obligationDigest=D1,revision=3,cycle=4)],
            actor='admin',now=now,approve=granted)
        fence=import_legacy(store,db,**options);assert import_legacy(store,db,**options)==fence
        body=parse(db.connection.execute("SELECT body FROM audit WHERE event='legacy_import_staged'").fetchone()[0].encode())
        assert body['source']['originals'][str(store.receipt_path(reclaimed['operationId'],'reclaim-result').relative_to(store.root))]==canonical_bytes(reclaimed).decode()
        assert not any('activation-receipt' in value for value in body['source']['originals'].values())
        witness=tmp_path/'route';witness.mkdir(mode=0o700)
        route=AuthorityRoute(witness/'route.json',authority_domain='domain')
        route.enroll(db,actor='admin',now=now+1,approve=granted)
        route.freeze(db,destination=data/'active.db',new_instance='next',migration_id='expired-unactivated',actor='admin',now=now+2,approve=granted)
        route.stage(db);route.activate(actor='admin',now=now+3,approve=granted)
        active=route.open_current()
        try:
            assert active.claim(TaskKey('domain','project','demo','T-002'),D1,actor='new-worker',now=now+4,
                expires_at=now+100,authorize=lambda c,o,a,e:e==2)==prior['leaseGeneration']+1
            for table in ('budgets','business_actions','completions','completion_bindings','reservations','action_payloads'):
                assert active.connection.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]==0
            active.check_integrity()
        finally:active.close()
        assert store.read_state('demo','T-002')==terminal and repo.head()==reclaimed['candidateCommit']
    finally:db.close()


@pytest.mark.parametrize('fault',['live','owner','subject','roles','no-verifier','head','lock-generation','lock-token','policy','matching-generation-drift'])
def test_expired_unactivated_reclaim_refuses_without_original_authority(tmp_path,monkeypatch,fault):
    from .test_claim import claim_files
    import dasops.protected.lifecycle as module
    from dasops.protected.claim import read_worker_lock, ProtectedClaimError
    repo,store,worker,_,state,clock,kwargs=expired_unactivated_claim(tmp_path,monkeypatch)
    if fault=='live':monkeypatch.setattr(module,'_now',lambda:clock-timedelta(seconds=10))
    if fault=='owner':kwargs['prior_owner']='other'
    if fault=='subject':kwargs['authorization']=with_self_digest({**{k:v for k,v in kwargs['authorization'].items() if k!='recordDigest'},'claimGeneration':2})
    if fault=='roles':kwargs['authorization_verifier']=lambda *args:dict(anchor_owner='same',task_governance='same',verifier='same')
    if fault=='no-verifier':kwargs['authorization_verifier']=None
    if fault=='head':
        path='openspec/changes/demo/tasks.md'
        candidate,_=repo.build_single_path_commit(base_commit=repo.head(),path=path,
            content=repo.read_path(repo.head(),path).replace(b'Pull me',b'Changed Task'),
            message='TEST canonical drift',timestamp=clock.isoformat().replace('+00:00','Z'),scratch_root=store.scratch_root)
        repo.cas(old_commit=repo.head(),new_commit=candidate)
    if fault in ('lock-generation','lock-token'):
        lock=read_worker_lock(worker,store)
        lock['leaseGeneration' if fault=='lock-generation' else 'tokenBase64']=2 if fault=='lock-generation' else 'A'*43
        worker.write_bytes(canonical_bytes(lock))
    if fault=='matching-generation-drift':
        changed=with_self_digest({**{k:v for k,v in state.items() if k!='recordDigest'},'leaseGeneration':2})
        store.write_state(changed)
        lock=read_worker_lock(worker,store);lock['leaseGeneration']=2;worker.write_bytes(canonical_bytes(lock))
        kwargs['authorization']=with_self_digest({**{k:v for k,v in kwargs['authorization'].items() if k!='recordDigest'},
            'leaseGeneration':2,'priorStateDigest':changed['recordDigest']})
        kwargs['authorization_verifier']=lambda *args:dict(anchor_owner='TEST-owner',task_governance='TEST-governance',verifier='TEST-verifier')
    if fault=='policy':
        policy=store.policy();(store.root/'policy.json').write_bytes(canonical_bytes({
            **policy,'allowedOperations':['activate','claim']}))
    before=claim_files(store,worker);head=repo.head()
    with pytest.raises(ProtectedClaimError):reclaim_expired_claim(**kwargs)
    assert claim_files(store,worker)==before and repo.head()==head
