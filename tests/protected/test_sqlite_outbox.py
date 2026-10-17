"""Independent real fixture resource; source tests, not installed qualification."""
from copy import deepcopy
from decimal import Decimal
from concurrent.futures import ThreadPoolExecutor
import os
import select
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading

import pytest

from dasops.protected.sqlite.store import CoordinationDatabase, CoordinationError, TaskKey
from dasops.protected.sqlite.outbox import DurableOutbox, Observation, encode_intent
from dasops.standards_contracts import exact_json as codec

D='sha256:'+'1'*64


def authorize(connection, operation, actor, epoch):
    return connection.in_transaction and actor in ('admin','worker','successor') and epoch == 1


class FixtureResource:
    """Actual independent SQLite side effect with atomic native idempotency.

    No boundary, production adapter, independent signature or power-loss claim.
    """
    def __init__(self, path, *, lose_response=False, crash=False, crash_before=False, suppress=False):
        self.path=path
        self.lose_response=lose_response
        self.crash=crash
        self.crash_before=crash_before
        self.suppress=suppress
        self.execute_calls=0
        connection=sqlite3.connect(path)
        connection.execute('CREATE TABLE IF NOT EXISTS effects (business TEXT PRIMARY KEY NOT NULL, request TEXT NOT NULL, receipt BLOB NOT NULL)')
        connection.commit();connection.close()

    def execute(self, intent, *, deadline):
        self.execute_calls+=1
        if self.crash_before:os._exit(23)
        if self.suppress:
            raise TimeoutError('send outcome unknown')
        digest=codec.digest(intent)
        native=codec.canonical({'business':intent['businessActionId'],'request':digest,'instance':'instance','committed':True})
        connection=sqlite3.connect(self.path,isolation_level=None,timeout=2)
        try:
            connection.execute('BEGIN IMMEDIATE')
            old=connection.execute('SELECT request,receipt FROM effects WHERE business=?',(intent['businessActionId'],)).fetchone()
            if old:
                if old[0]!=digest: raise RuntimeError('native immutable key conflict')
                native=old[1]
            else:
                connection.execute('INSERT INTO effects VALUES (?,?,?)',(intent['businessActionId'],digest,native))
            connection.execute('COMMIT')
        finally:connection.close()
        if self.crash:os._exit(23)
        if self.lose_response:raise TimeoutError('native commit response lost')
        return Observation('confirmed',digest,'instance',native)

    def lookup(self, intent, *, deadline):
        connection=sqlite3.connect(self.path)
        try:row=connection.execute('SELECT request,receipt FROM effects WHERE business=?',(intent['businessActionId'],)).fetchone()
        finally:connection.close()
        if row:return Observation('confirmed',row[0],'instance',row[1])
        native=codec.canonical({'business':intent['businessActionId'],'request':codec.digest(intent),'instance':'instance','committed':False})
        return Observation('not_executed',codec.digest(intent),'instance',native)

    def verify(self, intent, observation):
        expected=self.lookup(intent,deadline=0)
        return expected == observation

    def count(self):
        connection=sqlite3.connect(self.path)
        try:return connection.execute('SELECT COUNT(*) FROM effects').fetchone()[0]
        finally:connection.close()


def outbox(db, resource, *, closed=True, verifier=None):
    return DurableOutbox(db,adapters={('resource','instance','integrate'):resource},
        verify_observation=verifier or resource.verify,execution_closed=lambda intent:closed)


@pytest.fixture
def setup(tmp_path):
    control=tmp_path/'control';control.mkdir(mode=0o700)
    db=CoordinationDatabase.create(control/'state.db',authority_domain='domain',instance_id='writer')
    db.create_change('project','change',actor='admin',now=100,authorize=authorize)
    db.add_task(TaskKey('domain','project','change','task'),D,actor='admin',now=100,authorize=authorize)
    db.create_budget('shared',10,actor='admin',now=100,authorize=authorize)
    intent={'contractIdentity':'das-resource-action-intent/v1',
        'taskKey':dict(authorityDomain='domain',projectId='project',changeId='change',taskId='task'),
        'taskRevision':1,'taskCycle':1,'resourceId':'resource','resourceInstance':'instance','targetGeneration':1,
        'action':'integrate','businessActionId':'business','originalActor':'worker','parameters':{'before':'base','after':'candidate'},
        'toolDigest':D,'policyDigest':D,'budgetIds':['shared'],'cost':5}
    resource=FixtureResource(tmp_path/'independent-resource.db')
    yield db,resource,intent
    db.close()


def submit(box,intent,actor='worker'):
    return box.submit(intent,actor=actor,now=101,authorize=authorize)


def dispatch(box,**overrides):
    options=dict(actor='worker',now=102,authorize=authorize)
    options.update(overrides)
    return box.dispatch('resource','integrate','business',**options)


def reconcile(box):
    return box.reconcile('resource','integrate','business',actor='successor',now=103,authorize=authorize)


def reserved(db):
    return db.connection.execute('SELECT reserved FROM budgets').fetchone()[0]


@pytest.fixture
def routed(setup,tmp_path):
    from dasops.protected.sqlite.authority import AuthorityRoute
    db,resource,intent=setup
    control=tmp_path/'independent-route';control.mkdir(mode=0o700)
    route=AuthorityRoute(control/'route.json',authority_domain='domain')
    route.enroll(db,actor='admin',now=100,approve=lambda *args:True)
    return db,resource,intent,route


def interrupt_business(routed, operation, boundary):
    """Actual installed-writer process death; independent parent reads SQL."""
    db,resource,intent,route=routed
    box=outbox(db,resource,closed=False)
    if operation!='reserve':submit(box,intent)
    if operation=='complete':dispatch(box)
    script='''
import os,sys
from tests.protected.test_sqlite_outbox import FixtureResource,outbox,authorize,D
from dasops.protected.sqlite.authority import AuthorityRoute
from dasops.protected.sqlite.store import TaskKey
from dasops.standards_contracts import exact_json as codec
route=AuthorityRoute(sys.argv[1],authority_domain='domain');db=route.open_current()
publish=route._publish;started=[False]
def fault(record,**kw):
    if record['phase']=='committing':
        started[0]=True
        if sys.argv[4]=='before-commit':publish(record,**kw);os._exit(74)
    if record['phase']=='active' and started[0]:
        if sys.argv[4]=='after-commit':os._exit(74)
        if sys.argv[4]=='after-active':publish(record,**kw);os._exit(74)
    return publish(record,**kw)
route._publish=fault
box=outbox(db,FixtureResource(sys.argv[2]),closed=False)
intent=codec.parse(bytes.fromhex(sys.argv[5]))
if sys.argv[3]=='reserve':box.submit(intent,actor='worker',now=101,authorize=authorize)
elif sys.argv[3]=='action_dispatched':box.dispatch('resource','integrate','business',actor='worker',now=102,authorize=authorize)
else:
    row,_=box._load('resource','integrate','business')
    db.record_completion(TaskKey('domain','project','change','task'),cycle=1,revision=1,
        resource_id='resource',action_class='integrate',business_id='business',
        receipt_digest=row['receipt_digest'],evidence_digest=D,actor='worker',now=103,authorize=authorize)
'''
    env=dict(os.environ,PYTHONPATH=str(Path(__file__).resolve().parents[2]),PYTHONDONTWRITEBYTECODE='1')
    process=subprocess.run([sys.executable,'-B','-c',script,str(route.path),str(resource.path),operation,boundary,
        encode_intent(intent).hex()],env=env,capture_output=True,timeout=15)
    assert process.returncode==74,process.stderr.decode()
    return box


def resume_business(box, intent, operation, *, now=110, actor='successor', permission=authorize, evidence_digest=D):
    if operation=='reserve':return box.submit(intent,actor=actor,now=now,authorize=permission)
    if operation=='action_dispatched':
        return box.reconcile(intent['resourceId'],intent['action'],intent['businessActionId'],
            actor=actor,now=now,authorize=permission)
    row,_=box._load('resource','integrate','business')
    return box.database.record_completion(TaskKey(*(intent['taskKey'][name] for name in ('authorityDomain','projectId','changeId','taskId'))),
        cycle=intent['taskCycle'],revision=intent['taskRevision'],resource_id=intent['resourceId'],
        action_class=intent['action'],business_id=intent['businessActionId'],receipt_digest=row['receipt_digest'],
        evidence_digest=evidence_digest,actor=actor,now=now,authorize=permission)


@pytest.mark.parametrize('operation',['reserve','action_dispatched','complete'])
@pytest.mark.parametrize('boundary',['before-commit','after-commit'])
def test_original_business_recovery_after_real_exit(routed,operation,boundary):
    db,resource,intent,route=routed
    box=interrupt_business(routed,operation,boundary)
    assert route._read()['phase']=='committing'
    with pytest.raises(CoordinationError):route.open_current()
    if operation=='action_dispatched':
        with pytest.raises(CoordinationError,match='cannot execute'):dispatch(box,now=110)
    if operation=='reserve':
        from dasops.protected.sqlite.authority import _state_digest
        for field,value in (('budgetIds',['other']),('taskRevision',2),('taskCycle',2)):
            wrong=deepcopy(intent);wrong[field]=value
            before=_state_digest(db.connection);pending=route.path.read_bytes()
            with pytest.raises(CoordinationError):resume_business(box,wrong,operation)
            assert _state_digest(db.connection)==before and route.path.read_bytes()==pending and resource.count()==0
    result=resume_business(box,intent,operation)
    assert route._read()['phase']=='active' and reserved(db)==5
    assert db.connection.execute('SELECT COUNT(*) FROM business_actions').fetchone()[0]==1
    assert db.connection.execute('SELECT COUNT(*) FROM action_payloads').fetchone()[0]==1
    assert db.connection.execute('SELECT COUNT(*) FROM reservations').fetchone()[0]==1
    assert db.connection.execute("SELECT COUNT(*) FROM audit WHERE event='action_reserved'").fetchone()[0]==1
    assert db.connection.execute("SELECT COUNT(*) FROM audit WHERE event='business_reconciled'").fetchone()[0]==1
    if operation=='reserve':
        assert result['state']=='reserved' and resource.count()==0
        assert dispatch(box,now=111)['state']=='confirmed' and resource.count()==1
    elif operation=='action_dispatched':
        assert result['state']=='unknown' and resource.count()==0 and resource.execute_calls==0
        with pytest.raises(CoordinationError):dispatch(box,now=111)
    else:
        assert result['cycle']==1 and resource.count()==1
        assert resume_business(box,intent,operation,now=111)==result
    assert db.connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0]==int(operation=='complete')
    db.check_integrity()


@pytest.mark.parametrize('operation',['reserve','action_dispatched','complete'])
@pytest.mark.parametrize('boundary',['before-commit','after-commit'])
@pytest.mark.parametrize('recovery_boundary',['before-commit','after-commit'])
def test_repeated_business_recovery_retains_original_and_first_recovery(routed,monkeypatch,operation,boundary,recovery_boundary):
    db,resource,intent,route=routed;box=interrupt_business(routed,operation,boundary)
    original=route._read()['migration']['businessIntent'];publish=route._publish
    def fault(record,**kw):
        if record['phase']=='committing' and recovery_boundary=='before-commit':
            publish(record,**kw);raise OSError('before recovery COMMIT')
        if record['phase']=='active' and recovery_boundary=='after-commit':raise OSError('after recovery COMMIT')
        return publish(record,**kw)
    monkeypatch.setattr(route,'_publish',fault)
    for now in (110,112):
        with pytest.raises(OSError):resume_business(box,intent,operation,now=now)
        assert route._read()['migration']['businessIntent']==original
    monkeypatch.setattr(route,'_publish',publish)
    resume_business(box,intent,operation,now=114)
    events=db.connection.execute("SELECT body FROM audit WHERE event='business_reconciled'").fetchall()
    assert len(events)==1
    assert codec.parse(events[0][0].encode())=={'original':original,'recovery':{'actor':'successor','time':110}}
    assert reserved(db)==5 and resource.count()==int(operation=='complete')
    assert db.connection.execute('SELECT time_floor FROM metadata').fetchone()[0]==114


@pytest.mark.parametrize('operation',['reserve','action_dispatched','complete'])
@pytest.mark.parametrize('fault',['denied','clock','cost','task','key','budget-drift','intent-actor','source-digest','missing-result','commit','policy','schema'])
def test_business_recovery_refuses_conflict_corruption_and_current_denial(routed,monkeypatch,operation,fault):
    from dasops.protected.sqlite.authority import _state_digest
    db,resource,intent,route=routed;box=interrupt_business(routed,operation,'after-commit')
    value=deepcopy(intent);permission=authorize;now=110
    if fault=='denied':permission=lambda *args:False
    elif fault=='clock':now=99
    elif fault=='cost':
        if operation=='complete':value['taskRevision']=2
        elif operation=='action_dispatched':value['businessActionId']='wrong'
        else:value['cost']=6
    elif fault=='task':value['taskKey']['taskId']='wrong'
    elif fault=='key':value['businessActionId']='wrong'
    elif fault=='budget-drift':db.connection.execute('UPDATE budgets SET ceiling=99')
    elif fault in ('intent-actor','source-digest','missing-result'):
        record=route._read()
        if fault=='intent-actor':record['migration']['businessIntent']['actor']='forged'
        elif fault=='source-digest':record['migration']['businessIntent']['sourceStateDigest']=D
        else:record['migration'].pop('resultDigest')
        route._publish(record)
    elif fault=='commit':
        def permission(c,*args):
            c.execute('COMMIT');return True
    elif fault=='policy':db.connection.execute('PRAGMA synchronous=OFF')
    elif fault=='schema':db.connection.execute('DROP TRIGGER preserve_action_payload')
    # Immutable argument changes are meaningful to the operation; completion
    # has no separate cost, dispatch binds its key/request, and task changes
    # in reconcile are not supplied arguments. Inject actual payload drift for
    # that dispatch case rather than pretend the unused caller object matters.
    if operation=='action_dispatched' and fault=='task':
        db.connection.execute('UPDATE tasks SET revision=revision+1')
    before=_state_digest(db.connection);record=route.path.read_bytes();effects=resource.count();calls=resource.execute_calls
    schema=list(db.connection.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name'))
    with pytest.raises((CoordinationError,sqlite3.DatabaseError)):
        resume_business(box,value,operation,now=now,permission=permission)
    assert _state_digest(db.connection)==before and route.path.read_bytes()==record
    assert list(db.connection.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name'))==schema
    assert resource.count()==effects and resource.execute_calls==calls and reserved(db)==5


@pytest.mark.parametrize('operation',['reserve','action_dispatched','complete'])
def test_business_recovery_two_connections_preserve_one_result(routed,monkeypatch,operation):
    db,resource,intent,route=routed;interrupt_business(routed,operation,'before-commit')
    barrier=threading.Barrier(2)
    def contender():
        from dasops.protected.sqlite.authority import AuthorityRoute
        own_route=AuthorityRoute(route.path,authority_domain='domain')
        own=CoordinationDatabase(db.path,authority_domain='domain',authority_route=own_route)
        try:
            box=outbox(own,FixtureResource(resource.path),closed=False)
            barrier.wait(timeout=5)
            try:return resume_business(box,intent,operation)
            except CoordinationError as error:
                # A competing lookup may settle unknown before our CAS. This
                # explicit refusal is safe; never retry a resource execution.
                if str(error)!='action CAS conflict; reconcile original key':raise
                return None
        finally:own.close()
    with ThreadPoolExecutor(max_workers=2) as pool:
        a=pool.submit(contender);b=pool.submit(contender);results=[a.result(),b.result()]
    successful=[result for result in results if result is not None]
    assert successful and all(result==successful[0] for result in successful)
    assert resume_business(outbox(db,resource,closed=False),intent,operation)==successful[0]
    assert reserved(db)==5 and resource.count()==int(operation=='complete')
    assert db.connection.execute('SELECT COUNT(*) FROM reservations').fetchone()[0]==1
    assert db.connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0]==int(operation=='complete')
    assert db.connection.execute("SELECT COUNT(*) FROM audit WHERE event='business_reconciled'").fetchone()[0]==1


def test_dispatch_after_active_publication_death_only_looks_up(routed):
    db,resource,intent,route=routed;box=interrupt_business(routed,'action_dispatched','after-active')
    assert route._read()['phase']=='active' and resource.count()==0
    result=resume_business(box,intent,'action_dispatched')
    assert result['state']=='unknown' and resource.count()==0 and resource.execute_calls==0 and reserved(db)==5


@pytest.mark.parametrize('boundary',['before-commit','after-commit'])
@pytest.mark.parametrize('fault',['evidence','cycle','qualification-revoked'])
def test_completion_recovery_requires_original_qualified_input(routed,boundary,fault):
    from dasops.protected.sqlite.authority import _state_digest
    db,resource,intent,route=routed;box=interrupt_business(routed,'complete',boundary)
    value=deepcopy(intent);evidence=D;qualified=[True]
    if fault=='evidence':evidence='sha256:'+'2'*64
    elif fault=='cycle':value['taskCycle']=2
    else:qualified[0]=False
    def qualification(c,o,a,e):
        native=c.execute('SELECT native_bytes FROM resource_observations').fetchone()
        return authorize(c,o,a,e) and qualified[0] and native is not None and resource.verify(intent,
            Observation('confirmed',codec.digest(intent),'instance',native[0]))
    before=_state_digest(db.connection);pending=route.path.read_bytes()
    with pytest.raises(CoordinationError):
        resume_business(box,value,'complete',permission=qualification,evidence_digest=evidence)
    assert _state_digest(db.connection)==before and route.path.read_bytes()==pending and resource.count()==1
    qualified[0]=True
    result=resume_business(box,intent,'complete',permission=qualification)
    assert result['evidence_digest']==D and db.connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0]==1


@pytest.mark.parametrize('operation',['reserve','action_dispatched','complete'])
@pytest.mark.parametrize('recovery_boundary',['before-commit','after-commit'])
@pytest.mark.parametrize('field',['actor','time'])
def test_business_recovery_rejects_changed_first_recovery(routed,monkeypatch,operation,recovery_boundary,field):
    from dasops.protected.sqlite.authority import _state_digest
    db,resource,intent,route=routed;box=interrupt_business(routed,operation,'before-commit');publish=route._publish
    def fault(record,**kw):
        if record['phase']=='committing' and recovery_boundary=='before-commit':publish(record,**kw);raise OSError('interrupted')
        if record['phase']=='active' and recovery_boundary=='after-commit':raise OSError('interrupted')
        return publish(record,**kw)
    monkeypatch.setattr(route,'_publish',fault)
    with pytest.raises(OSError):resume_business(box,intent,operation)
    monkeypatch.setattr(route,'_publish',publish)
    retained=route._read();damaged=deepcopy(retained)
    damaged['migration']['recoveryIntent'][field]='forged' if field=='actor' else 109
    route._publish(damaged);before=_state_digest(db.connection);pending=route.path.read_bytes();effects=resource.count()
    with pytest.raises(CoordinationError):resume_business(box,intent,operation,now=114)
    assert _state_digest(db.connection)==before and route.path.read_bytes()==pending and resource.count()==effects
    if field=='actor':
        for malformed in (None,[],{}, {'actor':True,'time':110}, {'actor':'successor','time':True}):
            damaged=deepcopy(retained);damaged['migration']['recoveryIntent']=malformed
            route._publish(damaged);pending=route.path.read_bytes()
            with pytest.raises(CoordinationError):resume_business(box,intent,operation,now=114)
            assert _state_digest(db.connection)==before and route.path.read_bytes()==pending and resource.count()==effects
        for keys in (('recoveryIntent',),('priorCheckpoint',),('priorResultDigest',),('recoveryIntent','priorCheckpoint','priorResultDigest')):
            damaged=deepcopy(retained)
            for key in keys:damaged['migration'].pop(key)
            route._publish(damaged);pending=route.path.read_bytes()
            with pytest.raises(CoordinationError):resume_business(box,intent,operation,now=114)
            assert _state_digest(db.connection)==before and route.path.read_bytes()==pending and resource.count()==effects
    route._publish(retained);resume_business(box,intent,operation,now=114)
    event=db.connection.execute("SELECT body FROM audit WHERE event='business_reconciled'").fetchall()
    assert len(event)==1 and codec.parse(event[0][0].encode())['recovery']=={'actor':'successor','time':110}


def interrupt_settlement(db,resource,intent,route,boundary,*,outcome='confirmed'):
    box=outbox(db,resource);submit(box,intent)
    witness=None
    if outcome=='not_executed':
        # The fixed TEST dispatcher has no children or asynchronous transport.
        # Bind the actual original process with a pidfd before permitting send;
        # neither a PID lookup nor empty native SQL alone proves termination.
        child='''
import sys
from tests.protected.test_sqlite_outbox import FixtureResource,outbox,dispatch
from dasops.protected.sqlite.authority import AuthorityRoute
route=AuthorityRoute(sys.argv[1],authority_domain='domain');db=route.open_current()
resource=FixtureResource(sys.argv[2],crash_before=True);execute=resource.execute
def waiting(value,*,deadline):
    print('ready',flush=True);sys.stdin.readline();return execute(value,deadline=deadline)
resource.execute=waiting
dispatch(outbox(db,resource))
'''
        env=dict(os.environ,PYTHONPATH=str(Path(__file__).resolve().parents[2]),PYTHONDONTWRITEBYTECODE='1')
        process=subprocess.Popen([sys.executable,'-B','-c',child,str(route.path),str(resource.path)],
            env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        fd=None
        try:
            assert select.select([process.stdout],[],[],10)[0]
            assert process.stdout.readline()==b'ready\n'
            fd=os.pidfd_open(process.pid)
            poller=select.poll();poller.register(fd,select.POLLIN)
            readable=lambda:os.readlink('/proc/self/fd/'+str(fd))=='anon_inode:[pidfd]' and any(mask & select.POLLIN and not mask & (select.POLLERR|select.POLLNVAL) for _,mask in poller.poll(0))
            request=codec.digest(intent)
            def witness(value):return codec.digest(value)==request and readable() and process.returncode==23
            box.execution_closed=witness
            assert resource.count()==0 and not witness(intent) and process.poll() is None
            assert box.reconcile('resource','integrate','business',actor='worker',now=102,authorize=authorize)['state']=='unknown'
            assert reserved(db)==5 and process.poll() is None
            _,stderr=process.communicate(b'send\n',timeout=15)
            assert process.returncode==23,stderr.decode()
            assert resource.count()==0 and witness(intent)
            box._test_execution=process
        except BaseException:
            if process.poll() is None:process.kill();process.communicate()
            if fd is not None:os.close(fd)
            raise
    script='''
import os,select,sys
from tests.protected.test_sqlite_outbox import FixtureResource,outbox,dispatch
from dasops.protected.sqlite.authority import AuthorityRoute
from dasops.protected.sqlite.store import CoordinationDatabase
from dasops.standards_contracts import exact_json as codec
route=AuthorityRoute(sys.argv[3],authority_domain='domain')
db=route.open_current();publish=route._publish;settling=[False]
def fault(record,**kw):
    if record['phase']=='settling':settling[0]=True
    if record['phase']=='settling' and sys.argv[4]=='before-commit':
        publish(record,**kw);os._exit(74)
    if record['phase']=='active' and settling[0] and sys.argv[4]=='after-commit':os._exit(74)
    return publish(record,**kw)
route._publish=fault
box=outbox(db,FixtureResource(sys.argv[2]))
if sys.argv[5]=='not_executed':
    poller=select.poll();poller.register(int(sys.argv[6]),select.POLLIN)
    box.execution_closed=lambda i:codec.digest(i)==sys.argv[7] and os.readlink('/proc/self/fd/'+sys.argv[6])=='anon_inode:[pidfd]' and any(mask & select.POLLIN and not mask & (select.POLLERR|select.POLLNVAL) for _,mask in poller.poll(0))
    box.reconcile('resource','integrate','business',actor='worker',now=102,
        authorize=lambda c,o,a,e:c.in_transaction and a=='worker' and e==1)
else:dispatch(box)
'''
    env=dict(os.environ,PYTHONPATH=str(Path(__file__).resolve().parents[2]),PYTHONDONTWRITEBYTECODE='1')
    extra=[str(fd),codec.digest(intent)] if witness is not None else []
    try:
        result=subprocess.run([sys.executable,'-B','-c',script,str(db.path),str(resource.path),str(route.path),boundary,outcome,*extra],
            env=env,capture_output=True,timeout=15,pass_fds=(fd,) if witness is not None else ())
        assert result.returncode==74,result.stderr.decode()
        assert resource.count()==(1 if outcome=='confirmed' else 0) and route._read()['phase']=='settling'
        with pytest.raises(CoordinationError):route.open_current()
    except BaseException:
        if witness is not None:os.close(fd)
        raise
    # Keep the kernel handle alive for fresh recovery checks; the enclosing
    # test fixture closes only this owned descriptor during teardown.
    if witness is not None:box._test_pidfd=fd
    return box


@pytest.fixture
def absence(routed):
    boxes=[]
    def start(boundary):
        db,resource,intent,route=routed
        box=interrupt_settlement(db,resource,intent,route,boundary,outcome='not_executed')
        boxes.append(box);return (*routed,box)
    yield start
    for box in boxes:
        if box._test_pidfd is not None:os.close(box._test_pidfd)


@pytest.mark.parametrize('outcome',['confirmed','not_executed'])
@pytest.mark.parametrize('boundary',['before-commit','after-commit'])
@pytest.mark.parametrize('field',['actor','time'])
def test_outbox_recovery_rejects_changed_first_recovery(routed,absence,monkeypatch,outcome,boundary,field):
    from dasops.protected.sqlite.authority import _state_digest
    db,resource,intent,route=routed
    box=absence('before-commit')[-1] if outcome=='not_executed' else interrupt_settlement(db,resource,intent,route,'before-commit')
    publish=route._publish
    def fault(record,**kw):
        if record['phase']=='settling' and boundary=='before-commit':publish(record,**kw);raise OSError('interrupted')
        if record['phase']=='active' and boundary=='after-commit':raise OSError('interrupted')
        return publish(record,**kw)
    monkeypatch.setattr(route,'_publish',fault)
    with pytest.raises(OSError):reconcile(box)
    monkeypatch.setattr(route,'_publish',publish);retained=route._read();damaged=deepcopy(retained)
    damaged['migration']['recoveryIntent'][field]='forged' if field=='actor' else 102
    route._publish(damaged);before=_state_digest(db.connection);pending=route.path.read_bytes();effects=resource.count()
    with pytest.raises(CoordinationError):box.reconcile('resource','integrate','business',actor='successor',now=107,authorize=authorize)
    assert _state_digest(db.connection)==before and route.path.read_bytes()==pending and resource.count()==effects
    if field=='actor':
        for malformed in (None,[],{}, {'actor':True,'time':103}, {'actor':'successor','time':True}):
            damaged=deepcopy(retained);damaged['migration']['recoveryIntent']=malformed
            route._publish(damaged);pending=route.path.read_bytes()
            with pytest.raises(CoordinationError):box.reconcile('resource','integrate','business',actor='successor',now=107,authorize=authorize)
            assert _state_digest(db.connection)==before and route.path.read_bytes()==pending and resource.count()==effects
        for keys in (('recoveryIntent',),('priorCheckpoint',),('priorResultDigest',),('recoveryIntent','priorCheckpoint','priorResultDigest')):
            damaged=deepcopy(retained)
            for key in keys:damaged['migration'].pop(key)
            route._publish(damaged);pending=route.path.read_bytes()
            with pytest.raises(CoordinationError):box.reconcile('resource','integrate','business',actor='successor',now=107,authorize=authorize)
            assert _state_digest(db.connection)==before and route.path.read_bytes()==pending and resource.count()==effects
    route._publish(retained);box.reconcile('resource','integrate','business',actor='successor',now=107,authorize=authorize)
    event=db.connection.execute("SELECT body FROM audit WHERE event='outbox_reconciled'").fetchall()
    assert len(event)==1 and codec.parse(event[0][0].encode())['recovery']=={'actor':'successor','time':103}


@pytest.mark.parametrize('boundary',['before-commit','after-commit'])
def test_absence_settlement_recovers_with_real_closed_process_without_refund_or_completion(absence,boundary):
    db,resource,intent,route,box=absence(boundary)
    original=route._read()['migration']['settlementIntent']
    assert original['target']=='not_executed' and box.execution_closed(intent)
    row=reconcile(box)
    assert row['state']=='not_executed' and row['receipt_digest'] is None and resource.count()==0
    assert reserved(db)==5 and db.connection.execute('SELECT COUNT(*) FROM reservations').fetchone()[0]==1
    assert db.connection.execute("SELECT COUNT(*) FROM audit WHERE event='action_not_executed'").fetchone()[0]==1
    event=codec.parse(db.connection.execute("SELECT body FROM audit WHERE event='outbox_reconciled'").fetchone()[0].encode())
    assert event=={'original':original,'recovery':{'actor':'successor','time':103}}
    native=db.connection.execute('SELECT outcome,native_digest,native_bytes FROM resource_observations').fetchone()
    assert tuple(native)==('not_executed',original['nativeDigest'],resource.lookup(intent,deadline=0).native_receipt)
    assert not db.connection.execute('SELECT * FROM completions').fetchall()
    with pytest.raises(CoordinationError):
        db.record_completion(TaskKey('domain','project','change','task'),cycle=1,revision=1,
            resource_id='resource',action_class='integrate',business_id='business',receipt_digest=D,
            evidence_digest=D,actor='worker',now=104,authorize=authorize)
    with pytest.raises(CoordinationError):dispatch(box,now=104)
    # Only the existing explicit authorized retry of this stable key may send.
    db.transition_action('resource','integrate','business',expected='not_executed',target='reserved',
        actor='worker',now=104,authorize=authorize)
    retry=box.submit(intent,actor='worker',now=104,authorize=authorize)
    assert retry['state']=='reserved' and retry['fingerprint']==row['fingerprint']
    assert dispatch(box,now=104)['state']=='confirmed' and resource.count()==1 and reserved(db)==5
    assert db.connection.execute('SELECT COUNT(*) FROM business_actions').fetchone()[0]==1
    db.check_integrity()


@pytest.mark.parametrize('boundary',['before-commit','after-commit'])
@pytest.mark.parametrize('recovery_boundary',['before-commit','after-commit'])
def test_repeated_absence_recovery_requires_fresh_closure_and_keeps_original(absence,monkeypatch,boundary,recovery_boundary):
    db,resource,intent,route,box=absence(boundary)
    original=route._read()['migration']['settlementIntent'];publish=route._publish;closed=box.execution_closed
    calls=[]
    def witness(value):calls.append(codec.digest(value));return closed(value)
    box.execution_closed=witness
    def fault(record,**kw):
        if record['phase']=='settling' and recovery_boundary=='before-commit':
            publish(record,**kw);raise OSError('before absence recovery COMMIT')
        if record['phase']=='active' and recovery_boundary=='after-commit':raise OSError('after absence recovery COMMIT')
        return publish(record,**kw)
    monkeypatch.setattr(route,'_publish',fault)
    for now in (103,105):
        with pytest.raises(OSError):box.reconcile('resource','integrate','business',actor='successor',now=now,authorize=authorize)
        assert route._read()['migration']['settlementIntent']==original
    monkeypatch.setattr(route,'_publish',publish)
    box.execution_closed=lambda _:False
    route_before=route.path.read_bytes()
    with sqlite3.connect(db.path) as c:before=list(c.iterdump())
    with pytest.raises(CoordinationError,match='closure'):
        box.reconcile('resource','integrate','business',actor='successor',now=107,authorize=authorize)
    assert route.path.read_bytes()==route_before
    with sqlite3.connect(db.path) as c:assert list(c.iterdump())==before
    box.execution_closed=witness
    row=box.reconcile('resource','integrate','business',actor='successor',now=107,authorize=authorize)
    assert row['state']=='not_executed' and resource.count()==0 and reserved(db)==5 and len(calls)==3
    events=db.connection.execute("SELECT body FROM audit WHERE event='outbox_reconciled'").fetchall()
    assert len(events)==1 and codec.parse(events[0][0].encode())['recovery']=={'actor':'successor','time':103}
    db.check_integrity()


@pytest.mark.parametrize('fault',['closed-handle','truthy','exception','closure-tamper','revoked','wrong-native','effect-appeared',
    'budget-drift','state-race','route-race','target-tamper','missing-target','denied-final','original-actor','source-digest'])
def test_absence_recovery_rejects_changed_closure_native_state_and_authority(absence,monkeypatch,fault):
    db,resource,intent,route,box=absence('after-commit');closed=box.execution_closed;allowed=[True]
    def witness(value):
        with route.locked():pass
        with sqlite3.connect(db.path,isolation_level=None) as c:c.execute('BEGIN IMMEDIATE');c.execute('ROLLBACK')
        if fault=='truthy':return 1
        if fault=='exception':raise OSError('closure unavailable')
        if fault=='closure-tamper':value['cost']=1;return True
        if fault=='revoked':allowed[0]=False
        if fault=='state-race':
            with sqlite3.connect(db.path) as c:c.execute('UPDATE budgets SET ceiling=99')
        if fault=='route-race':
            record=route._read();route._publish(dict(record,generation=record['generation']+1))
        return closed(value)
    box.execution_closed=witness
    if fault=='closed-handle':os.close(box._test_pidfd);box._test_pidfd=None
    if fault=='wrong-native':
        lookup=resource.lookup
        def altered(value,*,deadline):
            old=lookup(value,deadline=deadline);return Observation('not_executed',old.request_digest,old.resource_instance,b'changed')
        monkeypatch.setattr(resource,'lookup',altered)
    if fault=='effect-appeared':resource.execute(intent,deadline=0)
    if fault=='budget-drift':
        with sqlite3.connect(db.path) as c:c.execute('UPDATE budgets SET ceiling=99')
    if fault in ('target-tamper','missing-target'):
        record=route._read()
        if fault=='target-tamper':record['migration']['settlementIntent']['target']='confirmed'
        else:record['migration']['settlementIntent'].pop('target')
        route._publish(record)
    if fault in ('original-actor','source-digest'):
        record=route._read();original=record['migration']['settlementIntent']
        original['actor' if fault=='original-actor' else 'sourceStateDigest']='forged' if fault=='original-actor' else D
        route._publish(record)
    def authority(c,o,a,e):return allowed[0] and authorize(c,o,a,e) and not (fault=='denied-final' and o=='action_not_executed')
    route_before=route.path.read_bytes()
    with sqlite3.connect(db.path) as c:before=list(c.iterdump())
    with pytest.raises((CoordinationError,OSError)):
        box.reconcile('resource','integrate','business',actor='successor',now=103,authorize=authority)
    if fault!='route-race':assert route.path.read_bytes()==route_before
    if fault!='state-race':
        with sqlite3.connect(db.path) as c:assert list(c.iterdump())==before
    assert route._read()['phase']=='settling' and reserved(db)==5
    assert not db.connection.execute('SELECT * FROM completions').fetchall()


def test_absence_recovery_concurrency_keeps_one_original_fact(absence,monkeypatch):
    db,resource,intent,route,original_box=absence('before-commit')
    barrier=threading.Barrier(2);lookup=resource.lookup
    def observed(value,*,deadline):barrier.wait(timeout=5);return lookup(value,deadline=deadline)
    monkeypatch.setattr(resource,'lookup',observed)
    def recover(_):
        local=CoordinationDatabase(db.path,authority_domain='domain',authority_route=route)
        try:
            box=outbox(local,resource,verifier=lambda i,o:lookup(i,deadline=0)==o)
            box.execution_closed=original_box.execution_closed
            try:return reconcile(box)['state']
            except CoordinationError:return 'conflict'
        finally:local.close()
    with ThreadPoolExecutor(2) as pool:results=list(pool.map(recover,range(2)))
    assert sorted(results)==['conflict','not_executed'] and resource.count()==0 and reserved(db)==5
    assert db.connection.execute("SELECT COUNT(*) FROM audit WHERE event='outbox_reconciled'").fetchone()[0]==1
    db.check_integrity()


@pytest.mark.parametrize('dependency',['verification','closure'])
def test_settlement_dependencies_cannot_rebind_original_intent(setup,dependency):
    db,resource,intent=setup;box=outbox(db,resource);submit(box,intent)
    original=codec.canonical(intent)
    def altered(value,*args):value['cost']=1;return True
    if dependency=='verification':box.verify_observation=altered;row=dispatch(box)
    else:
        resource.suppress=True;dispatch(box);box.execution_closed=altered;row=reconcile(box)
    assert row['state']=='unknown' and codec.canonical(intent)==original and reserved(db)==5
    assert not db.connection.execute('SELECT * FROM resource_observations').fetchall()
    assert not db.connection.execute('SELECT * FROM completions').fetchall()
    db.check_integrity()


@pytest.mark.parametrize('boundary',['before-commit','after-commit'])
def test_real_settlement_process_exit_recovers_only_original_fact_and_completion(routed,boundary):
    db,resource,intent,route=routed;box=interrupt_settlement(db,resource,intent,route,boundary)
    original=codec.canonical(route._read()['migration']['settlementIntent'])
    row=reconcile(box)
    assert row['state']=='confirmed' and resource.count()==1 and resource.execute_calls==0
    assert reserved(db)==5 and len(db.connection.execute('SELECT * FROM reservations').fetchall())==1
    assert db.connection.execute("SELECT COUNT(*) FROM audit WHERE event='action_confirmed'").fetchone()[0]==1
    assert db.connection.execute("SELECT COUNT(*) FROM audit WHERE event='outbox_reconciled'").fetchone()[0]==1
    body=db.connection.execute("SELECT body FROM audit WHERE event='outbox_reconciled'").fetchone()[0]
    assert codec.canonical(codec.parse(body.encode())['original'])==original
    key=TaskKey('domain','project','change','task')
    args=dict(cycle=1,revision=1,resource_id='resource',action_class='integrate',business_id='business',
        receipt_digest=row['receipt_digest'],evidence_digest=D,actor='successor',now=104,authorize=authorize)
    first=db.record_completion(key,**args);assert db.record_completion(key,**args)==first
    assert db.connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0]==1
    assert resource.count()==1 and reserved(db)==5
    with pytest.raises(CoordinationError):dispatch(box,now=104)
    db.check_integrity()


@pytest.mark.parametrize('boundary',['before-commit','after-commit'])
@pytest.mark.parametrize('recovery_boundary',['before-commit','after-commit'])
def test_repeated_settlement_recovery_preserves_original_and_first_recovery(routed,monkeypatch,boundary,recovery_boundary):
    db,resource,intent,route=routed;box=interrupt_settlement(db,resource,intent,route,boundary)
    original=route._read()['migration']['settlementIntent'];publish=route._publish
    def fault(record,**kw):
        if record['phase']=='settling' and recovery_boundary=='before-commit':
            publish(record,**kw);raise OSError('before recovery COMMIT')
        if record['phase']=='active' and recovery_boundary=='after-commit':raise OSError('after recovery COMMIT')
        return publish(record,**kw)
    monkeypatch.setattr(route,'_publish',fault)
    for now in (103,105):
        with pytest.raises(OSError):box.reconcile('resource','integrate','business',actor='successor',now=now,authorize=authorize)
        assert route._read()['migration']['settlementIntent']==original
    monkeypatch.setattr(route,'_publish',publish)
    row=box.reconcile('resource','integrate','business',actor='successor',now=107,authorize=authorize)
    assert row['state']=='confirmed' and resource.count()==1 and reserved(db)==5
    events=db.connection.execute("SELECT body FROM audit WHERE event='outbox_reconciled'").fetchall()
    assert len(events)==1 and codec.parse(events[0][0].encode())['recovery']=={'actor':'successor','time':103}
    assert db.connection.execute('SELECT time_floor FROM metadata').fetchone()[0]==107
    db.check_integrity()


@pytest.mark.parametrize('fault',['wrong-key','denied','revoked','changed-receipt','wrong-request','wrong-instance',
    'unverified','missing-receipt','wrong-outcome','budget-drift','future-floor','intent-tamper','commit','route-race',
    'missing-intent','missing-result','state-race','original-actor','source-digest','source-checkpoint'])
def test_settlement_recovery_refuses_missing_changed_or_revoked_evidence(routed,monkeypatch,fault):
    db,resource,intent,route=routed;box=interrupt_settlement(db,resource,intent,route,'after-commit')
    lookup=resource.lookup;allowed=[True]
    def observed(value,*,deadline):
        # Recovery must release the route lock and SQL writer before lookup.
        with route.locked():pass
        with sqlite3.connect(db.path,isolation_level=None) as c:c.execute('BEGIN IMMEDIATE');c.execute('ROLLBACK')
        original=lookup(value,deadline=deadline)
        if fault=='revoked':allowed[0]=False
        if fault=='route-race':
            record=route._read();route._publish(dict(record,generation=record['generation']+1))
        if fault=='state-race':
            with sqlite3.connect(db.path) as c:c.execute('UPDATE budgets SET ceiling=99')
        if fault in ('changed-receipt','wrong-request','wrong-instance','missing-receipt','wrong-outcome'):
            return Observation('not_executed' if fault=='wrong-outcome' else 'confirmed',
                D if fault=='wrong-request' else original.request_digest,
                'foreign' if fault=='wrong-instance' else original.resource_instance,
                b'' if fault=='missing-receipt' else b'changed' if fault=='changed-receipt' else original.native_receipt)
        return original
    monkeypatch.setattr(resource,'lookup',observed)
    if fault=='unverified':box.verify_observation=lambda *args:False
    if fault=='intent-tamper':
        def tamper(value,observation):value['cost']=1;return True
        box.verify_observation=tamper
    if fault in ('budget-drift','future-floor'):
        with sqlite3.connect(db.path) as c:
            c.execute('UPDATE budgets SET ceiling=99' if fault=='budget-drift' else 'UPDATE metadata SET time_floor=104')
    if fault in ('missing-intent','missing-result'):
        record=route._read();record['migration'].pop('settlementIntent' if fault=='missing-intent' else 'resultDigest');route._publish(record)
    if fault in ('original-actor','source-digest','source-checkpoint'):
        record=route._read();original=record['migration']['settlementIntent']
        if fault=='original-actor':original['actor']='forged'
        elif fault=='source-digest':original['sourceStateDigest']=D
        else:original['sourceCheckpoint']['digest']=D
        route._publish(record)
    def authority(c,o,a,e):
        if fault=='commit':c.commit()
        return fault!='denied' and allowed[0] and authorize(c,o,a,e)
    with sqlite3.connect(db.path) as c:before=list(c.iterdump())
    route_before=route.path.read_bytes()
    with pytest.raises(CoordinationError):
        box.reconcile('resource','integrate','other' if fault=='wrong-key' else 'business',
            actor='successor',now=103,authorize=authority)
    if fault!='state-race':
        with sqlite3.connect(db.path) as c:assert list(c.iterdump())==before
    if fault!='route-race':assert route.path.read_bytes()==route_before
    assert route._read()['phase']=='settling' and reserved(db)==5 and resource.count()==1
    assert not db.connection.execute('SELECT * FROM completions').fetchall()


def test_concurrent_settlement_recovery_has_one_original_result(routed,monkeypatch):
    db,resource,intent,route=routed;interrupt_settlement(db,resource,intent,route,'before-commit')
    barrier=threading.Barrier(2);lookup=resource.lookup
    def observed(value,*,deadline):
        barrier.wait(timeout=5);return lookup(value,deadline=deadline)
    monkeypatch.setattr(resource,'lookup',observed)
    def recover(_):
        local=CoordinationDatabase(db.path,authority_domain='domain',authority_route=route)
        try:
            box=outbox(local,resource,verifier=lambda i,o:lookup(i,deadline=0)==o)
            try:return reconcile(box)['state']
            except CoordinationError:return 'conflict'
        finally:local.close()
    with ThreadPoolExecutor(2) as pool:results=list(pool.map(recover,range(2)))
    assert sorted(results)==['confirmed','conflict']
    assert resource.count()==1 and reserved(db)==5
    assert db.connection.execute("SELECT COUNT(*) FROM audit WHERE event='outbox_reconciled'").fetchone()[0]==1
    db.check_integrity()


@pytest.mark.parametrize('boundary',['before-commit','after-commit'])
def test_legacy_confirmed_settlement_recovers_original_format_without_downgrade(routed,boundary):
    """Construct the earlier exact fixed writer, not a newly self-signed route."""
    from dasops.protected.sqlite.authority import _state_digest
    db,resource,payload,route=routed;box=outbox(db,resource);submit(box,payload)
    resource.lose_response=True;assert dispatch(box)['state']=='unknown'
    row,_=box._load('resource','integrate','business');observation=resource.lookup(payload,deadline=0)
    import hashlib
    native='sha256:'+hashlib.sha256(observation.native_receipt).hexdigest()
    with route.locked() as active:
        c=db.connection;c.execute('BEGIN IMMEDIATE')
        original=dict(key=['resource','integrate','business'],expected='unknown',nativeDigest=native,
            actor='worker',time=103,requestDigest=row['request_digest'],fingerprint=row['fingerprint'],
            sourceCheckpoint=db.checkpoint(),sourceStateDigest=_state_digest(c))
        c.execute('UPDATE metadata SET time_floor=103')
        db._transition_action(c,('domain','resource','integrate','business'),'unknown','confirmed',native,native,observation.native_receipt,'worker')
        pending=dict(active,phase='settling',timeFloor=103,checkpoint=db.checkpoint(),
            migration=dict(settlementIntent=original,resultDigest=_state_digest(c)))
        route._publish(pending);c.execute('ROLLBACK' if boundary=='before-commit' else 'COMMIT')
    restored=box.reconcile('resource','integrate','business',actor='successor',now=104,authorize=authorize)
    assert restored['state']=='confirmed' and reserved(db)==5 and resource.count()==1
    event=db.connection.execute("SELECT actor,body FROM audit WHERE event='action_confirmed'").fetchone()
    assert event['actor']=='worker' and codec.parse(event['body'].encode())=={'key':['domain','resource','integrate','business'],'receiptDigest':native}
    assert db.connection.execute("SELECT COUNT(*) FROM audit WHERE event='outbox_reconciled'").fetchone()[0]==1
    db.check_integrity()


def test_completed_cycle_stops_previously_reserved_unsent_business_action(setup):
    db,resource,intent=setup;box=outbox(db,resource)
    submit(box,intent);first=dispatch(box)
    later=deepcopy(intent);later['businessActionId']='later';later['cost']=1
    box.submit(later,actor='worker',now=102,authorize=authorize)
    db.record_completion(TaskKey('domain','project','change','task'),cycle=1,revision=1,
        resource_id='resource',action_class='integrate',business_id='business',
        receipt_digest=first['receipt_digest'],evidence_digest=D,
        actor='worker',now=103,authorize=authorize)
    checkpoint=db.checkpoint()
    with pytest.raises(CoordinationError,match='completed'):
        box.dispatch('resource','integrate','later',actor='worker',now=104,authorize=authorize)
    assert resource.execute_calls==1 and resource.count()==1 and reserved(db)==6
    assert db.checkpoint()==checkpoint
    assert db.connection.execute("SELECT state FROM business_actions WHERE business_id='later'").fetchone()[0]=='reserved'
    db.check_integrity()


@pytest.mark.parametrize('outcome',['confirmed','not_executed'])
def test_completed_cycle_settles_inflight_facts_without_resend(setup,outcome):
    db,resource,intent=setup;box=outbox(db,resource)
    submit(box,intent);first=dispatch(box)
    later=deepcopy(intent);later['businessActionId']='inflight';later['cost']=1
    box.submit(later,actor='worker',now=102,authorize=authorize)
    resource.lose_response=outcome=='confirmed';resource.suppress=outcome=='not_executed'
    assert box.dispatch('resource','integrate','inflight',actor='worker',now=102,authorize=authorize)['state']=='unknown'
    key=TaskKey('domain','project','change','task')
    original=db.record_completion(key,cycle=1,revision=1,resource_id='resource',action_class='integrate',
        business_id='business',receipt_digest=first['receipt_digest'],evidence_digest=D,
        actor='worker',now=103,authorize=authorize)
    result=box.reconcile('resource','integrate','inflight',actor='successor',now=104,authorize=authorize)
    assert result['state']==outcome and resource.execute_calls==2
    assert resource.count()==(2 if outcome=='confirmed' else 1) and reserved(db)==6
    assert dict(db.connection.execute('SELECT * FROM completions').fetchone())==original
    checkpoint=db.checkpoint()
    if outcome=='not_executed':
        with pytest.raises(CoordinationError,match='completed'):
            db.transition_action('resource','integrate','inflight',expected='not_executed',target='reserved',
                actor='worker',now=104,authorize=authorize)
        assert db.checkpoint()==checkpoint
    assert db.connection.execute('SELECT cycle FROM tasks').fetchone()[0]==1
    db.check_integrity()


def test_success_retains_exact_native_receipt_and_does_not_imply_completion(setup):
    db,resource,intent=setup;box=outbox(db,resource)
    submit(box,intent)
    result=dispatch(box)
    assert result['state']=='confirmed' and resource.count()==1 and reserved(db)==5
    native=db.connection.execute('SELECT native_bytes,native_digest FROM resource_observations').fetchone()
    assert native['native_bytes']==resource.lookup(intent,deadline=0).native_receipt
    assert native['native_digest']==result['receipt_digest']
    assert not db.connection.execute('SELECT * FROM completions').fetchall()
    db.check_integrity()


def test_same_key_and_payload_survive_identity_handoff_without_new_reservation(setup):
    db,resource,intent=setup;box=outbox(db,resource)
    first=submit(box,intent)
    assert submit(box,intent,'successor')==first and reserved(db)==5
    changed=deepcopy(intent);changed['parameters']['after']='another'
    with pytest.raises(CoordinationError,match='immutable request'):submit(box,changed)
    assert reserved(db)==5 and resource.count()==0


def test_response_loss_is_resolved_by_independent_lookup_without_resend(setup):
    db,resource,intent=setup;resource.lose_response=True;box=outbox(db,resource)
    submit(box,intent)
    assert dispatch(box)['state']=='unknown'
    assert resource.count()==resource.execute_calls==1
    with pytest.raises(CoordinationError,match='reconcile'):dispatch(box)
    assert reconcile(box)['state']=='confirmed'
    assert resource.execute_calls==resource.count()==1 and reserved(db)==5


def test_real_process_exit_after_native_commit_recovers_original_action(setup):
    db,resource,intent=setup;box=outbox(db,resource)
    submit(box,intent)
    script='''
import sys
from tests.protected.test_sqlite_outbox import FixtureResource,outbox,dispatch
from dasops.protected.sqlite.store import CoordinationDatabase
writer=CoordinationDatabase(sys.argv[1],authority_domain='domain')
resource=FixtureResource(sys.argv[2],crash=True)
dispatch(outbox(writer,resource))
'''
    env=dict(os.environ,PYTHONPATH=str(Path(__file__).resolve().parents[2]),PYTHONDONTWRITEBYTECODE='1')
    result=subprocess.run([sys.executable,'-B','-c',script,str(db.path),str(resource.path)],env=env,capture_output=True,timeout=10)
    assert result.returncode==23,result.stderr.decode()
    restored=CoordinationDatabase(db.path,authority_domain='domain')
    try:
        recovered=outbox(restored,resource)
        assert recovered._load('resource','integrate','business')[0]['state']=='dispatched'
        assert reconcile(recovered)['state']=='confirmed'
        assert resource.execute_calls==0 and resource.count()==1 and reserved(restored)==5
        restored.check_integrity()
    finally:restored.close()


@pytest.mark.parametrize('closed', [False, True])
@pytest.mark.parametrize('verified', [False, True])
def test_real_process_exit_before_send_requires_verified_absence_and_closed_execution(setup, closed, verified):
    db,resource,intent=setup;submit(outbox(db,resource),intent)
    script='''
import sys
from tests.protected.test_sqlite_outbox import FixtureResource,outbox,dispatch
from dasops.protected.sqlite.store import CoordinationDatabase
writer=CoordinationDatabase(sys.argv[1],authority_domain='domain')
resource=FixtureResource(sys.argv[2],crash_before=True)
dispatch(outbox(writer,resource))
'''
    env=dict(os.environ,PYTHONPATH=str(Path(__file__).resolve().parents[2]),PYTHONDONTWRITEBYTECODE='1')
    result=subprocess.run([sys.executable,'-B','-c',script,str(db.path),str(resource.path)],env=env,capture_output=True,timeout=10)
    assert result.returncode==23,result.stderr.decode()
    restored=CoordinationDatabase(db.path,authority_domain='domain')
    try:
        box=outbox(restored,resource,closed=closed and result.returncode==23,
                   verifier=resource.verify if verified else lambda *args:False)
        assert box._load('resource','integrate','business')[0]['state']=='dispatched'
        assert resource.count()==0
        with pytest.raises(CoordinationError,match='reconcile'):dispatch(box)
        recovered=reconcile(box)
        assert recovered['state']==('not_executed' if closed and verified else 'unknown')
        assert recovered['original_actor']=='worker'
        assert reserved(restored)==5 and resource.execute_calls==resource.count()==0
        assert not restored.connection.execute('SELECT * FROM completions').fetchall()
        if closed and verified:
            observation=restored.connection.execute('SELECT outcome,native_bytes FROM resource_observations').fetchone()
            assert observation['outcome']=='not_executed'
            assert observation['native_bytes']==resource.lookup(intent,deadline=0).native_receipt
            # Only a separate freshly authorized retry can resume the original
            # key. Reconciliation itself neither resends nor refunds its budget.
            restored.transition_action('resource','integrate','business',expected='not_executed',target='reserved',
                actor='successor',now=104,authorize=authorize)
            assert dispatch(box,actor='successor',now=105)['state']=='confirmed'
            assert resource.execute_calls==resource.count()==1 and reserved(restored)==5
        else:
            with pytest.raises(CoordinationError,match='reconcile'):dispatch(box)
            assert not restored.connection.execute('SELECT * FROM resource_observations').fetchall()
        restored.check_integrity()
    finally:restored.close()


def test_current_denial_commits_neither_dispatch_nor_resource_effect(setup):
    db,resource,intent=setup;box=outbox(db,resource)
    submit(box,intent)
    with pytest.raises(CoordinationError,match='authorization'):
        dispatch(box,authorize=lambda *args:False)
    assert resource.count()==resource.execute_calls==0
    assert box._load('resource','integrate','business')[0]['state']=='reserved'
    assert reserved(db)==5


@pytest.mark.parametrize('moment',['before-send','after-native-commit'])
def test_current_revocation_preserves_original_effect_for_authorized_successor(setup,tmp_path,moment):
    db,resource,intent=setup;box=outbox(db,resource)
    # Installed TEST authority reads a separate committed current-control row
    # on every operation, not a permission captured when reserve was accepted.
    controls=tmp_path/'current-permissions.db'
    with sqlite3.connect(controls) as c:
        c.execute('CREATE TABLE current (revoked INTEGER NOT NULL)')
        c.execute('INSERT INTO current VALUES (0)')
    operations=[]
    def current(c,operation,actor,epoch):
        assert c.in_transaction and epoch==1
        with sqlite3.connect(controls) as independent:
            revoked=independent.execute('SELECT revoked FROM current').fetchone()[0]
        operations.append((operation,actor,revoked))
        return ((actor=='worker' and not revoked) or
                (actor=='successor' and operation in ('action_lookup','action_confirmed')))
    def revoke():
        with sqlite3.connect(controls) as c:c.execute('UPDATE current SET revoked=1')
    box.submit(intent,actor='worker',now=101,authorize=current)
    original=db.connection.execute('SELECT payload_json,request_digest FROM action_payloads').fetchone()[:]
    execute=resource.execute
    def commit_then_revoke(value,*,deadline):
        execute(value,deadline=deadline)
        revoke()
        raise TimeoutError('TEST original effect committed, response lost, credentials revoked')
    resource.execute=commit_then_revoke
    if moment=='before-send':revoke()
    with pytest.raises(CoordinationError,match='authorization'):
        dispatch(box,authorize=current)
    expected='reserved' if moment=='before-send' else 'dispatched'
    assert box._load('resource','integrate','business')[0]['state']==expected
    assert resource.count()==resource.execute_calls==(moment=='after-native-commit')
    assert reserved(db)==5
    checkpoint=db.checkpoint()
    if moment=='before-send':
        with pytest.raises(CoordinationError,match='authorization'):
            dispatch(box,actor='successor',now=103,authorize=current)
        assert db.checkpoint()==checkpoint and resource.execute_calls==0
        return
    with pytest.raises(CoordinationError,match='authorization'):
        box.reconcile('resource','integrate','business',actor='worker',now=103,authorize=current)
    assert db.checkpoint()==checkpoint and resource.count()==1 and reserved(db)==5
    with pytest.raises(CoordinationError,match='reconcile'):
        dispatch(box,actor='successor',now=103,authorize=current)
    with pytest.raises(CoordinationError,match='business key'):
        box.reconcile('resource','integrate','other',actor='successor',now=103,authorize=current)
    result=box.reconcile('resource','integrate','business',actor='successor',now=103,authorize=current)
    assert result['state']=='confirmed' and result['original_actor']=='worker'
    assert db.connection.execute('SELECT payload_json,request_digest FROM action_payloads').fetchone()[:]==original
    native=resource.lookup(intent,deadline=0)
    observation=db.connection.execute('SELECT native_bytes,native_digest FROM resource_observations').fetchone()
    assert observation['native_bytes']==native.native_receipt and observation['native_digest']==result['receipt_digest']
    changed=deepcopy(intent);changed['businessActionId']='replacement'
    with pytest.raises(CoordinationError,match='authorization'):
        box.submit(changed,actor='successor',now=104,authorize=current)
    with pytest.raises(CoordinationError,match='authorization'):
        db.record_completion(TaskKey('domain','project','change','task'),cycle=1,revision=1,
            resource_id='resource',action_class='integrate',business_id='business',receipt_digest=result['receipt_digest'],
            evidence_digest=D,actor='successor',now=104,authorize=current)
    assert ('action_lookup','worker',1) in operations and ('action_confirmed','successor',1) in operations
    with sqlite3.connect(db.path) as reader:
        assert reader.execute('SELECT COUNT(*) FROM completions').fetchone()[0]==0
        assert reader.execute('SELECT COUNT(*) FROM business_actions').fetchone()[0]==1
        assert reader.execute('SELECT reserved FROM budgets').fetchone()[0]==5
    assert resource.count()==resource.execute_calls==1
    db.check_integrity()


def test_two_real_writer_connections_send_only_one_original_business_action(setup):
    db,resource,intent=setup;submit(outbox(db,resource),intent)
    barrier=threading.Barrier(2)
    def contender():
        writer=CoordinationDatabase(db.path,authority_domain='domain',busy_ms=2000)
        try:
            barrier.wait(timeout=5)
            try:return dispatch(outbox(writer,resource))['state']
            except CoordinationError:return 'denied'
        finally:writer.close()
    with ThreadPoolExecutor(2) as pool:
        first=pool.submit(contender);second=pool.submit(contender)
        assert sorted([first.result(timeout=10),second.result(timeout=10)])==['confirmed','denied']
    assert resource.count()==resource.execute_calls==1 and reserved(db)==5


def test_native_absence_requires_independent_closure_of_the_prior_dispatch(setup):
    db,resource,intent=setup;resource.suppress=True
    box=outbox(db,resource,closed=False);submit(box,intent)
    assert dispatch(box)['state']=='unknown'
    assert reconcile(box)['state']=='unknown' and resource.count()==0
    closed=outbox(db,resource,closed=True)
    assert reconcile(closed)['state']=='not_executed'
    assert reserved(db)==5
    with pytest.raises(CoordinationError,match='reconcile'):dispatch(closed)
    db.transition_action('resource','integrate','business',expected='not_executed',target='reserved',
        actor='successor',now=104,authorize=authorize)
    resource.suppress=False
    assert dispatch(closed,actor='successor',now=105)['state']=='confirmed'
    assert resource.count()==1 and reserved(db)==5
    assert len(db.connection.execute('SELECT * FROM resource_observations').fetchall())==2


@pytest.mark.parametrize('fault',['lost-response','before-send','foreign-object'])
def test_scoped_test_cleanup_retains_unknown_key_budget_and_other_tenant(setup,fault):
    """Finite installed TEST audit adapter, not a new public cleanup operation."""
    db,resource,intent=setup
    connection=sqlite3.connect(resource.path)
    connection.execute('CREATE TABLE test_objects (tenant TEXT NOT NULL, object_id TEXT NOT NULL, PRIMARY KEY(tenant,object_id))')
    connection.executemany('INSERT INTO test_objects VALUES (?,?)',[('test-a','fixture'),('test-b','fixture')])
    connection.commit();connection.close()
    value=deepcopy(intent);value.update(action='audit',originalActor='TEST-cleanup',parameters={'purpose':'cleanup','tenant':'test-b' if fault=='foreign-object' else 'test-a','objectId':'fixture'})
    native_execute=resource.execute;closed={'value':False}
    def cleanup(intent,*,deadline):
        if intent['parameters']!={'purpose':'cleanup','tenant':'test-a','objectId':'fixture'}:
            resource.execute_calls+=1
            raise PermissionError('TEST principal cannot clean another actual tenant/object')
        if fault=='before-send' and not closed['value']:
            resource.execute_calls+=1
            raise TimeoutError('TEST original dispatch has no independently established outcome')
        # Existing idempotency/receipt storage is reused; deletion is conditional
        # on the exact installed TEST object, never a caller-selected path.
        connection=sqlite3.connect(resource.path)
        connection.execute("DELETE FROM test_objects WHERE tenant='test-a' AND object_id='fixture'")
        connection.commit();connection.close()
        return native_execute(intent,deadline=deadline)
    resource.execute=cleanup;resource.lose_response=fault=='lost-response'
    def permitted(c,o,a,e):return c.in_transaction and a=='TEST-cleanup' and e==1
    box=DurableOutbox(db,adapters={('resource','instance','audit'):resource},
        verify_observation=resource.verify,execution_closed=lambda intent:closed['value'])
    box.submit(value,actor='TEST-cleanup',now=101,authorize=permitted)
    original=dict(db.connection.execute('SELECT * FROM business_actions').fetchone())
    assert box.dispatch('resource','audit','business',actor='TEST-cleanup',now=102,authorize=permitted)['state']=='unknown'
    assert resource.execute_calls==1 and reserved(db)==5
    with pytest.raises(CoordinationError,match='reconcile'):
        box.dispatch('resource','audit','business',actor='TEST-cleanup',now=103,authorize=permitted)
    result=box.reconcile('resource','audit','business',actor='TEST-cleanup',now=103,authorize=permitted)
    assert result['state']==('confirmed' if fault=='lost-response' else 'unknown')
    assert resource.execute_calls==1 and result['fingerprint']==original['fingerprint'] and reserved(db)==5
    if fault=='before-send':
        # Only the independently closed original permits one explicit same-key
        # bounded retry. No new budget/key/actor is manufactured by a timeout.
        closed['value']=True
        assert box.reconcile('resource','audit','business',actor='TEST-cleanup',now=104,authorize=permitted)['state']=='not_executed'
        db.transition_action('resource','audit','business',expected='not_executed',target='reserved',actor='TEST-cleanup',now=104,authorize=permitted)
        assert box.dispatch('resource','audit','business',actor='TEST-cleanup',now=105,authorize=permitted)['state']=='confirmed'
        assert resource.execute_calls==2
    connection=sqlite3.connect(resource.path)
    try:objects=connection.execute('SELECT tenant,object_id FROM test_objects ORDER BY tenant').fetchall()
    finally:connection.close()
    assert objects==([('test-a','fixture'),('test-b','fixture')] if fault=='foreign-object' else [('test-b','fixture')])
    assert resource.count()==int(fault!='foreign-object') and reserved(db)==5
    assert db.connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0]==0
    db.check_integrity()


@pytest.mark.parametrize('defect',['instance','digest','native','verifier','adapter-pass-json'])
def test_transport_claims_cannot_replace_independently_observed_resource_fact(setup,defect):
    db,resource,intent=setup;native_execute=resource.execute
    def forged(value,*,deadline):
        original=native_execute(value,deadline=deadline)
        if defect=='adapter-pass-json':return {'PASS':True,'receipt':original.native_receipt}
        return Observation(original.outcome, 'sha256:'+'2'*64 if defect=='digest' else original.request_digest,
            'other' if defect=='instance' else original.resource_instance,
            b'candidate says PASS' if defect=='native' else original.native_receipt)
    resource.execute=forged
    box=outbox(db,resource,verifier=(lambda *args:False) if defect=='verifier' else None)
    submit(box,intent)
    assert dispatch(box)['state']=='unknown' and resource.count()==1
    assert not db.connection.execute('SELECT * FROM resource_observations').fetchall()
    assert reserved(db)==5


def test_partial_reservation_failure_retains_neither_intent_nor_action(setup):
    db,resource,intent=setup;intent['budgetIds']=['absent','shared']
    with pytest.raises(CoordinationError,match='absent'):submit(outbox(db,resource),intent)
    assert not db.connection.execute('SELECT * FROM action_payloads').fetchall()
    assert not db.connection.execute('SELECT * FROM business_actions').fetchall()
    assert reserved(db)==0


@pytest.mark.parametrize('field,bad', [('taskRevision',True),('taskCycle',None),('cost',1.5),('targetGeneration',9007199254740992)])
def test_exact_security_fields_cannot_be_rounded_or_defaulted(setup,field,bad):
    db,resource,intent=setup;intent[field]=bad
    with pytest.raises((ValueError,TypeError)):
        submit(outbox(db,resource),intent)
    assert reserved(db)==0 and resource.count()==0


def test_current_task_revision_and_closed_parent_reject_new_work(setup):
    db,resource,intent=setup;box=outbox(db,resource)
    altered=deepcopy(intent);altered['taskRevision']=2
    with pytest.raises(CoordinationError,match='authorization'):submit(box,altered)
    submit(box,intent);resource.lose_response=True
    assert dispatch(box)['state']=='unknown'
    generation=db.connection.execute('SELECT generation FROM changes').fetchone()[0]
    db.begin_closing('project','change',generation,actor='admin',now=102,authorize=authorize)
    # Record a real in-flight fact while closing; no new execution or Completion.
    assert reconcile(box)['state']=='confirmed' and resource.count()==1
    assert not db.connection.execute('SELECT * FROM completions').fetchall()


def parent_authority(connection, operation, actor, epoch):
    return (authorize(connection,operation,actor,epoch)
        and (operation not in ('terminate_change','create_change') or actor=='admin'))


@pytest.mark.parametrize('terminal',['cancelled','superseded'])
@pytest.mark.parametrize('installed_route',[False,True])
def test_parent_termination_stops_unsent_actions_without_refund_or_new_completion(setup,tmp_path,terminal,installed_route):
    db,resource,intent=setup;box=outbox(db,resource)
    if installed_route:
        from dasops.protected.sqlite.authority import AuthorityRoute
        directory=tmp_path/'parent-route';directory.mkdir(mode=0o700)
        route=AuthorityRoute(directory/'route.json',authority_domain='domain')
        route.enroll(db,actor='admin',now=100,approve=lambda *args:True)
    submit(box,intent)
    key=TaskKey('domain','project','change','task')
    generation=db.connection.execute('SELECT generation FROM changes').fetchone()[0]
    options=dict(status=terminal,successor='next' if terminal=='superseded' else None,
        actor='admin',now=102,authorize=parent_authority)
    before=db.checkpoint()
    with pytest.raises(CoordinationError,match='authorization'):
        db.terminate_change('project','change',generation,**dict(options,actor='worker'))
    with pytest.raises(CoordinationError,match='generation'):
        db.terminate_change('project','change',generation+1,**options)
    assert db.checkpoint()==before
    assert db.terminate_change('project','change',generation,**options)==generation+1
    stopped=db.checkpoint()
    assert db.connection.execute('SELECT state FROM business_actions').fetchone()[0]=='not_executed'
    with pytest.raises(CoordinationError,match='reserved'):dispatch(box)
    with pytest.raises(CoordinationError,match='parent'):
        db.transition_action('resource','integrate','business',expected='not_executed',target='reserved',
            actor='worker',now=103,authorize=authorize)
    assert db.checkpoint()==stopped and resource.count()==resource.execute_calls==0 and reserved(db)==5
    with pytest.raises(CoordinationError,match='parent'):
        db.claim(key,D,actor='worker',expires_at=200,now=103,authorize=authorize)
    with pytest.raises(CoordinationError,match='parent'):
        db.add_task(TaskKey('domain','project','change','new'),D,actor='admin',now=103,authorize=authorize)
    with pytest.raises(CoordinationError,match='parent'):
        db.begin_closing('project','change',generation+1,actor='admin',now=103,authorize=authorize)
    if terminal=='cancelled':
        db.create_change('project','next',predecessor='change',actor='admin',now=103,authorize=parent_authority)
    successor=TaskKey('domain','project','next','task')
    db.add_task(successor,D,actor='admin',now=103,authorize=authorize)
    next_intent=deepcopy(intent);next_intent['taskKey']['changeId']='next';next_intent['businessActionId']='next-business'
    box.submit(next_intent,actor='worker',now=103,authorize=authorize)
    assert box.dispatch('resource','integrate','next-business',actor='worker',now=103,authorize=authorize)['state']=='confirmed'
    assert resource.count()==resource.execute_calls==1 and reserved(db)==10
    assert not db.connection.execute('SELECT * FROM completions').fetchall()
    parent=db.connection.execute("SELECT status,generation FROM changes WHERE change_id='change'").fetchone()
    assert tuple(parent)==(terminal,generation+1)
    created=[codec.parse(row[0].encode()) for row in db.connection.execute("SELECT body FROM audit WHERE event='change_created'")]
    assert created[-1]['predecessor']=='change' and created[-1]['predecessorStatus']==terminal
    assert created[-1]['predecessorGeneration']==generation+1
    db.check_integrity()
    if installed_route:
        current=route.open_current()
        try:assert current.checkpoint()==db.checkpoint()
        finally:current.close()


@pytest.mark.parametrize('terminal',['cancelled','superseded'])
def test_terminal_parent_keeps_late_real_resource_fact_without_restoring_worker_permission(setup,terminal):
    db,resource,intent=setup;box=outbox(db,resource);submit(box,intent)
    resource.lose_response=True
    assert dispatch(box)['state']=='unknown' and resource.count()==1
    generation=db.connection.execute('SELECT generation FROM changes').fetchone()[0]
    db.terminate_change('project','change',generation,status=terminal,
        successor='next' if terminal=='superseded' else None,actor='admin',now=103,authorize=parent_authority)
    assert reconcile(box)['state']=='confirmed' and resource.execute_calls==1
    row=db.connection.execute('SELECT receipt_digest FROM business_actions').fetchone()
    with pytest.raises(CoordinationError,match='parent'):
        db.record_completion(TaskKey('domain','project','change','task'),cycle=1,revision=1,
            resource_id='resource',action_class='integrate',business_id='business',
            receipt_digest=row[0],evidence_digest=D,actor='worker',now=103,authorize=authorize)
    changed=deepcopy(intent);changed['businessActionId']='replacement'
    with pytest.raises(CoordinationError,match='parent'):
        box.submit(changed,actor='worker',now=103,authorize=authorize)
    assert reserved(db)==5 and not db.connection.execute('SELECT * FROM completions').fetchall()
    assert db.connection.execute('SELECT COUNT(*) FROM resource_observations').fetchone()[0]==1
    db.check_integrity()


@pytest.mark.parametrize('leading',['terminate','dispatch'])
def test_parent_termination_and_dispatch_share_one_actual_serialization_boundary(setup,leading):
    db,resource,intent=setup;submit(outbox(db,resource),intent)
    generation=db.connection.execute('SELECT generation FROM changes').fetchone()[0]
    entered=threading.Event();attempted=threading.Event();release=threading.Event();traces={}
    def contender(kind,held):
        writer=CoordinationDatabase(db.path,authority_domain='domain',busy_ms=2000);trace=[]
        def tracing(statement):
            trace.append(statement)
            if not held and statement.startswith('BEGIN IMMEDIATE'):attempted.set()
        writer.connection.set_trace_callback(tracing)
        def current(c,o,a,e):
            if held and not entered.is_set():
                entered.set();assert release.wait(timeout=5)
            return parent_authority(c,o,a,e)
        try:
            if kind=='terminate':
                writer.terminate_change('project','change',generation,status='cancelled',
                    actor='admin',now=102,authorize=current)
                return 'cancelled'
            try:
                return dispatch(outbox(writer,resource),authorize=current)['state']
            except CoordinationError as exc:
                assert 'parent' in str(exc) or 'reserved' in str(exc)
                return 'stopped'
        finally:traces[kind]=trace;writer.close()
    trailing='dispatch' if leading=='terminate' else 'terminate'
    with ThreadPoolExecutor(2) as pool:
        first=pool.submit(contender,leading,True);assert entered.wait(timeout=5)
        second=pool.submit(contender,trailing,False);assert attempted.wait(timeout=5);release.set()
        results={leading:first.result(timeout=10),trailing:second.result(timeout=10)}
    assert results['terminate']=='cancelled'
    assert resource.count()==resource.execute_calls==(0 if leading=='terminate' else 1)
    assert results['dispatch']==('stopped' if leading=='terminate' else 'confirmed')
    assert reserved(db)==5 and not db.connection.execute('SELECT * FROM completions').fetchall()
    assert db.connection.execute('SELECT status FROM changes').fetchone()[0]=='cancelled'
    assert 'BEGIN IMMEDIATE' in traces['terminate'] and 'COMMIT' in traces['terminate']
    assert 'BEGIN IMMEDIATE' in traces['dispatch']
    assert ('ROLLBACK' if leading=='terminate' else 'COMMIT') in traces['dispatch']
    db.check_integrity()


@pytest.mark.parametrize('number',[Decimal('1.0000000000000000001'),Decimal('9007199254740991.1')])
def test_fractional_exact_value_cannot_become_an_integer_through_jcs_rounding(setup,number):
    db,resource,intent=setup;intent['cost']=number
    with pytest.raises(codec.ExactJsonError):submit(outbox(db,resource),intent)
    assert reserved(db)==0 and resource.count()==0


def test_legal_integral_decimal_is_checked_before_encoding_without_mutating_input(setup):
    db,resource,intent=setup;intent['cost']=Decimal('5.0')
    raw=encode_intent(intent)
    assert codec.parse(raw)['cost']==5
    assert type(intent['cost']) is Decimal
    assert submit(outbox(db,resource),intent)['state']=='reserved'
