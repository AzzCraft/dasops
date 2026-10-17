"""Real installed-control TEST routing, not production isolation/power-loss proof."""
import sqlite3
import os
import subprocess
import sys
from pathlib import Path
import threading
import base64
import json
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor

import pytest

from dasops.protected.sqlite.authority import AuthorityRoute, _state_digest
from dasops.protected.sqlite.store import CoordinationDatabase, CoordinationError, TaskKey
from dasops.standards_contracts import exact_json as codec

D1='sha256:'+'1'*64
D2='sha256:'+'2'*64
D3='sha256:'+'3'*64


def current(c, operation, actor, epoch):
    assert c.in_transaction
    return actor in ('admin','worker') and epoch in (1,2)


def approve(c, operation, actor, epoch, subject):
    assert c.in_transaction
    assert operation in ('authority_enroll','authority_freeze','authority_activate','authority_reconcile')
    assert subject and epoch in (1,2)
    return actor=='admin'


@pytest.fixture
def installed(tmp_path):
    data=tmp_path/'state';data.mkdir(mode=0o700)
    control=tmp_path/'independent-control';control.mkdir(mode=0o700)
    db=CoordinationDatabase.create(data/'old.db',authority_domain='domain',instance_id='original')
    db.create_change('project','change',actor='admin',now=100,authorize=current)
    key=TaskKey('domain','project','change','original-task')
    db.add_task(key,D1,actor='admin',now=100,authorize=current)
    db.create_budget('shared',20,actor='admin',now=100,authorize=current)
    route=AuthorityRoute(control/'route.json',authority_domain='domain')
    route.enroll(db,actor='admin',now=101,approve=approve)
    try:yield db,route,key
    finally:db.close()


def reserve(db,key,business='original',cycle=1):
    return db.reserve(key,resource_id='resource',action_class='integrate',business_id=business,
        original_actor='worker',request_digest=D2,budget_ids=['shared'],cost=5,cycle=cycle,
        actor='worker',now=102 if db.instance_id=='original' else 110,authorize=current)


def freeze(db,route):
    route.freeze(db,destination=db.path.parent/'new.db',new_instance='next-instance',
        migration_id='migration-one',actor='admin',now=105,approve=approve)


@pytest.mark.parametrize('entry',['stage','activate'])
@pytest.mark.parametrize('boundary',['file','directory'])
def test_retained_backup_requires_confirmed_sync_before_stage_or_activation(installed,monkeypatch,entry,boundary):
    """Injected fsync errors on real descriptors, not a system-crash proof."""
    import stat
    db,route,key=installed
    reserve(db,key)
    db.transition_action('resource','integrate','original',expected='reserved',target='dispatched',actor='worker',now=102,authorize=current)
    db.transition_action('resource','integrate','original',expected='dispatched',target='confirmed',receipt_digest=D3,actor='worker',now=102,authorize=current)
    args=dict(cycle=1,revision=1,resource_id='resource',action_class='integrate',business_id='original',
        receipt_digest=D3,evidence_digest=D2,actor='worker',now=102,authorize=current)
    original=db.record_completion(key,**args)
    db.rework(key,expected_cycle=1,actor='worker',now=102,authorize=current)
    reserve(db,key,'unknown',cycle=2)
    db.transition_action('resource','integrate','unknown',expected='reserved',target='dispatched',actor='worker',now=104,authorize=current)
    db.transition_action('resource','integrate','unknown',expected='dispatched',target='unknown',actor='worker',now=104,authorize=current)
    freeze(db,route)
    witness=db.checkpoint();record=route.path.read_bytes();destination=db.path.parent/'new.db'
    real_sync=os.fsync;calls=[]
    def failed_sync(fd):
        actual=Path(os.readlink('/proc/self/fd/'+str(fd)))
        match=(actual==destination and stat.S_ISREG(os.fstat(fd).st_mode) if boundary=='file'
            else actual==destination.parent and stat.S_ISDIR(os.fstat(fd).st_mode))
        if match:
            calls.append(str(actual));raise OSError('injected '+boundary+' sync failure')
        return real_sync(fd)
    monkeypatch.setattr(os,'fsync',failed_sync)
    with pytest.raises(OSError,match='sync failure'):route.stage(db)
    retained=destination.read_bytes()
    with pytest.raises(OSError,match='sync failure'):
        if entry=='stage':route.stage(db)
        else:route.activate(actor='admin',now=107,approve=approve)
    assert len(calls)==2
    assert destination.read_bytes()==retained and db.checkpoint()==witness and route.path.read_bytes()==record
    with pytest.raises(CoordinationError):route.open_current()
    with pytest.raises(CoordinationError):reserve(db,key,'bypass',cycle=2)
    monkeypatch.setattr(os,'fsync',real_sync)
    assert route.stage(db)['checkpoint']==witness and destination.read_bytes()==retained
    result=route.activate(actor='admin',now=107,approve=approve)
    assert result['epoch']==2 and result['instance']=='next-instance'
    recovered=route.open_current()
    try:
        recovered.check_integrity()
        assert recovered.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==10
        assert reserve(recovered,key,'unknown',cycle=2)['state']=='unknown'
        args['now']=110
        assert recovered.record_completion(key,**args)==original
        assert recovered.connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0]==1
        assert recovered.connection.execute('SELECT COUNT(*) FROM business_actions').fetchone()[0]==2
        with pytest.raises(CoordinationError):reserve(db,key,'old-epoch',cycle=2)
    finally:recovered.close()


@pytest.mark.parametrize('variant',['candidate-root','changed-subject','current-root'])
def test_actual_current_root_signature_approves_only_exact_activation(installed,tmp_path,variant):
    """TEST external approval provider; existing production route API unchanged.

    Real Ed25519 verification precedes the SQL callback. It approves a fixed
    existing intent, not a product grant/new protocol or independent OS topology.
    """
    db,route,key=installed
    reserve(db,key)
    db.transition_action('resource','integrate','original',expected='reserved',target='dispatched',
                         actor='worker',now=103,authorize=current)
    freeze(db,route);staged=route.stage(db)
    record=json.loads(route.path.read_bytes())
    copy=CoordinationDatabase(staged['database'],authority_domain='domain')
    try:
        intent=dict(migration=record['migration'],source=record['database'],sourceInstance=record['instance'],
            sourceCheckpoint=record['checkpoint'],stateDigest=_state_digest(copy.connection),actor='admin',time=107)
    finally:copy.close()
    proposal=dict(operation='authority_activate',actor='admin',epoch=1,subject=intent)
    approved_bytes=codec.canonical(proposal)
    before_route=route.path.read_bytes();before_checkpoint=db.checkpoint()
    def snapshot(source,destination):
        with closing(sqlite3.connect('file:'+str(source)+'?mode=ro',uri=True)) as reader, closing(sqlite3.connect(destination)) as target:
            reader.backup(target)
    snapshot(db.path,tmp_path/'before-activation.db')

    def prepare(seed,body):
        # Fixed public TEST keys; old control key is never read from the proposal.
        private=os.memfd_create('TEST-control-approval-key',os.MFD_CLOEXEC)
        public=os.memfd_create('TEST-current-control-public',os.MFD_CLOEXEC)
        payload=os.memfd_create('TEST-approval-exact-bytes',os.MFD_CLOEXEC)
        signature=os.memfd_create('TEST-approval-signature',os.MFD_CLOEXEC)
        old=os.memfd_create('TEST-old-key-der',os.MFD_CLOEXEC)
        try:
            prefix=bytes.fromhex('302e020100300506032b657004220420')
            os.write(private,prefix+bytes([seed])*32);os.write(old,prefix+bytes([1])*32)
            actual_public=subprocess.check_output(['openssl','pkey','-inform','DER','-in',f'/proc/self/fd/{old}',
                '-pubout','-outform','DER'],pass_fds=(old,),stderr=subprocess.STDOUT,timeout=5)
            os.write(public,actual_public);os.write(payload,body)
            signed=subprocess.check_output(['openssl','pkeyutl','-sign','-rawin','-inkey',f'/proc/self/fd/{private}',
                '-keyform','DER','-in',f'/proc/self/fd/{payload}'],pass_fds=(private,payload),stderr=subprocess.STDOUT,timeout=5)
            os.write(signature,signed)
            checked=subprocess.run(['openssl','pkeyutl','-verify','-rawin','-pubin','-inkey',f'/proc/self/fd/{public}',
                '-keyform','DER','-in',f'/proc/self/fd/{payload}','-sigfile',f'/proc/self/fd/{signature}'],
                pass_fds=(public,payload,signature),capture_output=True,timeout=5)
            return dict(body=base64.b64encode(body).decode(),signature=base64.b64encode(signed).decode(),
                currentPublicKeyDer=base64.b64encode(actual_public).decode(),verificationExit=checked.returncode,
                verificationOutput=base64.b64encode(checked.stdout+checked.stderr).decode())
        finally:
            for fd in (private,public,payload,signature,old):os.close(fd)

    def consume(prepared):
        retained=base64.b64decode(prepared['body'])
        valid=prepared['verificationExit']==0
        def installed_approval(connection,operation,actor,epoch,subject):
            assert connection.in_transaction
            return valid and retained==codec.canonical(dict(operation=operation,actor=actor,epoch=epoch,subject=subject))
        return installed_approval

    body=approved_bytes if variant!='changed-subject' else codec.canonical(dict(proposal,subject=dict(intent,stateDigest=D3)))
    attempted=prepare(9 if variant=='candidate-root' else 1,body)
    if variant!='current-root':
        with pytest.raises(CoordinationError,match='independent administrative approval denied'):
            route.activate(actor='admin',now=107,approve=consume(attempted))
        assert route.path.read_bytes()==before_route and db.checkpoint()==before_checkpoint
        with pytest.raises(CoordinationError):route.open_current()
    approved=prepare(1,approved_bytes) if variant!='current-root' else attempted
    result=route.activate(actor='admin',now=107,approve=consume(approved))
    assert (result['epoch'],result['instance'])==(2,'next-instance')
    with pytest.raises(CoordinationError):reserve(db,key,'old-writer')
    new=route.open_current()
    try:
        assert tuple(new.connection.execute('SELECT reserved FROM budgets WHERE budget_id="shared"').fetchone())==(5,)
        assert tuple(new.connection.execute('SELECT state FROM business_actions').fetchone())==('dispatched',)
        assert tuple(new.connection.execute('SELECT COUNT(*) FROM completions').fetchone())==(0,)
        with pytest.raises(CoordinationError,match='authorization'):
            new.create_budget('old-epoch',1,actor='admin',now=110,authorize=lambda c,o,a,e:e==1)
        new.create_budget('approved-new-epoch',1,actor='admin',now=110,authorize=lambda c,o,a,e:e==2)
        assert tuple(new.connection.execute("SELECT COUNT(*) FROM audit WHERE event='authority_activated'").fetchone())==(1,)
        snapshot(new.path,tmp_path/'after-activation.db')
        new.check_integrity()
    finally:new.close()
    proof=dict(variant=variant,proposal=proposal,attempted=attempted,approved=approved,
        result=result,beforeCheckpoint=before_checkpoint,retainedBudget=5,pending='dispatched',
        sdkModule=__import__('dasops.protected.sqlite.authority',fromlist=['__file__']).__file__,
        approvalProvider='TEST external original-byte approval, not a new product protocol',qualificationEligible=False)
    (tmp_path/'runtime-attempt-control-activation.json').write_bytes(codec.canonical(proof))
    evidence=os.environ.get('DAS_CONTROL_ACTIVATION_EVIDENCE_DIR')
    if evidence:
        import shutil
        target=Path(evidence)/variant;target.mkdir(mode=0o700)
        for name in ('before-activation.db','after-activation.db','runtime-attempt-control-activation.json'):
            shutil.copyfile(tmp_path/name,target/name)


def test_forward_migration_preserves_unknown_budget_completion_and_fences_old_writers(installed):
    db,route,key=installed
    reserve(db,key)
    db.transition_action('resource','integrate','original',expected='reserved',target='dispatched',
        actor='worker',now=103,authorize=current)
    db.transition_action('resource','integrate','original',expected='dispatched',target='confirmed',
        receipt_digest=D3,actor='worker',now=103,authorize=current)
    original=db.record_completion(key,cycle=1,revision=1,resource_id='resource',action_class='integrate',
        business_id='original',receipt_digest=D3,evidence_digest=D2,actor='worker',now=103,authorize=current)
    db.rework(key,expected_cycle=1,actor='admin',now=104,authorize=current)
    db.reserve(key,resource_id='resource',action_class='integrate',business_id='unknown',
        original_actor='worker',request_digest=D2,budget_ids=['shared'],cost=5,cycle=2,
        actor='worker',now=104,authorize=current)
    db.transition_action('resource','integrate','unknown',expected='reserved',target='dispatched',
        actor='worker',now=104,authorize=current)
    db.transition_action('resource','integrate','unknown',expected='dispatched',target='unknown',
        actor='worker',now=104,authorize=current)
    db.claim(key,D1,actor='worker',expires_at=200,now=104,authorize=current)
    other=CoordinationDatabase(db.path,authority_domain='domain',authority_route=route)
    try:
        freeze(db,route); frozen=db.checkpoint()
        with pytest.raises(CoordinationError):other.create_budget('late',1,actor='admin',now=106,authorize=current)
        with pytest.raises(CoordinationError):route.open_current()
        staged=route.stage(db)
        assert route.stage(db)==staged  # exact existing stage, no overwrite
        copy=CoordinationDatabase(staged['database'],authority_domain='domain')
        try:
            with pytest.raises(CoordinationError,match='enrolled'):
                copy.create_budget('unmanaged-copy',1,actor='admin',now=106,authorize=current)
        finally:copy.close()
        result=route.activate(actor='admin',now=107,approve=approve)
        assert result['epoch']==2 and result['instance']=='next-instance'
        for old in (db,other):
            with pytest.raises(CoordinationError):
                old.reserve(key,resource_id='r',action_class='apply',business_id='late',original_actor='worker',
                    request_digest=D2,budget_ids=['shared'],cost=1,cycle=2,actor='worker',now=110,authorize=current)
            with pytest.raises(CoordinationError):
                with old.read_snapshot():pass
        assert db.checkpoint()==frozen
        new=route.open_current()
        try:
            assert new.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==10
            assert new.connection.execute("SELECT state FROM business_actions WHERE business_id='unknown'").fetchone()[0]=='unknown'
            assert new.connection.execute('SELECT expires_at FROM leases').fetchone()[0]==107
            assert new.record_completion(key,cycle=1,revision=1,resource_id='resource',action_class='integrate',
                business_id='original',receipt_digest=D3,evidence_digest=D2,actor='worker',now=110,authorize=current)==original
            assert reserve(new,key,'unknown',cycle=2)['state']=='unknown'
            with pytest.raises(CoordinationError):
                new.transition_action('resource','integrate','unknown',expected='unknown',target='dispatched',
                    actor='worker',now=110,authorize=current)
            assert len(new.connection.execute('SELECT * FROM completions').fetchall())==1
            assert len(new.connection.execute('SELECT * FROM business_actions').fetchall())==2
            assert new.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==10
            with pytest.raises(CoordinationError,match='authorization'):
                new.create_budget('stale-grant',1,actor='admin',now=110,authorize=lambda c,o,a,e:e==1)
            new.create_budget('new-authority',1,actor='admin',now=110,authorize=current)
            assert new.claim(key,D2,actor='worker',expires_at=200,now=110,authorize=current)==2
            with pytest.raises(CoordinationError):
                new.renew(key,D1,1,actor='worker',expires_at=250,now=110,authorize=current)
            new.check_integrity()
        finally:new.close()
    finally:other.close()


def test_external_watermark_rejects_valid_old_database_even_if_caller_offers_old_checkpoint(installed):
    db,route,key=installed
    old=db.path.parent/'stale.db';db.backup(old,minimum_checkpoint=db.checkpoint())
    reserve(db,key)
    restored=CoordinationDatabase(old,authority_domain='domain',authority_route=route)
    try:
        # Isolate history freshness from pathname and clock fencing: neither a
        # relocated old DB nor its self-reported old checkpoint proves freshness.
        with route.locked() as record:
            route.check_current(db.connection,db,record)
            with pytest.raises(CoordinationError,match='watermark'):
                route.check_current(restored.connection,restored,dict(record,database=str(old),timeFloor=101))
        with pytest.raises(CoordinationError):restored.verify_checkpoint(db.checkpoint())
        with pytest.raises(CoordinationError):restored.create_budget('fork',1,actor='admin',now=104,authorize=current)
    finally:restored.close()


@pytest.mark.parametrize('fault',['denied','changed-copy','regressed-time','wrong-instance'])
def test_activation_refuses_without_changing_old_history_or_enabling_staged_writer(installed,fault):
    db,route,key=installed
    reserve(db,key);freeze(db,route);route.stage(db);checkpoint=db.checkpoint()
    copy=sqlite3.connect(db.path.parent/'new.db')
    try:
        if fault=='changed-copy':copy.execute('UPDATE budgets SET ceiling=ceiling+1');copy.commit()
        if fault=='wrong-instance':copy.execute("UPDATE metadata SET instance_id='unexpected'");copy.commit()
    finally:copy.close()
    with pytest.raises(CoordinationError):
        route.activate(actor='worker' if fault=='denied' else 'admin',now=104 if fault=='regressed-time' else 107,approve=approve)
    assert db.checkpoint()==checkpoint
    with pytest.raises(CoordinationError):route.open_current()
    with pytest.raises(CoordinationError):db.create_budget('restart-old',1,actor='admin',now=110,authorize=current)


@pytest.mark.parametrize('boundary',['before-intent','after-intent','after-commit'])
def test_activation_publication_failure_recovers_original_intent_forward(installed,monkeypatch,boundary):
    db,route,key=installed
    reserve(db,key);freeze(db,route);route.stage(db);old_checkpoint=db.checkpoint()
    original_publish=route._publish
    def crash(record,**kw):
        if record['phase']=='activating' and boundary=='before-intent':
            raise OSError('injected before intent publication')
        if record['phase']=='activating' and boundary=='after-intent':
            original_publish(record,**kw)
            raise OSError('injected after durable intent before SQL commit')
        if record['phase']=='active' and boundary=='after-commit':
            raise OSError('injected after SQL commit before active publication')
        return original_publish(record,**kw)
    monkeypatch.setattr(route,'_publish',crash)
    with pytest.raises(OSError):route.activate(actor='admin',now=107,approve=approve)
    with pytest.raises(CoordinationError):route.open_current()
    with pytest.raises(CoordinationError):db.create_budget('unfreeze',1,actor='admin',now=108,authorize=current)
    monkeypatch.setattr(route,'_publish',original_publish)
    if boundary=='after-intent':
        # SQL rolled back to time 105, but the independently retained activation
        # intent already observed 107. Re-entry must not rewind that time floor.
        with pytest.raises(CoordinationError,match='clock'):
            route.activate(actor='admin',now=106,approve=approve)
    result=route.activate(actor='admin',now=109,approve=approve)
    assert result['epoch']==2 and db.checkpoint()==old_checkpoint
    new=route.open_current()
    try:
        assert new.connection.execute('SELECT COUNT(*) FROM audit WHERE event=\'authority_activated\'').fetchone()[0]==1
        assert new.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==5
        assert reserve(new,key)['state']=='reserved'
        assert new.connection.execute('SELECT COUNT(*) FROM business_actions').fetchone()[0]==1
    finally:new.close()


def test_unbound_existing_handle_cannot_bypass_enrollment(installed):
    db,route,key=installed
    unbound=CoordinationDatabase(db.path,authority_domain='domain')
    try:
        with pytest.raises(CoordinationError,match='enrolled'):
            unbound.create_budget('bypass',1,actor='admin',now=104,authorize=current)
        with pytest.raises(CoordinationError,match='enrolled'):
            with unbound.read_snapshot():pass
    finally:unbound.close()


def test_freeze_serializes_with_a_real_inflight_writer_and_rejects_late_connection(installed):
    db,route,_=installed
    entered=threading.Event();release=threading.Event();freezing=threading.Event()
    def write():
        other=CoordinationDatabase(db.path,authority_domain='domain',authority_route=route)
        try:
            with other.transaction('inflight-write','worker',104,current) as c:
                c.execute("INSERT INTO budgets VALUES ('domain','inflight',1,0)")
                other._audit(c,'budget_created','worker',{'budgetId':'inflight','ceiling':1})
                entered.set();assert release.wait(5)
        finally:other.close()
    def stop():
        other=CoordinationDatabase(db.path,authority_domain='domain',authority_route=route)
        try:
            freezing.set();freeze(other,route)
        finally:other.close()
    with ThreadPoolExecutor(max_workers=2) as pool:
        writer=pool.submit(write);assert entered.wait(5)
        freezer=pool.submit(stop);assert freezing.wait(5)
        try:assert not freezer.done()
        finally:release.set()
        writer.result(timeout=5);freezer.result(timeout=5)
    assert db.connection.execute("SELECT ceiling FROM budgets WHERE budget_id='inflight'").fetchone()[0]==1
    route.stage(db);route.activate(actor='admin',now=107,approve=approve)
    new=route.open_current()
    try:
        assert new.connection.execute("SELECT ceiling FROM budgets WHERE budget_id='inflight'").fetchone()[0]==1
    finally:new.close()
    with pytest.raises(CoordinationError):db.create_budget('late',1,actor='admin',now=110,authorize=current)


@pytest.mark.parametrize('boundary',['after-intent','after-commit'])
def test_actual_control_process_death_recovers_forward_without_resetting_history(installed,boundary,tmp_path):
    db,route,key=installed
    reserve(db,key);freeze(db,route);route.stage(db)
    code='''
import os,sys
from dasops.protected.sqlite.authority import AuthorityRoute
route=AuthorityRoute(sys.argv[1],authority_domain='domain')
original=route._publish
def publish(record,**kw):
    if sys.argv[2]=='after-intent' and record['phase']=='activating':
        original(record,**kw);os._exit(71)
    if sys.argv[2]=='after-commit' and record['phase']=='active':os._exit(72)
    return original(record,**kw)
route._publish=publish
route.activate(actor='admin',now=107,approve=lambda c,o,a,e,s:True)
'''
    result=subprocess.run([sys.executable,'-B','-c',code,str(route.path),boundary],
        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=15,
        env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1'))
    (tmp_path/'process-output.log').write_bytes(result.stdout)
    assert result.returncode==(71 if boundary=='after-intent' else 72),result.stdout.decode()
    with pytest.raises(CoordinationError):route.open_current()
    route.activate(actor='admin',now=109,approve=approve)
    new=route.open_current()
    try:
        assert reserve(new,key)['state']=='reserved'
        assert new.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==5
        assert new.connection.execute("SELECT COUNT(*) FROM audit WHERE event='authority_activated'").fetchone()[0]==1
    finally:new.close()


def test_route_cannot_share_the_database_backup_domain(installed):
    db,_,_=installed
    isolated=CoordinationDatabase.create(db.path.parent/'other.db',authority_domain='other',instance_id='other')
    route=AuthorityRoute(db.path.parent/'same-domain.json',authority_domain='other')
    try:
        with pytest.raises(CoordinationError,match='separate'):
            route.enroll(isolated,actor='admin',now=101,approve=approve)
    finally:isolated.close()


def test_staged_hardlink_cannot_activate_or_modify_the_frozen_source(installed):
    db,route,_=installed
    freeze(db,route);before=db.checkpoint()
    os.link(db.path,db.path.parent/'new.db')
    with pytest.raises(CoordinationError,match='private'):
        route.stage(db)
    with pytest.raises(CoordinationError,match='private'):
        route.activate(actor='admin',now=107,approve=approve)
    assert db.checkpoint()==before


def test_busy_route_fails_bounded_without_a_partial_write_and_allows_full_retry(installed):
    db,route,_=installed
    before=db.checkpoint()
    with route.locked():
        with pytest.raises(CoordinationError,match='busy'):
            db.create_budget('busy',1,actor='admin',now=104,authorize=current)
    assert db.checkpoint()==before and not db.connection.in_transaction
    db.create_budget('busy',1,actor='admin',now=104,authorize=current)
    assert db.connection.execute("SELECT ceiling FROM budgets WHERE budget_id='busy'").fetchone()[0]==1


def admin_case(tmp_path,operation):
    data=tmp_path/'data';data.mkdir(mode=0o700)
    control=tmp_path/'control';control.mkdir(mode=0o700)
    db=CoordinationDatabase.create(data/'old.db',authority_domain='domain',instance_id='original')
    db.create_change('project','change',actor='admin',now=100,authorize=current)
    key=TaskKey('domain','project','change','original-task')
    db.add_task(key,D1,actor='admin',now=100,authorize=current)
    db.create_budget('shared',20,actor='admin',now=100,authorize=current)
    for business in ('original','unknown'):
        reserve(db,key,business)
        db.transition_action('resource','integrate',business,expected='reserved',target='dispatched',
            actor='worker',now=102,authorize=current)
        db.transition_action('resource','integrate',business,expected='dispatched',
            target='confirmed' if business=='original' else 'unknown',
            receipt_digest=D3 if business=='original' else None,actor='worker',now=102,authorize=current)
    db.record_completion(key,cycle=1,revision=1,resource_id='resource',action_class='integrate',
        business_id='original',receipt_digest=D3,evidence_digest=D2,actor='worker',now=102,authorize=current)
    route=AuthorityRoute(control/'route.json',authority_domain='domain')
    if operation=='freeze':route.enroll(db,actor='admin',now=103,approve=approve)
    def run(approval=approve):
        if operation=='enroll':route.enroll(db,actor='admin',now=105,approve=approval)
        else:freeze(db,route) if approval is approve else route.freeze(db,
            destination=data/'new.db',new_instance='next-instance',migration_id='migration-one',
            actor='admin',now=105,approve=approval)
    return db,route,key,run


def pending_failure(route,monkeypatch,operation,boundary):
    publish=route._publish
    pending='enrolling' if operation=='enroll' else 'freezing'
    final='active' if operation=='enroll' else 'frozen'
    def fail(record,**kw):
        if record['phase']==pending and boundary=='after-intent':
            publish(record,**kw)
            raise OSError('durable admin intent, SQL not confirmed')
        if record['phase']==final and boundary=='after-commit':
            raise OSError('SQL committed, final route not published')
        return publish(record,**kw)
    monkeypatch.setattr(route,'_publish',fail)
    return publish


def assert_admin_recovered(db,route,operation,*,reconciliation=True):
    event='authority_enrolled' if operation=='enroll' else 'authority_frozen'
    rows=db.connection.execute('SELECT actor FROM audit WHERE event=?',(event,)).fetchall()
    assert [r[0] for r in rows]==['admin']  # original actor, not the recovery actor
    recoveries=db.connection.execute("SELECT actor,body FROM audit WHERE event='authority_reconciled'").fetchall()
    assert len(recoveries)==int(reconciliation)
    if recoveries:
        from dasops.standards_contracts.exact_json import parse
        body=parse(recoveries[0]['body'].encode())
        assert body['originalIntent']['actor']=='admin'
        assert body['recovery']['actor']==recoveries[0]['actor']
        assert body['recovery']['time']>=105 and body['route']==str(route.path)
    assert db.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==10
    assert db.connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0]==1
    assert db.connection.execute("SELECT state FROM business_actions WHERE business_id='unknown'").fetchone()[0]=='unknown'
    assert db.connection.execute('SELECT COUNT(*) FROM business_actions').fetchone()[0]==2
    if operation=='freeze':
        with pytest.raises(CoordinationError):route.open_current()
        route.stage(db);route.activate(actor='admin',now=110,approve=approve)
        with pytest.raises(CoordinationError):
            db.create_budget('old-writer',1,actor='admin',now=111,authorize=current)
    current_db=route.open_current()
    try:
        assert current_db.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==10
        assert current_db.connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0]==1
        assert current_db.connection.execute("SELECT state FROM business_actions WHERE business_id='unknown'").fetchone()[0]=='unknown'
        current_db.create_budget('legal',1,actor='admin',now=111,authorize=current)
        current_db.check_integrity()
    finally:current_db.close()
    with pytest.raises(CoordinationError,match='retained administrative'):
        route.reconcile(actor='admin',now=112,approve=approve)


@pytest.mark.parametrize('operation',['enroll','freeze'])
@pytest.mark.parametrize('boundary',['after-intent','after-commit'])
def test_admin_publication_failure_recovers_exact_original_and_consumer(tmp_path,monkeypatch,operation,boundary):
    db,route,_,run=admin_case(tmp_path,operation)
    try:
        publish=pending_failure(route,monkeypatch,operation,boundary)
        with pytest.raises(OSError):run()
        with pytest.raises(CoordinationError):route.open_current()
        blocked=CoordinationDatabase(db.path,authority_domain='domain',authority_route=route)
        try:
            with pytest.raises(CoordinationError):
                with blocked.read_snapshot():pass
            with pytest.raises(CoordinationError):
                blocked.create_budget('late',1,actor='admin',now=106,authorize=current)
        finally:blocked.close()
        monkeypatch.setattr(route,'_publish',publish)
        def recovery_approval(c,o,a,e,s):
            assert o=='authority_reconcile' and a=='recovery-admin'
            assert s['original']['migration'] and s['route']==str(route.path)
            return True
        result=route.reconcile(actor='recovery-admin',now=109,approve=recovery_approval)
        assert result['phase']==('active' if operation=='enroll' else 'frozen')
        assert_admin_recovered(db,route,operation)
    finally:db.close()


@pytest.mark.parametrize('operation',['enroll','freeze'])
@pytest.mark.parametrize('boundary',['after-intent','after-commit'])
def test_real_admin_process_exit_recovers_original_once(tmp_path,operation,boundary):
    db,route,_,_=admin_case(tmp_path,operation)
    code='''
import os,sys
from pathlib import Path
from dasops.protected.sqlite import AuthorityRoute,CoordinationDatabase
route=AuthorityRoute(sys.argv[1],authority_domain='domain');operation,boundary=sys.argv[3:5]
db=CoordinationDatabase(sys.argv[2],authority_domain='domain',authority_route=route if operation=='freeze' else None)
publish=route._publish;pending='enrolling' if operation=='enroll' else 'freezing'
final='active' if operation=='enroll' else 'frozen'
def crash(record,**kw):
 if record['phase']==pending and boundary=='after-intent':publish(record,**kw);os._exit(71)
 if record['phase']==final and boundary=='after-commit':os._exit(72)
 return publish(record,**kw)
route._publish=crash
if operation=='enroll':route.enroll(db,actor='admin',now=105,approve=lambda *args:True)
else:route.freeze(db,destination=Path(sys.argv[2]).parent/'new.db',new_instance='next-instance',migration_id='migration-one',actor='admin',now=105,approve=lambda *args:True)
'''
    try:
        result=subprocess.run([sys.executable,'-B','-c',code,str(route.path),str(db.path),operation,boundary],
            capture_output=True,timeout=15,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1'))
        (tmp_path/'control-process.stdout').write_bytes(result.stdout)
        (tmp_path/'control-process.stderr').write_bytes(result.stderr)
        assert result.returncode==(71 if boundary=='after-intent' else 72),result.stderr.decode()
        with pytest.raises(CoordinationError):route.open_current()
        route.reconcile(actor='admin',now=109,approve=approve)
        assert_admin_recovered(db,route,operation)
    finally:db.close()


@pytest.mark.parametrize('operation',['enroll','freeze'])
@pytest.mark.parametrize('fault',['denied','subject','sql','drift','clock'])
def test_admin_reconciliation_refuses_bad_approval_changed_state_and_clock(tmp_path,monkeypatch,operation,fault):
    db,route,_,run=admin_case(tmp_path,operation)
    try:
        publish=pending_failure(route,monkeypatch,operation,'after-intent')
        with pytest.raises(OSError):run()
        monkeypatch.setattr(route,'_publish',publish)
        if fault=='drift':db.connection.execute('UPDATE budgets SET ceiling=ceiling+1')
        before=_state_digest(db.connection);route_bytes=route.path.read_bytes()
        def approval(c,o,a,e,s):
            if fault=='subject':s['original']['checkpoint']['sequence']=0
            if fault=='sql':c.execute('UPDATE budgets SET ceiling=ceiling+1')
            return fault!='denied'
        with pytest.raises(CoordinationError):route.reconcile(actor='admin',now=104 if fault=='clock' else 109,approve=approval)
        assert _state_digest(db.connection)==before and route.path.read_bytes()==route_bytes
        with pytest.raises(CoordinationError):route.open_current()
    finally:db.close()


@pytest.mark.parametrize('operation',['enroll','freeze'])
@pytest.mark.parametrize('boundary',['after-intent','after-commit'])
def test_repeated_admin_recovery_failure_retains_clock_and_exact_once(tmp_path,monkeypatch,operation,boundary):
    db,route,_,run=admin_case(tmp_path,operation)
    try:
        publish=pending_failure(route,monkeypatch,operation,'after-intent')
        with pytest.raises(OSError):run()
        monkeypatch.setattr(route,'_publish',publish)
        pending_failure(route,monkeypatch,operation,boundary)
        with pytest.raises(OSError):route.reconcile(actor='admin',now=107,approve=approve)
        monkeypatch.setattr(route,'_publish',publish)
        with pytest.raises(CoordinationError,match='clock'):
            route.reconcile(actor='admin',now=106,approve=approve)
        route.reconcile(actor='admin',now=109,approve=approve)
        assert_admin_recovered(db,route,operation)
    finally:db.close()


@pytest.mark.parametrize('operation',['enroll','freeze'])
@pytest.mark.parametrize('boundary',['after-intent','after-commit'])
@pytest.mark.parametrize('field',['actor','time'])
def test_admin_recovery_rejects_changed_first_recovery(tmp_path,monkeypatch,operation,boundary,field):
    from copy import deepcopy
    db,route,_,run=admin_case(tmp_path,operation)
    try:
        publish=pending_failure(route,monkeypatch,operation,'after-intent')
        with pytest.raises(OSError):run()
        monkeypatch.setattr(route,'_publish',publish);pending_failure(route,monkeypatch,operation,boundary)
        with pytest.raises(OSError):route.reconcile(actor='admin',now=107,approve=approve)
        monkeypatch.setattr(route,'_publish',publish);retained=route._read();damaged=deepcopy(retained)
        damaged['migration']['recoveryIntent'][field]='forged' if field=='actor' else 106
        route._publish(damaged);before=_state_digest(db.connection);pending=route.path.read_bytes()
        with pytest.raises(CoordinationError):route.reconcile(actor='admin',now=109,approve=approve)
        assert _state_digest(db.connection)==before and route.path.read_bytes()==pending
        if field=='actor':
            for malformed in (None,[],{}, {'actor':True,'time':107,'phase':retained['phase'],'checkpoint':retained['migration']['priorCheckpoint']}):
                damaged=deepcopy(retained);damaged['migration']['recoveryIntent']=malformed
                route._publish(damaged);pending=route.path.read_bytes()
                with pytest.raises(CoordinationError):route.reconcile(actor='admin',now=109,approve=approve)
                assert _state_digest(db.connection)==before and route.path.read_bytes()==pending
            for keys in (('recoveryIntent',),('priorCheckpoint',),('priorResultDigest',),('recoveryIntent','priorCheckpoint','priorResultDigest')):
                damaged=deepcopy(retained)
                for key in keys:damaged['migration'].pop(key)
                route._publish(damaged);pending=route.path.read_bytes()
                with pytest.raises(CoordinationError):route.reconcile(actor='admin',now=109,approve=approve)
                assert _state_digest(db.connection)==before and route.path.read_bytes()==pending
        route._publish(retained);route.reconcile(actor='admin',now=109,approve=approve)
        event=db.connection.execute("SELECT body FROM audit WHERE event='authority_reconciled'").fetchall()
        assert len(event)==1
        recovery=__import__('json').loads(event[0][0])['recovery'];assert recovery['actor']=='admin' and recovery['time']==107
        assert_admin_recovered(db,route,operation)
    finally:db.close()


@pytest.mark.parametrize('operation',['enroll','freeze'])
def test_admin_recovery_rejects_changed_original_actor(tmp_path,monkeypatch,operation):
    from copy import deepcopy
    db,route,_,run=admin_case(tmp_path,operation)
    try:
        publish=pending_failure(route,monkeypatch,operation,'after-commit')
        with pytest.raises(OSError):run()
        monkeypatch.setattr(route,'_publish',publish);retained=route._read();damaged=deepcopy(retained)
        field='enrollmentIntent' if operation=='enroll' else 'freezeIntent'
        damaged['migration'][field]['actor']='forged';route._publish(damaged)
        before=_state_digest(db.connection);pending=route.path.read_bytes()
        with pytest.raises(CoordinationError):route.reconcile(actor='admin',now=109,approve=approve)
        assert _state_digest(db.connection)==before and route.path.read_bytes()==pending
        damaged=deepcopy(retained);damaged['migration'][field]['epoch']=True;route._publish(damaged);pending=route.path.read_bytes()
        with pytest.raises(CoordinationError):route.reconcile(actor='admin',now=109,approve=approve)
        assert _state_digest(db.connection)==before and route.path.read_bytes()==pending
        route._publish(retained);route.reconcile(actor='admin',now=109,approve=approve)
        assert_admin_recovered(db,route,operation)
    finally:db.close()


@pytest.mark.parametrize('operation',['enroll','freeze'])
@pytest.mark.parametrize('fault',['business-facts','future-floor'])
def test_committed_admin_recovery_rejects_sql_drift(tmp_path,monkeypatch,operation,fault):
    db,route,_,run=admin_case(tmp_path,operation)
    try:
        publish=pending_failure(route,monkeypatch,operation,'after-commit')
        with pytest.raises(OSError):run()
        monkeypatch.setattr(route,'_publish',publish)
        if fault=='business-facts':db.connection.execute('UPDATE budgets SET ceiling=ceiling+1')
        else:db.connection.execute('UPDATE metadata SET time_floor=106')
        before=route.path.read_bytes()
        with pytest.raises(CoordinationError):route.reconcile(actor='admin',now=109,approve=approve)
        assert route.path.read_bytes()==before
    finally:db.close()


@pytest.mark.parametrize('operation',['enroll','freeze','activate'])
@pytest.mark.parametrize('fault',['subject','sql'])
def test_initial_admin_approval_cannot_rewrite_original_subject_or_sql(tmp_path,operation,fault):
    db,route,_,run=admin_case(tmp_path,'enroll' if operation=='enroll' else 'freeze')
    try:
        if operation=='activate':run();route.stage(db)
        before=_state_digest(db.connection);route_before=route.path.read_bytes() if route.path.exists() else None
        def approval(c,o,a,e,s):
            if fault=='subject':s['actor']='forged'
            else:c.execute('UPDATE budgets SET ceiling=ceiling+1')
            return True
        with pytest.raises(CoordinationError,match='approval modified'):
            route.activate(actor='admin',now=109,approve=approval) if operation=='activate' else run(approval)
        assert _state_digest(db.connection)==before
        assert (route.path.read_bytes() if route.path.exists() else None)==route_before
    finally:db.close()


def test_ordinary_uncertain_sql_cannot_be_replayed_as_administrative_recovery(installed,monkeypatch):
    db,route,_=installed;before=_state_digest(db.connection);publish=route._publish
    def fail(record,**kw):
        publish(record,**kw);raise OSError('ordinary write watermark published before failed SQL commit')
    monkeypatch.setattr(route,'_publish',fail)
    with pytest.raises(OSError):db.create_budget('uncertain',1,actor='admin',now=104,authorize=current)
    monkeypatch.setattr(route,'_publish',publish)
    retained=route.path.read_bytes()
    with pytest.raises(CoordinationError):route.reconcile(actor='admin',now=109,approve=approve)
    with pytest.raises(CoordinationError):route.open_current()
    assert _state_digest(db.connection)==before and route.path.read_bytes()==retained


@pytest.mark.parametrize('operation',['enroll','freeze'])
def test_admin_failure_before_intent_retries_whole_original_operation(tmp_path,monkeypatch,operation):
    db,route,_,run=admin_case(tmp_path,operation)
    try:
        before=_state_digest(db.connection);route_before=route.path.read_bytes() if route.path.exists() else None
        publish=route._publish
        def fail(record,**kw):raise OSError('publication did not happen')
        monkeypatch.setattr(route,'_publish',fail)
        with pytest.raises(OSError):run()
        assert _state_digest(db.connection)==before
        assert (route.path.read_bytes() if route.path.exists() else None)==route_before
        monkeypatch.setattr(route,'_publish',publish)
        with pytest.raises(CoordinationError):route.reconcile(actor='admin',now=109,approve=approve)
        run();assert_admin_recovered(db,route,operation,reconciliation=False)
    finally:db.close()


@pytest.mark.parametrize('operation',['enroll','freeze'])
@pytest.mark.parametrize('boundary',['after-intent','after-commit'])
def test_real_reconciliation_process_exit_retains_original_and_monotone_time(tmp_path,monkeypatch,operation,boundary):
    db,route,_,run=admin_case(tmp_path,operation)
    try:
        publish=pending_failure(route,monkeypatch,operation,'after-intent')
        with pytest.raises(OSError):run()
        monkeypatch.setattr(route,'_publish',publish)
        code='''
import os,sys
from dasops.protected.sqlite import AuthorityRoute
route=AuthorityRoute(sys.argv[1],authority_domain='domain');publish=route._publish
pending='enrolling' if sys.argv[2]=='enroll' else 'freezing';final='active' if sys.argv[2]=='enroll' else 'frozen'
def crash(record,**kw):
 if record['phase']==pending and sys.argv[3]=='after-intent':publish(record,**kw);os._exit(71)
 if record['phase']==final and sys.argv[3]=='after-commit':os._exit(72)
 return publish(record,**kw)
route._publish=crash
route.reconcile(actor='recovery-admin',now=107,approve=lambda *args:True)
'''
        child=subprocess.run([sys.executable,'-B','-c',code,str(route.path),operation,boundary],
            capture_output=True,timeout=15,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1'))
        (tmp_path/'reconciliation-process.stdout').write_bytes(child.stdout)
        (tmp_path/'reconciliation-process.stderr').write_bytes(child.stderr)
        assert child.returncode==(71 if boundary=='after-intent' else 72),child.stderr.decode()
        with pytest.raises(CoordinationError,match='clock'):
            route.reconcile(actor='admin',now=106,approve=approve)
        route.reconcile(actor='admin',now=109,approve=approve)
        assert_admin_recovered(db,route,operation)
    finally:db.close()


APPROVAL_SQL_FAULTS = ('update-commit-deny','commit','rollback','rebegin','script',
                       'cursor','pragma','caught-write','replace-policy')


def bad_sql_approval(connection, fault):
    if fault=='update-commit-deny':
        connection.execute('UPDATE budgets SET ceiling=99');connection.commit();return False
    if fault=='commit':connection.commit()
    elif fault=='rollback':connection.rollback()
    elif fault=='rebegin':connection.commit();connection.execute('BEGIN IMMEDIATE')
    elif fault=='script':connection.executescript('UPDATE budgets SET ceiling=99;')
    elif fault=='cursor':connection.cursor().execute('UPDATE budgets SET ceiling=99')
    elif fault=='pragma':connection.execute('PRAGMA ignore_check_constraints=ON')
    elif fault=='caught-write':
        try:connection.execute('UPDATE budgets SET ceiling=99')
        except sqlite3.DatabaseError:pass
    elif fault=='replace-policy':connection.set_authorizer(None)
    return True


@pytest.mark.parametrize('operation',['enroll','freeze','activate','reconcile'])
@pytest.mark.parametrize('fault',APPROVAL_SQL_FAULTS)
def test_administrative_approval_cannot_escape_owning_transaction(tmp_path,monkeypatch,operation,fault):
    db,route,_,run=admin_case(tmp_path,'enroll' if operation in ('enroll','reconcile') else 'freeze')
    try:
        target=db.path
        if operation=='activate':run();target=Path(route.stage(db)['database'])
        if operation=='reconcile':
            publish=pending_failure(route,monkeypatch,'enroll','after-intent')
            with pytest.raises(OSError):run()
            monkeypatch.setattr(route,'_publish',publish)
        def readback():
            with sqlite3.connect(target) as c:return _state_digest(c)
        before=readback();route_before=route.path.read_bytes() if route.path.exists() else None
        approval=lambda c,*args:bad_sql_approval(c,fault)
        with pytest.raises(CoordinationError,match='approval modified'):
            if operation=='activate':route.activate(actor='admin',now=109,approve=approval)
            elif operation=='reconcile':route.reconcile(actor='admin',now=109,approve=approval)
            else:run(approval)
        assert readback()==before
        assert (route.path.read_bytes() if route.path.exists() else None)==route_before
        # A refused callback must not leave a policy that prevents legal recovery.
        if operation=='activate':route.activate(actor='admin',now=109,approve=approve)
        elif operation=='reconcile':route.reconcile(actor='admin',now=109,approve=approve)
        else:run()
    finally:db.close()


@pytest.mark.parametrize('fault',APPROVAL_SQL_FAULTS)
def test_business_approval_sql_guard_restores_prior_policy_and_cached_statements(installed,fault):
    db,_,_=installed;events=[]
    def policy(*args):events.append(args[0]);return sqlite3.SQLITE_OK
    db.connection.set_authorizer(policy)
    # Previously compiled statements must be re-authorized during approval.
    db.connection.execute('UPDATE budgets SET ceiling=99')
    db.connection.execute('UPDATE budgets SET ceiling=20')
    before=_state_digest(db.connection)
    with pytest.raises(CoordinationError,match='approval modified'):
        db.create_budget('forbidden',1,actor='admin',now=104,
            authorize=lambda c,*args:bad_sql_approval(c,fault))
    with sqlite3.connect(db.path) as c:assert _state_digest(c)==before
    events.clear()
    def legal(c,*args):
        assert c.execute('SELECT ceiling FROM budgets').fetchone()[0]==20
        assert c.execute('PRAGMA foreign_keys').fetchone()[0]==1
        return True
    db.create_budget('legal',1,actor='admin',now=104,authorize=legal)
    assert sqlite3.SQLITE_UPDATE in events and sqlite3.SQLITE_INSERT in events
    assert db.connection._authorizer is policy and db.connection._approval_guard is None


@pytest.mark.parametrize('fault',['budget','lease','future-floor','missing-result'])
def test_committed_activation_recovery_rejects_complete_state_drift(installed,monkeypatch,fault):
    db,route,key=installed
    reserve(db,key);db.claim(key,D1,actor='worker',expires_at=200,now=104,authorize=current)
    freeze(db,route);target=Path(route.stage(db)['database']);publish=route._publish
    def fail(record,**kw):
        if record['phase']=='active':raise OSError('after activation COMMIT')
        return publish(record,**kw)
    monkeypatch.setattr(route,'_publish',fail)
    with pytest.raises(OSError):route.activate(actor='admin',now=107,approve=approve)
    monkeypatch.setattr(route,'_publish',publish)
    if fault=='missing-result':
        record=route._read();record['migration'].pop('activationResultDigest');publish(record)
    else:
        with sqlite3.connect(target) as c:
            c.execute({'budget':'UPDATE budgets SET ceiling=99',
                'lease':'UPDATE leases SET expires_at=200','future-floor':'UPDATE metadata SET time_floor=108'}[fault])
    before=route.path.read_bytes()
    with pytest.raises(CoordinationError):route.activate(actor='admin',now=109,approve=approve)
    assert route.path.read_bytes()==before
    with pytest.raises(CoordinationError):route.open_current()
    with pytest.raises(CoordinationError):db.create_budget('old',1,actor='admin',now=110,authorize=current)


@pytest.mark.parametrize('boundary',['after-intent','after-commit'])
def test_repeated_activation_recovery_retains_exact_result_and_original_lease_time(installed,monkeypatch,boundary):
    db,route,key=installed
    reserve(db,key);db.claim(key,D1,actor='worker',expires_at=200,now=104,authorize=current)
    freeze(db,route);route.stage(db);publish=route._publish
    def fail(record,**kw):
        if record['phase']=='activating' and boundary=='after-intent':
            publish(record,**kw);raise OSError('before activation COMMIT')
        if record['phase']=='active' and boundary=='after-commit':raise OSError('after activation COMMIT')
        return publish(record,**kw)
    monkeypatch.setattr(route,'_publish',fail)
    for now in (107,109):
        with pytest.raises(OSError):route.activate(actor='admin',now=now,approve=approve)
    original_result=route._read()['migration']['activationResultDigest']
    monkeypatch.setattr(route,'_publish',publish)
    route.activate(actor='admin',now=111,approve=approve)
    new=route.open_current()
    try:
        assert _state_digest(new.connection,time_floor=107)==original_result
        assert new.connection.execute('SELECT expires_at FROM leases').fetchone()[0]==107
        assert new.connection.execute('SELECT time_floor FROM metadata').fetchone()[0]==111
        assert new.connection.execute("SELECT COUNT(*) FROM audit WHERE event='authority_activated'").fetchone()[0]==1
    finally:new.close()
