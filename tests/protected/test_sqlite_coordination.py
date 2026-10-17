"""Real staging DB invariants; no protected deployment or power-loss claim."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import json
import hashlib
import sqlite3
import threading

import pytest

from dasops.protected.sqlite.store import CoordinationDatabase, CoordinationError, TaskKey, admit_wal, RuntimeApproval

D1='sha256:'+'1'*64
D2='sha256:'+'2'*64
D3='sha256:'+'3'*64


def authorized(connection, operation, actor, epoch):
    assert connection.in_transaction
    return actor in ('admin','worker','successor') and epoch==1


@pytest.fixture
def database(tmp_path):
    directory=tmp_path/'authority';directory.mkdir(mode=0o700)
    db=CoordinationDatabase.create(directory/'authority.db',authority_domain='domain',instance_id='instance')
    db.create_change('project','change',actor='admin',now=100,authorize=authorized)
    key=TaskKey('domain','project','change','T-1')
    db.add_task(key,D1,actor='admin',now=100,authorize=authorized)
    db.create_budget('shared',10,actor='admin',now=100,authorize=authorized)
    db.create_budget('child',10,actor='admin',now=100,authorize=authorized)
    yield db,key
    db.close()


def reserve(db,key,business='business',cost=5,actor='worker',digest=D2,original='worker'):
    return db.reserve(key,resource_id='resource',action_class='integrate',business_id=business,
        original_actor=original,request_digest=digest,budget_ids=['shared','child'],cost=cost,cycle=1,
        actor=actor,now=101,authorize=authorized)


def confirmed(db,key,business='business'):
    reserve(db,key,business)
    db.transition_action('resource','integrate',business,expected='reserved',target='dispatched',actor='worker',now=101,authorize=authorized)
    db.transition_action('resource','integrate',business,expected='dispatched',target='confirmed',receipt_digest=D3,actor='worker',now=101,authorize=authorized)


def completion(db,key,**overrides):
    values=dict(cycle=1,revision=1,resource_id='resource',action_class='integrate',business_id='business',receipt_digest=D3,evidence_digest=D2,actor='worker',now=101,authorize=authorized)
    values.update(overrides)
    return db.record_completion(key,**values)


@pytest.mark.parametrize('action',['integrate','apply','rollback','submit','complete','renamed-mutation'])
def test_completed_cycle_cannot_reserve_another_business_action_without_rework(database,action):
    db,key=database; confirmed(db,key); original=completion(db,key)
    checkpoint=db.checkpoint()
    with pytest.raises(CoordinationError,match='completed'):
        db.reserve(key,resource_id='resource',action_class=action,business_id='another-action',
            original_actor='worker',request_digest=D2,budget_ids=['shared','child'],cost=1,cycle=1,
            actor='worker',now=102,authorize=authorized)
    assert db.checkpoint()==checkpoint
    assert db.connection.execute('SELECT COUNT(*) FROM business_actions').fetchone()[0]==1
    assert completion(db,key)==original
    # Original exact replay is history; it creates no new reservation.
    assert reserve(db,key)['state']=='confirmed' and db.checkpoint()==checkpoint
    # Explicit rework permits the new cycle, preserving the old fact and cost.
    db.rework(key,expected_cycle=1,actor='worker',now=102,authorize=authorized)
    db.reserve(key,resource_id='resource',action_class=action,business_id='new-cycle',
        original_actor='worker',request_digest=D2,budget_ids=['shared','child'],cost=1,cycle=2,
        actor='worker',now=103,authorize=authorized)
    assert db.connection.execute('SELECT cycle FROM completions').fetchone()[0]==1
    assert {row[0] for row in db.connection.execute('SELECT reserved FROM budgets')}=={6}
    db.check_integrity()


def test_completed_cycle_cannot_claim_new_worker_lease(database):
    db,key=database; confirmed(db,key); completion(db,key); checkpoint=db.checkpoint()
    with pytest.raises(CoordinationError,match='completed'):
        db.claim(key,D2,actor='worker',expires_at=200,now=102,authorize=authorized)
    assert db.checkpoint()==checkpoint and not db.connection.execute('SELECT * FROM leases').fetchall()


def test_completed_cycle_cannot_renew_old_worker_lease(database):
    db,key=database
    generation=db.claim(key,D2,actor='worker',expires_at=200,now=100,authorize=authorized)
    confirmed(db,key); completion(db,key); checkpoint=db.checkpoint()
    with pytest.raises(CoordinationError,match='completed'):
        db.renew(key,D2,generation,actor='worker',expires_at=250,now=102,authorize=authorized)
    assert db.checkpoint()==checkpoint
    assert db.connection.execute('SELECT expires_at FROM leases').fetchone()[0]==200


@pytest.mark.parametrize('action',['inspect','audit'])
def test_completed_cycle_retains_currently_authorized_read_actions(database,action):
    db,key=database; confirmed(db,key); original=completion(db,key)
    db.reserve(key,resource_id='resource',action_class=action,business_id='read-history',
        original_actor='successor',request_digest=D2,budget_ids=['shared','child'],cost=1,cycle=1,
        actor='successor',now=102,authorize=authorized)
    db.transition_action('resource',action,'read-history',expected='reserved',target='dispatched',
        actor='successor',now=102,authorize=authorized)
    checkpoint=db.checkpoint()
    with pytest.raises(CoordinationError):
        db.reserve(key,resource_id='resource',action_class=action,business_id='unauthorized-read',
            original_actor='successor',request_digest=D2,budget_ids=['shared','child'],cost=1,cycle=1,
            actor='successor',now=102,authorize=lambda *args:False)
    assert db.checkpoint()==checkpoint
    assert completion(db,key,now=102)==original
    assert {row[0] for row in db.connection.execute('SELECT reserved FROM budgets')}=={6}
    db.check_integrity()


def test_connections_enforce_actual_constraints_and_transaction_rollback(database):
    db,key=database
    other=CoordinationDatabase(db.path,authority_domain='domain')
    try:
        for connection in (db.connection,other.connection):
            assert connection.isolation_level is None
            assert connection.execute('PRAGMA foreign_keys').fetchone()[0]==1
            assert connection.execute('PRAGMA synchronous').fetchone()[0]==2
        checkpoint=db.checkpoint()
        with pytest.raises(sqlite3.IntegrityError):
            with other.transaction('fixture','worker',101,authorized) as connection:
                connection.execute('UPDATE budgets SET reserved=1 WHERE budget_id=\'shared\'')
                connection.execute('INSERT INTO tasks VALUES (?,?,?,?,?,1,1)',('domain','project','absent','bad',D1))
        assert db.connection.execute('SELECT reserved FROM budgets WHERE budget_id=\'shared\'').fetchone()[0]==0
        assert db.checkpoint()==checkpoint
        assert not other.connection.in_transaction
    finally: other.close()


@pytest.mark.parametrize('bad',[None,'',True,1.1])
def test_identity_and_exact_number_domain_reject(database,bad):
    db,key=database
    with pytest.raises((CoordinationError,UnicodeError)):
        db.create_budget(bad,10,actor='admin',now=100,authorize=authorized)
    with pytest.raises(CoordinationError):
        db.create_budget('bad',bad,actor='admin',now=100,authorize=authorized)


def test_current_authorization_is_inside_real_begin_before_any_state_change(database):
    db,key=database
    checkpoint=db.checkpoint()
    calls=[]
    def deny(connection,operation,actor,epoch):
        calls.append((connection.in_transaction,operation,actor,epoch));return False
    with pytest.raises(CoordinationError,match='authorization'):
        db.create_budget('unauthorized',3,actor='self-reported-admin',now=101,authorize=deny)
    assert calls==[(True,'create_budget','self-reported-admin',1)]
    assert db.checkpoint()==checkpoint
    assert not db.connection.in_transaction
    with pytest.raises(CoordinationError,match='backwards'):
        db.create_budget('rollback',3,actor='admin',now=99,authorize=authorized)


def test_stable_key_survives_handoff_and_changed_parameters_are_rejected(database):
    db,key=database
    original=reserve(db,key)
    duplicate=reserve(db,key,actor='successor')
    assert original==duplicate and duplicate['original_actor']=='worker'
    assert db.connection.execute("SELECT reserved FROM budgets WHERE budget_id='shared'").fetchone()[0]==5
    for values in [dict(digest=D1),dict(cost=6),dict(original='successor',actor='successor')]:
        with pytest.raises(CoordinationError,match='immutable request'): reserve(db,key,**values)
    db.transition_action('resource','integrate','business',expected='reserved',target='dispatched',actor='worker',now=101,authorize=authorized)
    db.transition_action('resource','integrate','business',expected='dispatched',target='unknown',actor='worker',now=101,authorize=authorized)
    assert reserve(db,key,actor='successor')['state']=='unknown'
    with pytest.raises(CoordinationError,match='unsupported'): db.transition_action('resource','integrate','business',expected='unknown',target='dispatched',actor='successor',now=101,authorize=authorized)
    assert db.connection.execute("SELECT reserved FROM budgets WHERE budget_id='shared'").fetchone()[0]==5


def test_failed_second_ancestor_budget_rolls_back_entire_action(database):
    db,key=database
    db.connection.execute("UPDATE budgets SET ceiling=2 WHERE budget_id='shared'")
    checkpoint=db.checkpoint()
    with pytest.raises(CoordinationError,match='exceeded'): reserve(db,key)
    assert not db.connection.execute('SELECT * FROM business_actions').fetchall()
    assert not db.connection.execute('SELECT * FROM reservations').fetchall()
    assert [row[0] for row in db.connection.execute('SELECT reserved FROM budgets')]==[0,0]
    assert db.checkpoint()==checkpoint


def test_two_actual_writer_connections_cannot_overspend_shared_budget(database):
    db,key=database
    barrier=threading.Barrier(2)
    def contender(business):
        connection=CoordinationDatabase(db.path,authority_domain='domain',busy_ms=2000)
        try:
            barrier.wait(timeout=5)
            try:reserve(connection,key,business,cost=6);return 'reserved'
            except CoordinationError:return 'denied'
        finally:connection.close()
    with ThreadPoolExecutor(2) as pool:
        first=pool.submit(contender,'one');second=pool.submit(contender,'two')
        results=[first.result(timeout=10),second.result(timeout=10)]
    assert sorted(results)==['denied','reserved']
    assert db.connection.execute("SELECT reserved FROM budgets WHERE budget_id='shared'").fetchone()[0]==6
    assert len(db.connection.execute('SELECT * FROM business_actions').fetchall())==1
    db.check_integrity()


def test_renew_and_reclaim_actual_generation_prevents_old_owner(database):
    db,key=database
    assert db.claim(key,D1,actor='worker',expires_at=110,now=101,authorize=authorized)==1
    other=CoordinationDatabase(db.path,authority_domain='domain')
    try:
        other.renew(key,D1,1,actor='worker',expires_at=112,now=105,authorize=authorized)
        with pytest.raises(CoordinationError,match='held'):
            db.claim(key,D2,actor='successor',expires_at=120,now=110,authorize=authorized)
        assert db.claim(key,D2,actor='successor',expires_at=120,now=112,authorize=authorized)==2
        with pytest.raises(CoordinationError,match='superseded'):
            other.renew(key,D1,1,actor='worker',expires_at=125,now=113,authorize=authorized)
    finally:other.close()


def test_completion_unique_receipt_binding_and_closing_set_are_atomic(database):
    db,key=database
    with pytest.raises(CoordinationError,match='confirmed'):completion(db,key)
    confirmed(db,key)
    first=completion(db,key)
    assert completion(db,key)==first
    with pytest.raises(CoordinationError,match='different immutable'):completion(db,key,evidence_digest=D1)
    generation=db.connection.execute('SELECT generation FROM changes').fetchone()[0]
    closing_generation,task_set=db.begin_closing('project','change',generation,actor='admin',now=102,authorize=authorized)
    with pytest.raises(CoordinationError,match='parent'):
        db.add_task(TaskKey('domain','project','change','new'),D1,actor='admin',now=102,authorize=authorized)
    with pytest.raises(CoordinationError,match='parent'):
        db.rework(key,expected_cycle=1,actor='admin',now=102,authorize=authorized)
    db.close_change('project','change',closing_generation,task_set,actor='admin',now=102,authorize=authorized)
    assert db.connection.execute('SELECT status FROM changes').fetchone()[0]=='closed'
    with pytest.raises(CoordinationError,match='parent'):
        db.claim(key,D2,actor='worker',expires_at=120,now=103,authorize=authorized)


def test_closing_rejects_missing_current_completion_and_unknown_side_effects(database):
    db,key=database
    confirmed(db,key);completion(db,key)
    second=TaskKey('domain','project','change','T-2');db.add_task(second,D1,actor='admin',now=101,authorize=authorized)
    generation=db.connection.execute('SELECT generation FROM changes').fetchone()[0]
    generation,digest=db.begin_closing('project','change',generation,actor='admin',now=101,authorize=authorized)
    with pytest.raises(CoordinationError,match='incomplete'):
        db.close_change('project','change',generation,digest,actor='admin',now=101,authorize=authorized)
    assert db.connection.execute('SELECT status FROM changes').fetchone()[0]=='closing'


def test_rework_retains_original_completion_and_increments_only_current_cycle(database):
    db,key=database
    confirmed(db,key);completion(db,key)
    assert db.rework(key,expected_cycle=1,actor='admin',now=102,authorize=authorized)==2
    assert len(db.connection.execute('SELECT * FROM completions').fetchall())==1
    assert db.connection.execute('SELECT cycle FROM tasks').fetchone()[0]==2
    with pytest.raises(CoordinationError,match='receipt does not bind'):
        completion(db,key,cycle=2,now=102)


def test_closing_withdrawal_rejects_stale_plan_and_preserves_completed_cycle(database):
    db,key=database;confirmed(db,key);original=completion(db,key)
    generation=db.connection.execute('SELECT generation FROM changes').fetchone()[0]
    closing,task_set=db.begin_closing('project','change',generation,actor='admin',now=102,authorize=authorized)
    assert db.withdraw_closing('project','change',closing,actor='admin',now=102,authorize=authorized)==closing+1
    assert db.connection.execute('SELECT task_set_digest FROM changes').fetchone()[0] is None
    with pytest.raises(CoordinationError,match='parent'):
        db.close_change('project','change',closing,task_set,actor='admin',now=102,authorize=authorized)
    assert completion(db,key,now=102)==original
    assert db.rework(key,expected_cycle=1,actor='admin',now=102,authorize=authorized)==2
    assert db.connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0]==1
    assert db.connection.execute('SELECT COUNT(*) FROM audit WHERE event=\'closing_withdrawn\'').fetchone()[0]==1
    db.check_integrity()


@pytest.mark.parametrize('status,successor',[('closed',None),('active',None),('cancelled','next'),('superseded',None),('superseded','change'),('superseded','occupied')])
def test_invalid_parent_termination_retains_the_whole_authority(database,status,successor):
    db,key=database
    db.create_change('project','occupied',actor='admin',now=100,authorize=authorized)
    generation=db.connection.execute("SELECT generation FROM changes WHERE change_id='change'").fetchone()[0]
    checkpoint=db.checkpoint();dump='\n'.join(db.connection.iterdump())
    with pytest.raises((CoordinationError,sqlite3.IntegrityError)):
        db.terminate_change('project','change',generation,status=status,successor=successor,
            actor='admin',now=101,authorize=authorized)
    assert db.checkpoint()==checkpoint and '\n'.join(db.connection.iterdump())==dump


@pytest.mark.parametrize('terminal',['cancelled','superseded'])
def test_cancelled_or_superseded_parent_is_not_an_administrative_misclosure(database,terminal):
    db,key=database
    generation=db.connection.execute('SELECT generation FROM changes').fetchone()[0]
    db.terminate_change('project','change',generation,status=terminal,
        successor='next' if terminal=='superseded' else None,actor='admin',now=101,authorize=authorized)
    checkpoint=db.checkpoint()
    with pytest.raises(CoordinationError,match='parent'):
        db.rescind_closure('project','change',generation+1,actor='successor',now=102,
            authorize=authorized,impact_evidence_digest=D1,verify_no_impact=lambda *args:True)
    with pytest.raises(CoordinationError,match='parent'):
        db.withdraw_closing('project','change',generation+1,actor='admin',now=102,authorize=authorized)
    assert db.checkpoint()==checkpoint


def test_new_change_lineage_requires_an_existing_terminal_predecessor(database):
    db,key=database;checkpoint=db.checkpoint()
    for predecessor in ('absent','change'):
        with pytest.raises(CoordinationError,match='parent'):
            db.create_change('project','next',predecessor=predecessor,actor='admin',now=101,authorize=authorized)
        assert db.checkpoint()==checkpoint


@pytest.mark.parametrize('impact',['deployed','migrated','dependency','consumed','unknown','none'])
def test_administrative_rescission_requires_independent_exact_no_impact_review(database,tmp_path,impact):
    db,key=database;confirmed(db,key);original=completion(db,key)
    generation=db.connection.execute('SELECT generation FROM changes').fetchone()[0]
    closing,task_set=db.begin_closing('project','change',generation,actor='admin',now=102,authorize=authorized)
    db.close_change('project','change',closing,task_set,actor='admin',now=102,authorize=authorized)
    closed=closing+1;checkpoint=db.checkpoint()
    # Separately controlled TEST impact ledger, bound to the actual closure.
    # It exercises the installed predicate boundary, not production fact approval.
    facts=tmp_path/'independent-impacts.db'
    with sqlite3.connect(facts) as witness:
        witness.execute('CREATE TABLE review (closure TEXT PRIMARY KEY, deployed, migrated, dependency, consumed)')
        values=[0,0,0,0]
        if impact=='unknown':values[0]=None
        elif impact!='none':values[['deployed','migrated','dependency','consumed'].index(impact)]=1
        witness.execute('INSERT INTO review VALUES (?,?,?,?,?)',(checkpoint['digest'],*values))
    evidence="sha256:"+hashlib.sha256(facts.read_bytes()).hexdigest()
    observations=[]
    def reviewed(connection,closure,impact_digest):
        assert impact_digest==evidence=="sha256:"+hashlib.sha256(facts.read_bytes()).hexdigest()
        assert connection.in_transaction and closure['digest']==checkpoint['digest']
        witness=sqlite3.connect(facts.as_uri()+'?mode=ro',uri=True)
        try:row=witness.execute('SELECT deployed,migrated,dependency,consumed FROM review WHERE closure=?',(closure['digest'],)).fetchone()
        finally:witness.close()
        observations.append(row)
        return row is not None and all(value==0 for value in row)
    # The closer cannot approve its own administrative reversal.
    with pytest.raises(CoordinationError,match='independent'):
        db.rescind_closure('project','change',closed,actor='admin',now=103,authorize=authorized,impact_evidence_digest=evidence,verify_no_impact=reviewed)
    assert not observations and db.checkpoint()==checkpoint
    options=dict(actor='successor',now=103,authorize=authorized,impact_evidence_digest=evidence,verify_no_impact=reviewed)
    if impact=='none':
        assert db.rescind_closure('project','change',closed,**options)==closed+1
        row=db.connection.execute('SELECT status,generation FROM changes').fetchone()
        assert tuple(row)==('active',closed+1)
        event=db.connection.execute("SELECT body FROM audit WHERE event='closureRescinded'").fetchone()[0]
        assert json.loads(event)['closureDigest']==checkpoint['digest']
        assert json.loads(event)['impactEvidenceDigest']==evidence
        # Only administrative status changed; no second Task Completion or cycle.
        assert completion(db,key,now=103)==original
        with pytest.raises(CoordinationError,match='completed'):
            db.claim(key,D2,actor='worker',expires_at=200,now=103,authorize=authorized)
    else:
        with pytest.raises(CoordinationError,match='impact'):
            db.rescind_closure('project','change',closed,**options)
        assert db.checkpoint()==checkpoint
        assert tuple(db.connection.execute('SELECT status,generation FROM changes').fetchone())==('closed',closed)
        db.create_change('project','next',predecessor='change',actor='admin',now=103,authorize=authorized)
    assert observations and db.connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0]==1
    assert db.connection.execute('SELECT cycle FROM tasks').fetchone()[0]==1
    assert db.connection.execute("SELECT COUNT(*) FROM audit WHERE event='change_closed'").fetchone()[0]==1
    db.check_integrity()


@pytest.mark.parametrize('fault',['mutate-review','commit-review','wrong-generation','denied','not-closed'])
def test_rescission_review_cannot_change_history_or_bypass_the_current_transaction(database,fault):
    db,key=database;confirmed(db,key);completion(db,key)
    generation=db.connection.execute('SELECT generation FROM changes').fetchone()[0]
    closing,task_set=db.begin_closing('project','change',generation,actor='admin',now=102,authorize=authorized)
    if fault!='not-closed':db.close_change('project','change',closing,task_set,actor='admin',now=102,authorize=authorized)
    checkpoint=db.checkpoint();dump='\n'.join(db.connection.iterdump())
    def review(connection,closure,impact_digest):
        if fault=='commit-review':connection.execute('COMMIT')
        if fault=='mutate-review':closure['body']['generation']=999
        return True
    with pytest.raises((CoordinationError,sqlite3.DatabaseError)):
        db.rescind_closure('project','change',closing+1+(fault=='wrong-generation'),actor='successor',now=103,
            authorize=(lambda *args:False) if fault=='denied' else authorized,impact_evidence_digest=D1,verify_no_impact=review)
    assert db.checkpoint()==checkpoint and '\n'.join(db.connection.iterdump())==dump


@pytest.mark.parametrize('leading',['complete','close'])
def test_last_completion_and_parent_close_read_one_serial_current_set(database,leading):
    db,key=database;confirmed(db,key)
    generation=db.connection.execute('SELECT generation FROM changes').fetchone()[0]
    closing,task_set=db.begin_closing('project','change',generation,actor='admin',now=101,authorize=authorized)
    entered=threading.Event();attempted=threading.Event();release=threading.Event();traces={}
    def contender(kind,held):
        writer=CoordinationDatabase(db.path,authority_domain='domain',busy_ms=2000);trace=[]
        def tracing(statement):
            trace.append(statement)
            if not held and statement.startswith('BEGIN IMMEDIATE'):attempted.set()
        writer.connection.set_trace_callback(tracing)
        def current(c,o,a,e):
            if held:entered.set();assert release.wait(timeout=5)
            return authorized(c,o,a,e)
        try:
            if kind=='complete':completion(writer,key,authorize=current);return 'completed'
            try:
                writer.close_change('project','change',closing,task_set,actor='admin',now=101,authorize=current)
                return 'closed'
            except CoordinationError as exc:assert 'incomplete' in str(exc);return 'incomplete'
        finally:traces[kind]=trace;writer.close()
    trailing='close' if leading=='complete' else 'complete'
    with ThreadPoolExecutor(2) as pool:
        first=pool.submit(contender,leading,True);assert entered.wait(timeout=5)
        second=pool.submit(contender,trailing,False);assert attempted.wait(timeout=5);release.set()
        results={leading:first.result(timeout=10),trailing:second.result(timeout=10)}
    assert results['complete']=='completed'
    assert results['close']==('closed' if leading=='complete' else 'incomplete')
    if leading=='close':db.close_change('project','change',closing,task_set,actor='admin',now=101,authorize=authorized)
    assert db.connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0]==1
    assert db.connection.execute('SELECT status FROM changes').fetchone()[0]=='closed'
    assert 'ROLLBACK' in traces['close'] if leading=='close' else 'COMMIT' in traces['close']
    for trace in traces.values():assert 'BEGIN IMMEDIATE' in trace
    with pytest.raises(CoordinationError,match='parent'):
        db.withdraw_closing('project','change',closing+1,actor='admin',now=102,authorize=authorized)
    db.check_integrity()


def test_consistent_backup_and_independent_watermark_reject_stale_restore(database):
    db,key=database
    old=db.checkpoint();output=db.path.parent/'backup.db'
    receipt=db.backup(output,minimum_checkpoint=old)
    confirmed(db,key)
    new=db.checkpoint()
    restored=CoordinationDatabase(output,authority_domain='domain')
    try:
        assert restored.checkpoint()==receipt['checkpoint']==old
        restored.verify_checkpoint(old)
        with pytest.raises(CoordinationError,match='older'):restored.verify_checkpoint(new)
        db.verify_checkpoint(new)
    finally:restored.close()
    with pytest.raises(FileExistsError):db.backup(output,minimum_checkpoint=new)


@pytest.mark.parametrize('mode',['read','write','attached','temp'])
def test_backup_rejects_uncopied_or_unfinished_source_domain_before_creating_output(database,mode):
    db,key=database
    witness=db.checkpoint();output=db.path.parent/'unsupported.db'
    if mode=='read':
        db.connection.execute('BEGIN');db.connection.execute('SELECT * FROM tasks').fetchall()
    elif mode=='write':
        db.connection.execute('BEGIN IMMEDIATE')
        db.connection.execute("UPDATE budgets SET ceiling=11 WHERE budget_id='shared'")
    elif mode=='attached':db.connection.execute("ATTACH DATABASE ':memory:' AS uncopied")
    else:db.connection.execute('CREATE TEMP TABLE shadow (value TEXT)')
    try:
        with pytest.raises(CoordinationError,match='transaction|TEMP'):
            db.backup(output,minimum_checkpoint=witness)
        assert not output.exists() and db.checkpoint()==witness
    finally:
        if mode in ('read','write'):db.connection.rollback()
        elif mode=='attached':db.connection.execute('DETACH DATABASE uncopied')
        else:db.connection.execute('DROP TABLE temp.shadow')
    assert db.connection.execute("SELECT ceiling FROM budgets WHERE budget_id='shared'").fetchone()[0]==10
    db.check_integrity()


def test_backup_restore_retains_unknown_outbox_budget_and_unique_completion(database):
    db,key=database
    confirmed(db,key);original=completion(db,key)
    pending=TaskKey('domain','project','change','T-pending')
    db.add_task(pending,D1,actor='admin',now=101,authorize=authorized)
    reserve(db,pending,business='unknown',cost=2)
    db.transition_action('resource','integrate','unknown',expected='reserved',target='dispatched',
        actor='worker',now=101,authorize=authorized)
    db.transition_action('resource','integrate','unknown',expected='dispatched',target='unknown',
        actor='worker',now=101,authorize=authorized)
    witness=db.checkpoint();output=db.path.parent/'recoverable.db'
    receipt=db.backup(output,minimum_checkpoint=witness)
    import hashlib
    assert receipt['sha256']==hashlib.sha256(output.read_bytes()).hexdigest()
    assert receipt['checkpoint']==witness and output.stat().st_mode & 0o777 == 0o600
    restored=CoordinationDatabase(output,authority_domain='domain')
    try:
        restored.verify_checkpoint(witness);restored.check_integrity()
        assert completion(restored,key)==original
        assert reserve(restored,pending,business='unknown',cost=2)['state']=='unknown'
        assert restored.checkpoint()==witness
        assert {r[0] for r in restored.connection.execute('SELECT reserved FROM budgets')}=={7}
        assert restored.connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0]==1
        with pytest.raises(CoordinationError,match='unsupported'):
            restored.transition_action('resource','integrate','unknown',expected='unknown',target='dispatched',
                actor='successor',now=102,authorize=authorized)
        with pytest.raises(CoordinationError,match='immutable request'):
            reserve(restored,pending,business='unknown',cost=1)
        assert restored.checkpoint()==witness
        restored.check_integrity()
    finally:restored.close()
    assert db.checkpoint()==witness


def test_actual_runtime_admission_rejects_missing_proof_and_artifact_changes(database):
    db,key=database
    assert db.runtime['sqliteVersion']==sqlite3.sqlite_version
    assert db.runtime['sqliteSourceId']
    assert db.runtime['loadedLibrarySha256']
    with pytest.raises(CoordinationError,match='approved exact runtime'):admit_wal(db.runtime,None)
    approval=RuntimeApproval(db.runtime['sqliteVersion'],db.runtime['sqliteSourceId'],db.runtime['driverSha256'],
                            db.runtime['compileOptionsDigest'],tuple(db.runtime['loadedLibrarySha256']),D1,D2)
    # This tests exact binding, not acceptance of this host's unpatched runtime.
    admit_wal(db.runtime,approval)
    for field in ['sqliteVersion','sqliteSourceId','driverSha256','compileOptionsDigest','loadedLibrarySha256']:
        bad=dict(db.runtime);bad[field]=[] if field=='loadedLibrarySha256' else 'tampered'
        with pytest.raises(CoordinationError,match='differs'):admit_wal(bad,approval)
    with pytest.raises(CoordinationError):CoordinationDatabase(db.path,authority_domain='domain',journal='WAL')


def test_changed_constraints_and_writer_pragmas_cannot_be_silently_accepted(database):
    db,key=database
    db.connection.execute('PRAGMA foreign_keys=OFF')
    with pytest.raises(CoordinationError,match='policy changed'):
        db.create_budget('bypass',5,actor='admin',now=101,authorize=authorized)
    db.connection.execute('PRAGMA foreign_keys=ON')
    db.connection.execute('DROP TRIGGER preserve_audit')
    with pytest.raises(CoordinationError,match='schema/constraint'):
        CoordinationDatabase(db.path,authority_domain='domain')


@pytest.mark.parametrize('journal',['OFF','MEMORY','PERSIST','TRUNCATE'])
def test_changed_journal_policy_cannot_bypass_runtime_admission(database,journal):
    db,key=database;checkpoint=db.checkpoint()
    assert db.connection.execute('PRAGMA journal_mode='+journal).fetchone()[0].upper()==journal
    with pytest.raises(CoordinationError,match='journal policy changed'):reserve(db,key)
    with pytest.raises(CoordinationError,match='journal policy changed'):db.check_integrity()
    assert db.checkpoint()==checkpoint
    assert db.connection.execute('SELECT COUNT(*) FROM business_actions').fetchone()[0]==0
    assert {r[0] for r in db.connection.execute('SELECT reserved FROM budgets')}=={0}
    # Only this installed test resets its own connection. The writer never
    # silently converts an active database to hide drift or claim WAL approval.
    assert db.connection.execute('PRAGMA journal_mode=DELETE').fetchone()[0]=='delete'
    reserve(db,key);db.check_integrity()


def test_null_keys_and_replace_do_not_destroy_retained_history(database):
    db,key=database
    confirmed(db,key);completion(db,key)
    checkpoint=db.checkpoint()
    for query,params in [
        ('INSERT INTO tasks VALUES (?,?,?,?,?,1,1)',('domain','project','change',None,D1)),
        ('INSERT OR REPLACE INTO tasks VALUES (?,?,?,?,?,1,1)',(*key.values(),D2)),
        ('DELETE FROM completions',()),('DELETE FROM audit',())]:
        with pytest.raises(sqlite3.IntegrityError):
            with db.transaction('fixture','admin',101,authorized) as connection:connection.execute(query,params)
    assert db.checkpoint()==checkpoint
    assert db.connection.execute('SELECT obligation_digest FROM tasks').fetchone()[0]==D1


def test_attached_or_shadowing_databases_are_not_an_authority_transaction_domain(database):
    db,key=database
    db.connection.execute("ATTACH DATABASE ':memory:' AS other")
    with pytest.raises(CoordinationError,match='transaction domain'):
        db.create_budget('attached',5,actor='admin',now=101,authorize=authorized)
    db.connection.execute('DETACH DATABASE other')
    db.connection.execute('CREATE TEMP TABLE budgets (budget_id TEXT)')
    with pytest.raises(CoordinationError,match='shadowing TEMP'):
        db.create_budget('shadow',5,actor='admin',now=101,authorize=authorized)
    db.connection.execute('DROP TABLE temp.budgets')
    db.check_integrity()


def test_confirmed_no_execution_continues_same_key_and_retained_reservation(database):
    db,key=database
    reserve(db,key)
    db.transition_action('resource','integrate','business',expected='reserved',target='dispatched',actor='worker',now=101,authorize=authorized)
    db.transition_action('resource','integrate','business',expected='dispatched',target='unknown',actor='worker',now=101,authorize=authorized)
    db.transition_action('resource','integrate','business',expected='unknown',target='not_executed',actor='successor',now=101,authorize=authorized)
    db.transition_action('resource','integrate','business',expected='not_executed',target='reserved',actor='successor',now=101,authorize=authorized)
    assert reserve(db,key,actor='successor')['state']=='reserved'
    assert db.connection.execute("SELECT reserved FROM budgets WHERE budget_id='shared'").fetchone()[0]==5


def test_two_real_connections_create_only_one_completion(database):
    db,key=database
    confirmed(db,key)
    barrier=threading.Barrier(2)
    def contender():
        writer=CoordinationDatabase(db.path,authority_domain='domain',busy_ms=2000)
        try:
            barrier.wait(timeout=5)
            return completion(writer,key)
        finally:writer.close()
    with ThreadPoolExecutor(2) as pool:
        a=pool.submit(contender);b=pool.submit(contender)
        assert a.result(timeout=10)==b.result(timeout=10)
    assert len(db.connection.execute('SELECT * FROM completions').fetchall())==1
    assert len(db.connection.execute("SELECT * FROM audit WHERE event='completion_recorded'").fetchall())==1


@pytest.mark.parametrize('cut', ['before_commit','after_commit'])
def test_real_process_exit_does_not_reset_committed_action_or_leave_partial_budget(database,cut):
    import os
    import subprocess
    import sys
    db,key=database
    script='''
import os,sys
from dasops.protected.sqlite.store import CoordinationDatabase,TaskKey
path,cut=sys.argv[1:]
db=CoordinationDatabase(path,authority_domain='domain')
authorized=lambda c,o,a,e: c.in_transaction and a=='worker' and e==1
if cut=='before_commit':
    with db.transaction('fixture','worker',101,authorized) as connection:
        connection.execute("UPDATE budgets SET reserved=5 WHERE budget_id='shared'")
        os._exit(17)
db.reserve(TaskKey('domain','project','change','T-1'),resource_id='resource',action_class='integrate',
 business_id='business',original_actor='worker',request_digest='sha256:'+'2'*64,
 budget_ids=['shared','child'],cost=5,cycle=1,actor='worker',now=101,authorize=authorized)
os._exit(17)
'''
    env=dict(os.environ,PYTHONPATH=str(Path(__file__).resolve().parents[2]),PYTHONDONTWRITEBYTECODE='1')
    result=subprocess.run([sys.executable,'-B','-c',script,str(db.path),cut],env=env,capture_output=True,timeout=10)
    assert result.returncode==17,result.stderr.decode()
    recovered=CoordinationDatabase(db.path,authority_domain='domain')
    try:
        value=recovered.connection.execute("SELECT reserved FROM budgets WHERE budget_id='shared'").fetchone()[0]
        assert value==(5 if cut=='after_commit' else 0)
        assert reserve(recovered,key)['fingerprint']
        assert recovered.connection.execute("SELECT reserved FROM budgets WHERE budget_id='shared'").fetchone()[0]==5
        assert len(recovered.connection.execute('SELECT * FROM business_actions').fetchall())==1
        recovered.check_integrity()
    finally:recovered.close()


def test_nonmaterial_revision_retains_original_completion_and_closes_current_task_set(database):
    db,key=database;confirmed(db,key);original=completion(db,key)
    def reviewed(c,context):
        assert c.in_transaction
        assert context['fromRevision']==1 and context['toRevision']==2
        assert context['evidenceDigest']==original['evidence_digest']
        return context['obligationDigest']==D1 and context['reviewDigest']==D3
    assert db.clarify_task(key,revision=1,cycle=1,obligation=D1,clarification_digest=D2,
        review_digest=D3,review=reviewed,actor='admin',now=102,authorize=authorized)==2
    with db.transaction('inspect','admin',102,authorized) as c:
        assert db.current_completion(c,key)==original
    assert db.connection.execute('SELECT revision,cycle,obligation_digest FROM tasks').fetchone()[:]==(2,1,D1)
    assert completion(db,key,now=102)==original
    assert db.connection.execute('SELECT reserved FROM budgets WHERE budget_id="shared"').fetchone()[0]==5
    generation=db.connection.execute('SELECT generation FROM changes').fetchone()[0]
    closing,task_set=db.begin_closing('project','change',generation,actor='admin',now=103,authorize=authorized)
    db.close_change('project','change',closing,task_set,actor='admin',now=104,authorize=authorized)
    assert db.connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0]==1


@pytest.mark.parametrize('fault',['material','stale','review-denied','review-mutated','commit','lease','pending','closing','cancelled'])
def test_task_clarification_refuses_unapproved_or_nonquiescent_definition(database,fault):
    db,key=database
    if fault=='lease':db.claim(key,D2,actor='worker',expires_at=110,now=100,authorize=authorized)
    if fault=='pending':reserve(db,key)
    if fault=='closing':db.begin_closing('project','change',2,actor='admin',now=101,authorize=authorized)
    if fault=='cancelled':db.terminate_change('project','change',2,status='cancelled',actor='admin',now=101,authorize=authorized)
    before=list(db.connection.iterdump())
    def review(c,context):
        if fault=='commit':c.execute('COMMIT')
        if fault=='review-mutated':context['toRevision']=7
        return fault!='review-denied'
    with pytest.raises(CoordinationError):
        db.clarify_task(key,revision=2 if fault=='stale' else 1,cycle=1,
            obligation=D2 if fault=='material' else D1,clarification_digest=D2,
            review_digest=D3,review=review,actor='admin',now=102,authorize=authorized)
    assert list(db.connection.iterdump())==before


def test_material_successor_has_new_identity_and_retains_original_obligation(database):
    db,key=database;confirmed(db,key);original=completion(db,key)
    successor=TaskKey('domain','project','change','replacement')
    db.add_task(successor,D2,predecessor=key,actor='admin',now=102,authorize=authorized)
    assert db.connection.execute('SELECT obligation_digest FROM tasks WHERE task_id=?',(key.task_id,)).fetchone()[0]==D1
    assert completion(db,key,now=102)==original
    event=json.loads(db.connection.execute("SELECT body FROM audit WHERE event='task_added' ORDER BY sequence DESC LIMIT 1").fetchone()[0])
    assert event['predecessor']['task_id']==key.task_id and event['predecessor']['obligation_digest']==D1
    with db.transaction('inspect','admin',102,authorized) as c:assert db.current_completion(c,successor) is None
    assert db.connection.execute('SELECT reserved FROM budgets WHERE budget_id="shared"').fetchone()[0]==5


def test_completion_revision_cannot_be_changed_without_explicit_binding(database):
    db,key=database;confirmed(db,key);completion(db,key)
    # Corruption probe, not an authorized revision operation.
    db.connection.execute('UPDATE tasks SET revision=2')
    generation,task_set=db.begin_closing('project','change',2,actor='admin',now=102,authorize=authorized)
    with pytest.raises(CoordinationError,match='explicit revision'):
        db.close_change('project','change',generation,task_set,actor='admin',now=103,authorize=authorized)
    assert db.connection.execute('SELECT status FROM changes').fetchone()[0]=='closing'


def test_analysis_revision_retains_original_mode_and_explicit_scope_binding(database):
    db,_=database;key=TaskKey('domain','project','change','analysis')
    binding=dict(contractIdentity='das-analysis-task-binding/v1',taskKey=dict(zip(
        ('authorityDomain','projectId','changeId','taskId'),key.values())),taskRevision=1,taskCycle=1,
        obligationDigest=D1,policyDigest=D2,completionMode='analysis',verificationScopeDigest=D3)
    db.add_task(key,D1,analysis_binding=binding,actor='admin',now=100,authorize=authorized)
    args=dict(revision=1,cycle=1,obligation=D1,clarification_digest=D2,review_digest=D3,
        review=lambda c,x:x['analysisBinding']['verificationScopeDigest']==D3,
        actor='successor',now=101,authorize=authorized)
    with pytest.raises(CoordinationError,match='explicit analysis'):
        db.clarify_task(key,**args)
    revised=dict(binding,taskRevision=2)
    assert db.clarify_task(key,analysis_binding=revised,**args)==2
    with db.read_snapshot() as c:
        assert db.analysis_task_binding(c,key)==revised
        assert db.analysis_task_binding(c,key,revision=1)==binding
    with pytest.raises(CoordinationError,match='approver'):
        db.claim(key,D2,actor='successor',expires_at=120,now=102,authorize=authorized)


@pytest.mark.parametrize('command',['COMMIT','ROLLBACK'])
def test_analysis_rework_secondary_approval_cannot_end_owner_transaction(database,command):
    db,_=database;key=TaskKey('domain','project','change','analysis')
    binding=dict(contractIdentity='das-analysis-task-binding/v1',taskKey=dict(zip(
        ('authorityDomain','projectId','changeId','taskId'),key.values())),taskRevision=1,taskCycle=1,
        obligationDigest=D1,policyDigest=D2,completionMode='analysis',verificationScopeDigest=D3)
    db.add_task(key,D1,analysis_binding=binding,actor='admin',now=100,authorize=authorized)
    # Kernel fixture: trusted consumer has recorded the completed analysis action.
    db.reserve(key,resource_id='analysis',action_class='complete',business_id='analysis',original_actor='worker',
        request_digest=D2,budget_ids=['shared'],cost=1,cycle=1,actor='worker',now=101,authorize=authorized)
    for before,after in [('reserved','dispatched'),('dispatched','confirmed')]:
        db.transition_action('analysis','complete','analysis',expected=before,target=after,
            receipt_digest=D3 if after=='confirmed' else None,actor='worker',now=101,authorize=authorized)
    db.record_completion(key,cycle=1,revision=1,resource_id='analysis',action_class='complete',business_id='analysis',
        receipt_digest=D3,evidence_digest=D2,actor='worker',now=101,authorize=authorized)
    before=list(db.connection.iterdump())
    def approval(c,operation,actor,epoch):
        if operation=='approve_analysis_rework':c.execute(command)
        return True
    with pytest.raises(CoordinationError,match='approval modified'):
        db.rework(key,expected_cycle=1,analysis_binding=dict(binding,taskCycle=2),actor='admin',now=102,authorize=approval)
    assert list(db.connection.iterdump())==before
