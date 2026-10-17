"""Actual SQL target integration/Completion; TEST policy, not deployment approval.

The installed qualification predicate is a bounded fixture here. These tests do
not prove the missing native Decision/evidence service or installed beta chain.
"""
import sqlite3
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import subprocess
import sys
import threading

import pytest

from dasops.protected.candidates import CandidateError, CandidateStore
from dasops.protected.candidates.versions import VersionTreeManager
from dasops.protected.sqlite.store import CoordinationDatabase, CoordinationError, TaskKey
from dasops.protected.sqlite.authority import AuthorityRoute
from dasops.protected.sqlite.outbox import DurableOutbox, Observation
from dasops.standards_contracts import exact_json as codec
from tests.protected.test_candidate_store import fixture, receive, sha, D
from tests.protected.test_version_trees import setup, authorized, OWNERS, DELETIONS, KEY, intent, durable_dispatch, target


INTEGRATE_REFS = dict(verificationPlanDigest='sha256:'+'3'*64,
                      verificationEvidenceDigest='sha256:'+'4'*64, decisionDigest='sha256:'+'5'*64)
COMPLETE_REFS = dict(INTEGRATE_REFS, decisionDigest='sha256:'+'6'*64)


@pytest.fixture
def chain(setup, tmp_path):
    db, store, _, before, _ = setup
    source_dir=tmp_path/'source'; source_dir.mkdir()
    source=receive(store, fixture(source_dir, content={'README.md':(b'original source C\n',False),
        'src/run.py':(b'print("legal")\n',False),'config.json':(b'{"fixed":true}\n',False)}))['candidateDigest']
    integrated=store.compose_integration(before,source,
        source_paths=['tree/README.md','tree/config.json','tree/src/run.py'],
        deleted_paths=['tree/tests/test_source.txt'],tool_digest=D)['candidateDigest']
    calls=[]; state={'allow':True}
    def qualify(connection, phase, actor, epoch, context):
        calls.append((phase, actor, epoch, context))
        expected = COMPLETE_REFS if phase=='complete' else INTEGRATE_REFS
        return (connection.in_transaction and state['allow'] and actor in ('worker','successor') and epoch==1
                and context['plan']['sourceCandidateDigest']==source
                and context['plan']['afterCandidateDigest']==integrated
                and context['qualificationRefs']==expected)
    kernel=VersionTreeManager(db,store,ownership=OWNERS,tool_digest=D,policy_digest=D,
                              check_qualification=qualify)
    kernel.register_candidate(source,actor='worker',now=100,authorize=authorized)
    kernel.register_candidate(integrated,actor='worker',now=100,authorize=authorized)
    yield db, store, kernel, before, integrated, source, calls, state


def integration_plan(chain, refs=None):
    return chain[2].create_integration_plan('target','instance',1,chain[5],chain[4],
        qualification_refs=INTEGRATE_REFS if refs is None else refs, deletion_reasons=DELETIONS,
        actor='worker',now=101,authorize=authorized)


def integrate(chain):
    digest, plan=integration_plan(chain); request=intent(digest,plan,action='integrate')
    durable_dispatch(chain[0],request)
    raw=chain[2].switch(request,actor='worker',now=101,authorize=authorized)
    chain[0].transition_action('target','integrate','forward',expected='dispatched',target='confirmed',
        receipt_digest=sha(raw),receipt_bytes=raw,actor='worker',now=101,authorize=authorized)
    return request,raw


def complete(chain, refs=None):
    return chain[2].complete_integration(KEY,cycle=1,revision=1,resource='target',instance='instance',
        business='forward',qualification_refs=COMPLETE_REFS if refs is None else refs,
        actor='successor',now=102,authorize=authorized)


def test_completed_cycle_cannot_plan_another_target_change(chain):
    integrate(chain);original=complete(chain);db,_,kernel,before,integrated,*_=chain
    checkpoint=db.checkpoint()
    with pytest.raises((CandidateError,CoordinationError),match='completed'):
        kernel.create_plan('target','instance',2,before,deletion_reasons={'tree/config.json':'restore the original baseline configuration'},
            actor='worker',now=103,authorize=authorized)
    assert db.checkpoint()==checkpoint and target(db)==(2,integrated)
    assert complete(chain)==original


def test_forward_authority_migration_preserves_real_target_native_receipt_and_completion(chain,tmp_path):
    """Actual immutable I/CAS/native bytes survive; fresh authority gates reads."""
    request,receipt=integrate(chain);original=complete(chain)
    db,store,_,_,integrated,*_=chain
    control=tmp_path/'independent-control';control.mkdir(mode=0o700)
    route=AuthorityRoute(control/'route.json',authority_domain='domain')
    approval=lambda c,o,a,e,s:c.in_transaction and a=='admin' and e==1
    route.enroll(db,actor='admin',now=103,approve=approval)
    route.freeze(db,destination=db.path.parent/'migrated.db',new_instance='migrated-state',
        migration_id='actual-target-migration',actor='admin',now=104,approve=approval)
    route.stage(db);route.activate(actor='admin',now=105,approve=approval)
    new=route.open_current()
    try:
        assert target(new)==(2,integrated)
        store.verify(integrated)
        restored=VersionTreeManager(new,store,ownership=OWNERS,tool_digest=D,policy_digest=D,
            check_qualification=lambda *args:False)
        auth=lambda c,o,a,e:c.in_transaction and a=='successor' and e==2
        assert restored.lookup('target','instance','integrate','forward',actor='successor',now=106,authorize=auth)==receipt
        assert restored.complete_integration(KEY,cycle=1,revision=1,resource='target',instance='instance',
            business='forward',qualification_refs=COMPLETE_REFS,actor='successor',now=106,authorize=auth)==original
        assert new.connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0]==1
        assert new.connection.execute('SELECT COUNT(*) FROM version_switch_receipts').fetchone()[0]==1
        with pytest.raises(CoordinationError):
            restored.lookup('target','instance','integrate','forward',actor='worker',now=106,authorize=authorized)
        with pytest.raises(CoordinationError):
            chain[2].lookup('target','instance','integrate','forward',actor='worker',now=106,authorize=authorized)
    finally:new.close()


def test_separate_compensation_restores_completed_snapshot_without_reopening_history(chain):
    """Real Completion plus trusted staging compensation, not native admission.

    The separate native exchange tests exercise grants/verification/CLI. Here
    the original completion kernel establishes the historical terminal fact.
    """
    _,forward=integrate(chain);original=complete(chain)
    db,store,_,before,integrated,*_=chain
    old_task=tuple(db.connection.execute('SELECT revision,cycle,obligation_digest FROM tasks').fetchone())
    key=TaskKey('domain','project','recovery','compensation')
    obligation=sha(b'separately approved compensation')
    db.create_change('project','recovery',actor='admin',now=103,authorize=authorized)
    db.add_task(key,obligation,actor='admin',now=103,authorize=authorized)
    binding=deepcopy(store.verify(before))
    binding.update(taskKey=dict(zip(('authorityDomain','projectId','changeId','taskId'),key.values())),obligationDigest=obligation)
    retained=store.root/before[7:]
    restored=store.receive(codec.canonical(binding),commit_bytes=(retained/'commit.bin').read_bytes(),
        archive_bytes=(retained/'archive.bin').read_bytes(),external_materials={})['candidateDigest']
    staging=VersionTreeManager(db,store,ownership=OWNERS,tool_digest=D,policy_digest=D)
    staging.register_candidate(restored,actor='worker',now=103,authorize=authorized)
    digest,plan=staging.create_plan('target','instance',2,restored,rollback_of=sha(forward),
        deletion_reasons={'tree/config.json':'restore the original snapshot'},actor='worker',now=103,authorize=authorized)
    request=intent(digest,plan,business='compensation',action='rollback');raw=codec.canonical(request)
    db.reserve(key,resource_id='target',action_class='rollback',business_id='compensation',
        original_actor='worker',request_digest=sha(raw),budget_ids=['shared'],cost=1,cycle=1,
        actor='worker',now=103,authorize=authorized,payload=raw)
    db.transition_action('target','rollback','compensation',expected='reserved',target='dispatched',
        actor='worker',now=103,authorize=authorized)
    result=codec.parse(staging.switch(request,actor='worker',now=103,authorize=authorized))
    assert target(db)==(3,restored) and result['rollbackOf']==sha(forward)
    assert result['beforeCandidateDigest']==integrated and result['afterCandidateDigest']!=before
    assert tuple(db.connection.execute('SELECT revision,cycle,obligation_digest FROM tasks WHERE task_id="task"').fetchone())==old_task
    assert chain[2].complete_integration(KEY,cycle=1,revision=1,resource='target',instance='instance',
        business='forward',qualification_refs=COMPLETE_REFS,actor='successor',now=104,authorize=authorized)==original
    assert db.connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0]==1
    assert db.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==2
    assert store.verify(before)['taskKey']!=binding['taskKey']
    db.check_integrity()


def test_rework_cannot_remove_original_integration_obligation(chain):
    integrate(chain);original=complete(chain);db=chain[0];checkpoint=db.checkpoint()
    definition=dict(contractIdentity='das-analysis-task-binding/v1',
        taskKey=dict(zip(('authorityDomain','projectId','changeId','taskId'),KEY.values())),
        taskRevision=1,taskCycle=2,obligationDigest=D,policyDigest=D,
        completionMode='analysis',verificationScopeDigest=D)
    with pytest.raises(CoordinationError,match='not approved at task creation'):
        db.rework(KEY,expected_cycle=1,analysis_binding=definition,
            actor='admin',now=103,authorize=authorized)
    assert db.checkpoint()==checkpoint
    assert db.connection.execute('SELECT cycle FROM tasks').fetchone()[0]==1
    assert complete(chain)==original
    db.check_integrity()


def test_completed_cycle_replays_candidate_registration_but_rejects_fresh_registration(chain,tmp_path):
    integrate(chain);complete(chain);db,store,kernel,before,*_=chain
    fresh_dir=tmp_path/'fresh-after-completion';fresh_dir.mkdir()
    fresh=receive(store,fixture(fresh_dir,content={'README.md':(b'new terminal-cycle candidate\n',False)}))['candidateDigest']
    checkpoint=db.checkpoint()
    assert kernel.register_candidate(before,actor='successor',now=103,authorize=authorized)==before
    assert db.checkpoint()==checkpoint
    with pytest.raises((CandidateError,CoordinationError),match='completed'):
        kernel.register_candidate(fresh,actor='worker',now=103,authorize=authorized)
    assert db.checkpoint()==checkpoint
    assert not db.connection.execute('SELECT * FROM candidate_objects WHERE candidate_digest=?',(fresh,)).fetchall()
    db.check_integrity()


def test_existing_dispatched_plan_cannot_change_target_after_cycle_completion(chain):
    request,raw=integrate(chain);db,_,kernel,before,integrated,*_=chain
    digest,value=kernel.create_plan('target','instance',2,before,deletion_reasons={'tree/config.json':'restore the original baseline configuration'},
        actor='worker',now=101,authorize=authorized)
    later=intent(digest,value,business='pending-before-complete')
    durable_dispatch(db,later);original=complete(chain);checkpoint=db.checkpoint()
    with pytest.raises((CandidateError,CoordinationError),match='completed'):
        kernel.switch(later,actor='worker',now=103,authorize=authorized)
    assert db.checkpoint()==checkpoint and target(db)==(2,integrated)
    assert complete(chain)==original and db.checkpoint()==checkpoint
    assert kernel.switch(request,actor='worker',now=103,authorize=authorized)==raw
    assert db.checkpoint()==checkpoint
    assert db.connection.execute('SELECT COUNT(*) FROM version_switch_receipts').fetchone()[0]==1
    assert db.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==2
    db.check_integrity()


def test_source_c_actual_i_native_receipt_and_unique_completion_bind_the_same_chain(chain):
    db,store,kernel,before,integrated,source,calls,_=chain
    request,raw=integrate(chain); receipt=codec.parse(raw)
    assert source!=integrated and target(db)==(2,integrated)
    assert receipt['contractIdentity']=='das-integration-receipt/v1'
    assert receipt['sourceCandidateDigest']==source and receipt['afterCandidateDigest']==integrated
    assert receipt['beforeCandidateDigest']==before and receipt['verificationEvidenceDigest']==INTEGRATE_REFS['verificationEvidenceDigest']
    assert kernel.lookup('target','instance','integrate','forward',actor='successor',now=102,authorize=authorized)==raw
    result=complete(chain)
    assert result['contractIdentity']=='das-completion/v1'
    assert result['integrationReceiptDigest']==sha(raw) and result['integrationCandidateDigest']==integrated
    assert result['decisionDigest']==COMPLETE_REFS['decisionDigest']!=receipt['decisionDigest']
    assert result['taskKey']==request['taskKey'] and result['parentChange']['status']=='active'
    assert not result['authority'] and not result['qualification']
    assert [call[0] for call in calls]==['plan','integrate','complete']
    assert db.connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0]==1
    assert db.connection.execute('SELECT COUNT(*) FROM completion_bindings').fetchone()[0]==1
    assert complete(chain)==result and target(db)==(2,integrated)
    assert db.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==1
    assert store.verify(source) and store.verify(integrated)
    db.check_integrity()


@pytest.mark.parametrize('fault',['missing','extra','wrong-evidence','wrong-stage'])
def test_missing_or_mismatched_qualification_cannot_create_integration_plan(chain,fault):
    refs=dict(INTEGRATE_REFS)
    if fault=='missing': refs.pop('verificationPlanDigest')
    elif fault=='extra': refs['allowed']=True
    elif fault=='wrong-evidence': refs['verificationEvidenceDigest']='sha256:'+'9'*64
    else: refs=COMPLETE_REFS
    checkpoint=chain[0].checkpoint()
    with pytest.raises((CandidateError,ValueError)): integration_plan(chain,refs)
    assert target(chain[0])==(1,chain[3]) and chain[0].checkpoint()==checkpoint
    assert not chain[0].connection.execute('SELECT * FROM version_plans').fetchall()


def test_default_version_manager_does_not_enable_integrate_without_installed_qualifier(chain):
    db,store,_,before,_,_,_,_=chain
    disabled=VersionTreeManager(db,store,ownership=OWNERS,tool_digest=D,policy_digest=D)
    with pytest.raises(CandidateError,match='qualification'):
        disabled.create_integration_plan('target','instance',1,chain[5],chain[4],
            qualification_refs=INTEGRATE_REFS,deletion_reasons=DELETIONS,actor='worker',now=101,authorize=authorized)
    assert target(db)==(1,before)


def test_approved_test_predicate_cannot_admit_an_unrelated_registered_i(chain, tmp_path):
    db,store,kernel,before,_,source,_,_=chain
    unrelated=tmp_path/'unrelated';unrelated.mkdir()
    wrong=receive(store,fixture(unrelated,content={'README.md':(b'no B/C lineage',False)}))['candidateDigest']
    kernel.register_candidate(wrong,actor='worker',now=100,authorize=authorized)
    checkpoint=db.checkpoint()
    with pytest.raises(CandidateError):
        kernel.create_integration_plan('target','instance',1,source,wrong,
            qualification_refs=INTEGRATE_REFS,
            deletion_reasons={'tree/src/run.py':'explicit','tree/tests/test_source.txt':'explicit'},
            actor='worker',now=101,authorize=authorized)
    assert target(db)==(1,before) and db.checkpoint()==checkpoint
    assert not db.connection.execute('SELECT * FROM version_plans').fetchall()


@pytest.mark.parametrize('fault',['revoked','task-cycle','target-generation','parent-terminal'])
def test_current_changes_after_verification_block_the_actual_target_commit(chain,fault):
    db,_,kernel,before,_,_,_,state=chain
    digest,plan=integration_plan(chain); request=intent(digest,plan,action='integrate'); durable_dispatch(db,request)
    if fault=='revoked': state['allow']=False
    elif fault=='task-cycle': db.connection.execute('UPDATE tasks SET cycle=cycle+1')
    elif fault=='target-generation': db.connection.execute('UPDATE version_targets SET generation=generation+2')
    else:
        generation=db.connection.execute('SELECT generation FROM changes').fetchone()[0]
        db.terminate_change('project','change',generation,status='cancelled',
            actor='admin',now=101,authorize=authorized)
    checkpoint=db.checkpoint()
    with pytest.raises((CandidateError,CoordinationError)):
        kernel.switch(request,actor='worker',now=101,authorize=authorized)
    assert target(db)[1]==before and db.checkpoint()==checkpoint
    assert not db.connection.execute('SELECT * FROM version_switch_receipts').fetchall()
    assert not db.connection.execute('SELECT * FROM completions').fetchall()
    assert db.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==1


def test_completion_storage_failure_preserves_integration_and_retry_does_not_integrate_again(chain):
    db,_,_,_,integrated,_,_,_=chain
    request,raw=integrate(chain)
    # Native SQLite refuses the final binding INSERT. No TEMP object or writer
    # constraint is disabled, and this is not a power-loss/disk-full claim.
    db.connection.set_authorizer(lambda operation, table, *_:
        sqlite3.SQLITE_DENY if operation==sqlite3.SQLITE_INSERT and table=='completion_bindings' else sqlite3.SQLITE_OK)
    checkpoint=db.checkpoint()
    with pytest.raises(sqlite3.DatabaseError,match='not authorized'): complete(chain)
    # Python 3.10 does not support disabling this callback with None.
    db.connection.set_authorizer(lambda *_: sqlite3.SQLITE_OK)
    assert target(db)==(2,integrated) and db.checkpoint()==checkpoint
    assert not db.connection.execute('SELECT * FROM completions').fetchall()
    assert not db.connection.execute('SELECT * FROM completion_bindings').fetchall()
    assert db.connection.execute('SELECT state FROM business_actions').fetchone()[0]=='confirmed'
    result=complete(chain)
    assert result['integrationReceiptDigest']==sha(raw) and target(db)==(2,integrated)
    assert db.connection.execute('SELECT COUNT(*) FROM version_switch_receipts').fetchone()[0]==1


def test_confirmed_legacy_apply_is_not_an_integration_receipt(chain):
    db,store,installed,_,integrated,_,_,_=chain
    # Prepare legacy staging history explicitly. The integration-only TEST
    # predicate must not become authorization for governed apply/rollback.
    kernel=VersionTreeManager(db,store,ownership=dict(installed.ownership),
        tool_digest=installed.tool_digest,policy_digest=installed.policy_digest)
    digest,plan=kernel.create_plan('target','instance',1,integrated,deletion_reasons=DELETIONS,
                                  actor='worker',now=101,authorize=authorized)
    request=intent(digest,plan,action='apply');durable_dispatch(db,request)
    raw=kernel.switch(request,actor='worker',now=101,authorize=authorized)
    db.transition_action('target','apply','forward',expected='dispatched',target='confirmed',
        receipt_digest=sha(raw),receipt_bytes=raw,actor='worker',now=101,authorize=authorized)
    assert codec.parse(raw)['contractIdentity']=='das-version-switch-receipt/v1'
    with pytest.raises(CandidateError,match='actual native integration receipt'): complete(chain)
    assert target(db)==(2,integrated) and not db.connection.execute('SELECT * FROM completions').fetchall()


def test_last_approved_completion_in_closing_and_closed_replay_keep_original_history(chain):
    db,_,kernel,_,integrated,_,_,_=chain
    integrate(chain)
    generation,task_set=db.begin_closing('project','change',2,actor='worker',now=102,authorize=authorized)
    result=complete(chain)
    assert result['parentChange']==dict(status='closing',generation=generation,taskSetDigest=task_set)
    db.close_change('project','change',generation,task_set,actor='worker',now=102,authorize=authorized)
    checkpoint=db.checkpoint()
    assert complete(chain)==result and db.checkpoint()==checkpoint
    assert db.connection.execute('SELECT status FROM changes').fetchone()[0]=='closed'
    assert target(db)==(2,integrated)
    with pytest.raises(CandidateError):
        kernel.complete_integration(KEY,cycle=2,revision=1,resource='target',instance='instance',
            business='forward',qualification_refs=COMPLETE_REFS,actor='successor',now=102,authorize=authorized)
    assert db.connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0]==1


def test_two_real_writers_record_only_one_native_completion(chain):
    db,store,kernel,_,integrated,_,_,_=chain
    integrate(chain);barrier=threading.Barrier(2)
    def writer():
        database=CoordinationDatabase(db.path,authority_domain='domain',busy_ms=2000)
        candidates=CandidateStore(store.root)
        try:
            other=VersionTreeManager(database,candidates,ownership=OWNERS,tool_digest=D,policy_digest=D,
                                     check_qualification=kernel.check_qualification)
            barrier.wait(timeout=5)
            return other.complete_integration(KEY,cycle=1,revision=1,resource='target',instance='instance',
                business='forward',qualification_refs=COMPLETE_REFS,actor='successor',now=102,authorize=authorized)
        finally:database.close();candidates.close()
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda _:writer(),range(2)))
    assert results[0]==results[1]
    assert db.connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0]==1
    assert db.connection.execute('SELECT COUNT(*) FROM completion_bindings').fetchone()[0]==1
    assert target(db)==(2,integrated) and db.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==1
    db.check_integrity()


@pytest.mark.parametrize('death_point',['after-cas','after-completion'])
def test_actual_control_process_death_recovers_original_integration_without_another_effect(chain,death_point):
    db,store,kernel,_,integrated,_,_,_=chain
    digest,plan=integration_plan(chain);request=intent(digest,plan,action='integrate')
    program='''
import json,os,sys
from pathlib import Path
root,db_path,store_path,point,request_raw=sys.argv[1:];sys.path.insert(0,root)
from dasops.protected.candidates import CandidateStore
from dasops.protected.candidates.versions import VersionTreeManager
from dasops.protected.sqlite.store import CoordinationDatabase
from dasops.protected.sqlite.outbox import DurableOutbox,Observation
from dasops.standards_contracts import exact_json as codec
from tests.protected.test_version_trees import authorized,OWNERS,KEY,D
from tests.protected.test_integration_chain import INTEGRATE_REFS,COMPLETE_REFS
database=CoordinationDatabase(Path(db_path),authority_domain='domain')
candidates=CandidateStore(Path(store_path))
def qualify(connection,phase,actor,epoch,context):
 return (authorized(connection,phase,actor,epoch) and
         context['qualificationRefs']==(COMPLETE_REFS if phase=='complete' else INTEGRATE_REFS))
manager=VersionTreeManager(database,candidates,ownership=OWNERS,tool_digest=D,policy_digest=D,check_qualification=qualify)
request=codec.parse(request_raw.encode())
class Adapter:
 def execute(self,value,*,deadline):
  raw=manager.switch(value,actor='worker',now=101,authorize=authorized)
  if point=='after-cas':os._exit(73)
  return Observation('confirmed',codec.digest(value),'instance',raw)
 def lookup(self,value,*,deadline):raise RuntimeError('first process must not reconcile')
def verify(value,observation):
 return observation.native_receipt==manager.lookup('target','instance','integrate','forward',actor='worker',now=101,authorize=authorized)
outbox=DurableOutbox(database,adapters={('target','instance','integrate'):Adapter()},verify_observation=verify,execution_closed=lambda _:False)
outbox.submit(request,actor='worker',now=101,authorize=authorized)
outbox.dispatch('target','integrate','forward',actor='worker',now=101,authorize=authorized)
manager.complete_integration(KEY,cycle=1,revision=1,resource='target',instance='instance',business='forward',qualification_refs=COMPLETE_REFS,actor='successor',now=102,authorize=authorized)
os._exit(74)
'''
    environment=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1')
    process=subprocess.run([sys.executable,'-I','-B','-c',program,str(Path(__file__).resolve().parents[2]),
        str(db.path),str(store.root),death_point,codec.canonical(request).decode()],
        cwd=db.path.parent,env=environment,capture_output=True,timeout=20)
    assert process.returncode==(73 if death_point=='after-cas' else 74),process.stderr
    assert target(db)==(2,integrated)
    if death_point=='after-cas':
        assert db.connection.execute('SELECT state FROM business_actions').fetchone()[0]=='dispatched'
        class LookupOnly:
            def execute(self, *_args, **_kwargs):raise AssertionError('recovery attempted another integration')
            def lookup(self,value,*,deadline):
                raw=kernel.lookup('target','instance','integrate','forward',actor='successor',now=102,authorize=authorized)
                return Observation('confirmed',codec.digest(value),'instance',raw)
        outbox=DurableOutbox(db,adapters={('target','instance','integrate'):LookupOnly()},
            verify_observation=lambda value,observation:observation.native_receipt==kernel.lookup(
                'target','instance','integrate','forward',actor='successor',now=102,authorize=authorized),
            execution_closed=lambda _:False)
        assert outbox.reconcile('target','integrate','forward',actor='successor',now=102,authorize=authorized)['state']=='confirmed'
        assert not db.connection.execute('SELECT * FROM completions').fetchall()
    result=complete(chain)
    assert result['integrationCandidateDigest']==integrated and target(db)==(2,integrated)
    assert db.connection.execute('SELECT COUNT(*) FROM version_switch_receipts').fetchone()[0]==1
    assert db.connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0]==1
    assert db.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==1
    db.check_integrity()


@pytest.mark.parametrize('fault',['wrong-stage','unconfirmed','target-moved','cancelled','missing-receipt'])
def test_completion_cannot_upgrade_wrong_stage_or_missing_actual_result(chain,fault):
    db,_,_,_,integrated,_,_,_=chain
    integrate(chain)
    if fault=='unconfirmed': db.connection.execute("UPDATE business_actions SET state='unknown'")
    elif fault=='target-moved': db.connection.execute('UPDATE version_targets SET generation=generation+2')
    elif fault=='cancelled': db.connection.execute("UPDATE changes SET status='cancelled'")
    refs=INTEGRATE_REFS if fault=='wrong-stage' else COMPLETE_REFS
    if fault=='missing-receipt':
        with pytest.raises(CandidateError):
            chain[2].complete_integration(KEY,cycle=1,revision=1,resource='target',instance='instance',
                business='another-apply',qualification_refs=refs,actor='successor',now=102,authorize=authorized)
    else:
        with pytest.raises((CandidateError,CoordinationError)): complete(chain,refs)
    assert not db.connection.execute('SELECT * FROM completions').fetchall()
    assert target(db)[1]==integrated


def test_clarified_task_rejects_old_candidate_and_requires_new_revision_qualification(chain):
    db,store,kernel,before,integrated,source,*_=chain
    integration_plan(chain)  # Actual original candidate was usable before revision.
    db.clarify_task(KEY,revision=1,cycle=1,obligation=D,clarification_digest=sha(b'clarified author'),
        review_digest=sha(b'independent nonmaterial review'),review=lambda c,x: x['completionDigest'] is None,
        actor='admin',now=102,authorize=authorized)
    with pytest.raises(CandidateError,match='current approved task'):
        kernel.create_integration_plan('target','instance',1,source,integrated,
            qualification_refs=INTEGRATE_REFS,deletion_reasons=DELETIONS,actor='worker',now=103,authorize=authorized)
    binding=deepcopy(store.verify(source));binding['taskRevision']=2;retained=store.root/source[7:]
    new_source=store.receive(codec.canonical(binding),commit_bytes=(retained/'commit.bin').read_bytes(),
        archive_bytes=(retained/'archive.bin').read_bytes(),external_materials={})['candidateDigest']
    new_i=store.compose_integration(before,new_source,source_paths=['tree/README.md','tree/config.json','tree/src/run.py'],
        deleted_paths=['tree/tests/test_source.txt'],tool_digest=D)['candidateDigest']
    fresh={n:sha(('revision-two-'+n).encode()) for n in INTEGRATE_REFS}
    consumer=VersionTreeManager(db,store,ownership=OWNERS,tool_digest=D,policy_digest=D,
        check_qualification=lambda c,p,a,e,x:x['plan']['taskRevision']==2 and x['qualificationRefs']==fresh)
    for candidate in (new_source,new_i):consumer.register_candidate(candidate,actor='worker',now=103,authorize=authorized)
    with pytest.raises(CandidateError,match='qualification denied'):
        consumer.create_integration_plan('target','instance',1,new_source,new_i,
            qualification_refs=INTEGRATE_REFS,deletion_reasons=DELETIONS,actor='worker',now=103,authorize=authorized)
    _,plan=consumer.create_integration_plan('target','instance',1,new_source,new_i,
        qualification_refs=fresh,deletion_reasons=DELETIONS,actor='worker',now=103,authorize=authorized)
    assert plan['taskRevision']==2 and plan['obligationDigest']==D and target(db)==(1,before)


@pytest.fixture
def verification_service(chain,tmp_path):
    import json
    integrate(chain);original=complete(chain)
    db,store,_,_,integrated,*_=chain
    original_digest=db.connection.execute('SELECT native_digest FROM completion_bindings').fetchone()[0]
    # Independently retained TEST control and a real file observation. No claim
    # that this local predicate supplies deployed native signatures/approval.
    control=tmp_path/'verification-control';control.mkdir(mode=0o700)
    plan=dict(completionDigest=original_digest,candidateDigest=integrated,assertion='README content',
        expectedContentSha256=sha(b'original source C\n'))
    (control/'plan.json').write_bytes(codec.canonical(plan))
    state={'revoked':False,'reviewFault':None}
    def service_authorized(c,o,a,e):return c.in_transaction and a=='verifier' and e==1 and not state['revoked']
    def review(c,phase,actor,epoch,context):
        if state['reviewFault']=='commit':c.execute('COMMIT')
        if state['reviewFault']=='mutate':context['completionDigest']=D
        if actor!='verifier' or state['revoked']:return False
        actual=codec.parse((control/'plan.json').read_bytes())
        if (actual['completionDigest']!=context['completionDigest'] or actual['candidateDigest']!=context['targetCandidateDigest']
                or codec.digest(actual)!=context['intent']['parameters']['verificationPlanDigest']):return False
        if phase=='plan':return True
        raw=(control/'report.json').read_bytes();report=codec.parse(raw)
        decision=(control/'decision.json').read_bytes();dec=codec.parse(decision)
        return (context['qualificationRefs']==dict(verificationPlanDigest=codec.digest(actual),
            verificationEvidenceDigest=sha(raw),decisionDigest=sha(decision))
            and report==dict(completionDigest=original_digest,verificationPlanDigest=codec.digest(actual),
                actualContentSha256=actual['expectedContentSha256'],outcome='pass')
            and dec==dict(action='audit',actor='verifier',reportDigest=sha(raw),allow=True))
    manager=VersionTreeManager(db,store,ownership=OWNERS,tool_digest=D,policy_digest=D,check_reverification=review)
    options=dict(resource='target',instance='instance',business='current-review',completion_digest=original_digest,
        verification_plan_digest=codec.digest(plan),budget_ids=['shared'],cost=2,actor='verifier',now=103,authorize=service_authorized)
    def observe():
        data=(store.root/integrated[7:]/'tree/README.md').read_bytes()
        report=dict(completionDigest=original_digest,verificationPlanDigest=codec.digest(plan),actualContentSha256=sha(data),outcome='pass')
        raw=codec.canonical(report);(control/'report.json').write_bytes(raw)
        decision=codec.canonical(dict(action='audit',actor='verifier',reportDigest=sha(raw),allow=True));(control/'decision.json').write_bytes(decision)
        return dict(verificationPlanDigest=codec.digest(plan),verificationEvidenceDigest=sha(raw),decisionDigest=sha(decision))
    return db,manager,options,observe,state,original,control


@pytest.mark.parametrize('parent',['active','closing','closed'])
def test_current_verification_uses_own_budget_and_preserves_terminal_history(verification_service,parent):
    db,manager,options,observe,state,original,_=verification_service
    if parent!='active':
        g=db.connection.execute('SELECT generation FROM changes').fetchone()[0]
        g,digest=db.begin_closing('project','change',g,actor='admin',now=103,authorize=authorized)
        if parent=='closed':db.close_change('project','change',g,digest,actor='admin',now=103,authorize=authorized)
    before_parent=tuple(db.connection.execute('SELECT * FROM changes').fetchone())
    before_task=tuple(db.connection.execute('SELECT * FROM tasks').fetchone())
    ack=manager.start_reverification(KEY,**options);assert ack['newlyDispatched'] and ack['state']=='dispatched'
    assert not manager.start_reverification(KEY,**options)['newlyDispatched']
    refs=observe()  # Run once, outside the writer transaction, after reservation.
    result=manager.record_reverification(ack['intent'],qualification_refs=refs,actor='verifier',now=104,authorize=options['authorize'])
    assert result['completionDigest']==options['completion_digest'] and result['qualification'] is False
    assert manager.record_reverification(ack['intent'],qualification_refs=refs,actor='verifier',now=104,authorize=options['authorize'])==result
    assert manager.start_reverification(KEY,**dict(options,now=104))['state']=='confirmed'
    assert tuple(db.connection.execute('SELECT * FROM changes').fetchone())==before_parent
    assert tuple(db.connection.execute('SELECT * FROM tasks').fetchone())==before_task
    assert target(db)==(original['targetGeneration'],original['integrationCandidateDigest'])
    assert db.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==3
    assert db.connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0]==1
    assert db.connection.execute("SELECT COUNT(*) FROM audit WHERE event='completion_reverified'").fetchone()[0]==1
    with pytest.raises(CoordinationError):db.claim(KEY,D,actor='worker',expires_at=120,now=104,authorize=authorized)


@pytest.mark.parametrize('fault',['revoked','worker','bad-evidence','wrong-plan','target-corrupt','cancelled','superseded','commit','mutate'])
def test_current_verification_refusal_retains_spent_budget_and_original_completion(verification_service,fault):
    db,manager,options,observe,state,original,_=verification_service
    ack=manager.start_reverification(KEY,**options);refs=observe();actor='verifier';auth=options['authorize']
    if fault=='revoked':state['revoked']=True
    if fault=='worker':actor='worker';auth=authorized
    if fault=='bad-evidence':refs['verificationEvidenceDigest']=D
    if fault=='wrong-plan':refs['verificationPlanDigest']=D
    if fault=='target-corrupt':db.connection.execute('UPDATE version_targets SET generation=generation+1')
    if fault in ('cancelled','superseded'):
        generation=db.connection.execute('SELECT generation FROM changes').fetchone()[0]
        db.terminate_change('project','change',generation,status=fault,successor='next' if fault=='superseded' else None,
            actor='admin',now=103,authorize=authorized)
    if fault in ('commit','mutate'):state['reviewFault']=fault
    before=list(db.connection.iterdump())
    with pytest.raises((CandidateError,CoordinationError)):
        manager.record_reverification(ack['intent'],qualification_refs=refs,actor=actor,now=104,authorize=auth)
    assert list(db.connection.iterdump())==before
    assert db.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==3
    assert db.connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0]==1
    assert db.connection.execute("SELECT state FROM business_actions WHERE action_class='audit'").fetchone()[0]=='dispatched'


def test_verification_after_revision_uses_explicit_original_completion_binding(verification_service):
    db,manager,options,observe,_,original,_=verification_service
    db.clarify_task(KEY,revision=1,cycle=1,obligation=D,clarification_digest=sha(b'clarification'),
        review_digest=sha(b'review'),review=lambda c,x:x['evidenceDigest']==options['completion_digest'],
        actor='admin',now=103,authorize=authorized)
    ack=manager.start_reverification(KEY,**options);assert ack['intent']['taskRevision']==2
    result=manager.record_reverification(ack['intent'],qualification_refs=observe(),actor='verifier',now=104,authorize=options['authorize'])
    assert result['taskRevision']==2
    assert codec.parse(db.connection.execute('SELECT native_bytes FROM completion_bindings').fetchone()[0])==original


def test_verification_budget_is_serial_across_real_connections(verification_service):
    db,manager,options,_,_,_,_=verification_service
    db.connection.execute('UPDATE budgets SET ceiling=4')  # TEST installation budget.
    barrier=threading.Barrier(2)
    def start(index):
        other=CoordinationDatabase(db.path,authority_domain='domain')
        try:
            consumer=VersionTreeManager(other,manager.candidates,ownership=OWNERS,tool_digest=D,policy_digest=D,
                check_reverification=manager.check_reverification)
            barrier.wait(timeout=5)
            try:return consumer.start_reverification(KEY,**dict(options,business='check-'+str(index)))['newlyDispatched']
            except CoordinationError:return False
        finally:other.close()
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(start,[1,2]))
    assert results.count(True)==1 and results.count(False)==1
    assert db.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==3


@pytest.mark.parametrize('routed',[False,True])
def test_verification_restart_reuses_original_reservation_and_installed_control(verification_service,tmp_path,routed):
    db,manager,options,observe,state,original,_=verification_service
    if routed:
        control=tmp_path/'authority-route';control.mkdir(mode=0o700)
        route=AuthorityRoute(control/'route.json',authority_domain='domain')
        route.enroll(db,actor='admin',now=103,approve=lambda c,o,a,e,s:c.in_transaction and a=='admin' and e==1)
    ack=manager.start_reverification(KEY,**options)
    reopened=route.open_current() if routed else CoordinationDatabase(db.path,authority_domain='domain')
    try:
        consumer=VersionTreeManager(reopened,manager.candidates,ownership=OWNERS,tool_digest=D,policy_digest=D,
            check_reverification=manager.check_reverification)
        resumed=consumer.start_reverification(KEY,**options)
        assert resumed['intent']==ack['intent'] and not resumed['newlyDispatched']
        result=consumer.record_reverification(resumed['intent'],qualification_refs=observe(),actor='verifier',now=104,authorize=options['authorize'])
        assert result['completionDigest']==options['completion_digest']
        assert reopened.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==3
        assert reopened.connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0]==1
    finally:reopened.close()


def test_worker_or_missing_service_cannot_start_verification(verification_service):
    db,manager,options,_,_,_,_=verification_service
    before=list(db.connection.iterdump())
    with pytest.raises(CandidateError,match='verification-service'):
        manager.start_reverification(KEY,**dict(options,actor='worker',authorize=authorized))
    uninstalled=VersionTreeManager(db,manager.candidates,ownership=OWNERS,tool_digest=D,policy_digest=D)
    with pytest.raises(CandidateError,match='not installed'):
        uninstalled.start_reverification(KEY,**options)
    assert list(db.connection.iterdump())==before


@pytest.mark.parametrize('fault',['none','epoch','unknown'])
def test_verification_native_grant_references_commit_with_the_original_result(verification_service,fault):
    db,manager,options,observe,_,_,_=verification_service
    original_review=manager.check_reverification
    authorization=dict(checkedRefs=dict(authorizationId='TEST-grant',principals=['TEST-independent-approver'],
        keyFingerprints=[D],authorityEpoch=2 if fault=='epoch' else 1,authorizationGeneration=1,ancestorIds=[]),
        grantEnvelopeDigest=D,parentEnvelopeDigests={},controlContextDigest=D)
    def review(*args):
        if original_review(*args) is not True:return False
        return dict(authorization=authorization,**({'unexpected':True} if fault=='unknown' else {}))
    manager.check_reverification=review
    if fault!='none':
        before=list(db.connection.iterdump())
        with pytest.raises((CandidateError,ValueError)):
            manager.start_reverification(KEY,**options)
        assert list(db.connection.iterdump())==before
        return
    ack=manager.start_reverification(KEY,**options)
    manager.start_reverification(KEY,**options)  # no duplicate authorization audit
    result=manager.record_reverification(ack['intent'],qualification_refs=observe(),actor='verifier',now=104,authorize=options['authorize'])
    assert manager.record_reverification(ack['intent'],qualification_refs=observe(),actor='verifier',now=104,authorize=options['authorize'])==result
    for event in ('verification_authorized','completion_reverified'):
        rows=db.connection.execute('SELECT body FROM audit WHERE event=?',(event,)).fetchall()
        assert len(rows)==1
        body=codec.parse(rows[0]['body'].encode())
        assert body['authorization']==authorization and body['completionDigest']==options['completion_digest']
    db.check_integrity()
