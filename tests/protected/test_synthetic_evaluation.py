"""Scoring/state tests with an explicit stub; no native runtime qualification."""
from pathlib import Path
import pytest

from dasops.protected.candidates import CandidateStore, CandidateError
from dasops.protected.synthetic_evaluation import SyntheticEvaluation, SyntheticProtocol, INPUT_NAME
from dasops.protected.sqlite.store import CoordinationDatabase, CoordinationError, TaskKey
from dasops.standards_contracts import exact_json as codec
from tests.protected.test_candidate_store import fixture, receive, D

KEY=TaskKey('domain','project','change','task')


def dataset_manifest(protocol):
    return dict(schemaVersion='1.0.0',datasetId=protocol.protocol_id,datasetVersion='1.0.0',
        owner='TEST-collector',pointOfContact='TEST-installation',
        intendedUse=dict(purpose='synthetic-reference',restrictions=['no-statistical-unseen-claim']),
        provenance=dict(source='controlled-synthetic',collectionMethod='synthetic'),
        license=dict(terms='TEST controlled material',restrictions=['private-evidence-only']),
        sensitivity=dict(pii='none',accessLevel='restricted'),schemaRef='urn:das:synthetic-binary-pairs',
        splits={'sealed':{'count':len(protocol.labels)}},contentHash=protocol.private_digest,
        contentHashMethod=codec.DIGEST_METHOD,artifactRefs={'raw':{'uri':'urn:'+protocol.private_digest}},
        retention=dict(windowDays=90,deletionOwner='TEST-collector'))


class StubRuntime:
    """Never executes candidate code. Native tests live at the root boundary."""
    def __init__(self,output=b'[1,1,1,0,0,0]',stopped=True):
        self.output,self.stopped,self.calls=output,stopped,0
    def run(self,root,*,expected_snapshot,timeout):
        self.calls+=1
        assert (Path(root)/INPUT_NAME).is_file()
        return dict(recordUse='explicit_unit_runtime_stub',domainTerminated=self.stopped,
            snapshotUnchanged=True,failureType=None,exitCode=0,stdout=self.output,stderr=b'',candidateStdout=self.output)


@pytest.fixture
def evaluation(tmp_path):
    root=tmp_path/'control';root.mkdir(mode=0o700)
    store_root=tmp_path/'candidates';store_root.mkdir(mode=0o700)
    private=tmp_path/'private';private.mkdir(mode=0o700)
    db=CoordinationDatabase.create(root/'state.db',authority_domain='domain',instance_id='writer')
    state={'revoked':False}
    def allow(connection,operation,actor,epoch):
        return connection.in_transaction and actor in ('admin','account-a','account-b') and epoch==1 and not state['revoked']
    db.create_change('project','change',actor='admin',now=100,authorize=allow)
    db.add_task(KEY,D,actor='admin',now=100,authorize=allow)
    db.create_budget('shared',9,actor='admin',now=100,authorize=allow)
    store=CandidateStore(store_root);source=tmp_path/'source';source.mkdir()
    candidate=receive(store,fixture(source,content={'run.py':(b'print("stub never executes this")\n',False)}))['candidateDigest']
    runtime=StubRuntime();protocol=SyntheticProtocol('synthetic-six',(3,5,7,8,10,12),(1,1,1,0,0,0))
    service=SyntheticEvaluation(database=db,candidates=store,controller=runtime,
        snapshot=lambda _: 'explicit-unit-snapshot',private_root=private,task_key=KEY,
        resource='evaluation',instance='instance',protocol=protocol,
        subjects={'account-a':('controlled-owner','shared'),'account-b':('controlled-owner','shared')},authorize=allow,
        dataset_manifest=dataset_manifest(protocol),evidence_actor='admin')
    yield db,store,service,runtime,state,candidate
    store.close();db.close()


@pytest.mark.parametrize('inputs,labels',[
    ([1],(0,)),((True,),(1,)),((1,),(True,)),((1,),(2,)),((),()),((1,2),(0,)),
])
def test_protocol_requires_bounded_exact_immutable_synthetic_data(inputs,labels):
    with pytest.raises(CandidateError):SyntheticProtocol('test',inputs,labels)


def test_private_dataset_bytes_have_a_separate_unexported_binding():
    first=SyntheticProtocol('test',(1,2),(0,1));second=SyntheticProtocol('test',(3,4),(1,0))
    assert first.digest==second.digest and first.private_digest!=second.private_digest


def test_existing_C12_contracts_bind_actual_private_result_without_query_or_budget_replay(evaluation):
    db,_,service,runtime,_,candidate=evaluation
    service.evaluate(candidate,'query',actor='account-a',now=101)
    before=tuple(db.connection.iterdump())
    evidence=service.prepare_evidence('query',actor='admin',now=102)
    assert evidence['evalReport']['metrics']==dict(correct=6,samples=6,failedSamples=0)
    assert evidence['evalReport']['artifacts']['c12']['taskKey']==dict(zip(('authorityDomain','projectId','changeId','taskId'),KEY.values()))
    result=service.consume_evidence('query',evidence,actor='admin',now=102)
    assert result['evidenceDigest']==codec.digest(evidence) and result['statisticalClaim']=='not_assessed'
    assert not result['qualificationEligible'] and not result['authorityVerified']
    assert tuple(db.connection.iterdump())==before and runtime.calls==1
    assert service.feedback('query','release',actor='account-a',now=103)==b'TOP\n'
    assert service.select_candidate(candidate,'release',actor='account-b',now=104)=='adaptive'
    with pytest.raises(CandidateError,match='unseen'):
        service.consume_evidence('query',evidence,actor='admin',now=105,claim='unseen')
    assert db.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==3
    assert service.consume_evidence('query',evidence,actor='admin',now=105)==result


@pytest.mark.parametrize('identity',['das-integration-plan/v1','das-analysis-verification-plan/v1'])
def test_C12_installed_loader_confirms_the_actual_plan_in_owning_writer(evaluation,identity):
    db,_,service,runtime,_,candidate=evaluation
    service.evaluate(candidate,'query',actor='account-a',now=101)
    evidence=service.prepare_evidence('query',actor='admin',now=102)
    binding=evidence['evalReport']['artifacts']['c12']
    common={name:binding[name] for name in ('taskKey','taskRevision','taskCycle')}
    plan=(dict(contractIdentity=identity,**common,afterCandidateDigest=candidate) if identity=='das-integration-plan/v1'
        else dict(contractIdentity=identity,bindings=dict(common,candidateDigest=candidate)))
    with db.transaction('integration_plan','account-a',102,service.authorize) as connection:
        before=tuple(connection.iterdump())
        checked=service.confirm_evidence(connection,'query',evidence,actor='admin',now=102,context={'plan':plan})
        assert connection.in_transaction and tuple(connection.iterdump())==before
        assert checked['evidenceDigest']==codec.digest(evidence) and not checked['qualificationEligible']
    assert runtime.calls==1 and db.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==2


@pytest.mark.parametrize('fault',['task','revision','cycle','candidate','identity','missing-plan','revoked','actor'])
def test_C12_installed_loader_denies_changed_consuming_scope_without_writes(evaluation,fault):
    db,_,service,runtime,state,candidate=evaluation
    service.evaluate(candidate,'query',actor='account-a',now=101)
    evidence=service.prepare_evidence('query',actor='admin',now=102)
    binding=evidence['evalReport']['artifacts']['c12']
    plan=dict(contractIdentity='das-integration-plan/v1',afterCandidateDigest=candidate,
        **{name:binding[name] for name in ('taskKey','taskRevision','taskCycle')})
    if fault=='task':plan['taskKey']=dict(plan['taskKey'],taskId='other')
    elif fault=='revision':plan['taskRevision']=2
    elif fault=='cycle':plan['taskCycle']=2
    elif fault=='candidate':plan['afterCandidateDigest']=D
    elif fault=='identity':plan['contractIdentity']='das-version-tree-plan/v1'
    context={} if fault=='missing-plan' else {'plan':plan}
    with db.transaction('integration_plan','account-a',102,service.authorize) as connection:
        if fault=='revoked':state['revoked']=True
        before=tuple(connection.iterdump())
        with pytest.raises(CandidateError):
            service.confirm_evidence(connection,'query',evidence,
                actor='account-a' if fault=='actor' else 'admin',now=102,context=context)
        assert connection.in_transaction and tuple(connection.iterdump())==before
    assert runtime.calls==1


def test_C12_installed_loader_requires_owning_writer_not_another_or_preparation_connection(evaluation):
    db,_,service,_,_,candidate=evaluation
    service.evaluate(candidate,'query',actor='account-a',now=101)
    evidence=service.prepare_evidence('query',actor='admin',now=102)
    with pytest.raises(CandidateError,match='owning'):
        service.confirm_evidence(db.connection,'query',evidence,actor='admin',now=102,context={})
    with db.read_snapshot() as connection:
        with pytest.raises(CandidateError,match='owning'):
            service.confirm_evidence(connection,'query',evidence,actor='admin',now=102,context={})


@pytest.mark.parametrize('statement',['COMMIT','ROLLBACK','UPDATE budgets SET reserved=0'])
def test_C12_installed_loader_reuses_approval_guard_even_if_callback_swallows_write_error(evaluation,statement):
    import sqlite3
    db,_,service,_,_,candidate=evaluation
    service.evaluate(candidate,'query',actor='account-a',now=101)
    evidence=service.prepare_evidence('query',actor='admin',now=102)
    allow=service.authorize
    def attempted_write(connection,*args):
        try:connection.execute(statement)
        except sqlite3.DatabaseError:pass
        return True
    binding=evidence['evalReport']['artifacts']['c12']
    context={'plan':dict(contractIdentity='das-integration-plan/v1',afterCandidateDigest=candidate,
        **{name:binding[name] for name in ('taskKey','taskRevision','taskCycle')})}
    with db.transaction('integration_plan','account-a',102,allow) as connection:
        before=tuple(connection.iterdump());service.authorize=attempted_write
        with pytest.raises(CoordinationError,match='approval'):
            service.confirm_evidence(connection,'query',evidence,actor='admin',now=102,context=context)
        assert connection.in_transaction and tuple(connection.iterdump())==before


@pytest.mark.parametrize('fault',['task','candidate','dataset','dataset-bytes','denominator','protocol',
    'budget','cost','request','missing-report','status','private-record','dataset-declaration','revoked','actor'])
def test_C12_consumer_rejects_schema_valid_mixing_and_current_authority_changes(evaluation,fault):
    db,_,service,runtime,state,candidate=evaluation
    service.evaluate(candidate,'query',actor='account-a',now=101)
    evidence=service.prepare_evidence('query',actor='admin',now=102)
    binding=evidence['evalReport']['artifacts']['c12']
    if fault=='task':binding['taskKey']['projectId']='other-project'
    elif fault=='candidate':binding['candidateDigest']=D
    elif fault=='dataset':evidence['evalReport']['dataset']['datasetId']='other-dataset'
    elif fault=='dataset-bytes':evidence['datasetManifest']['contentHash']=D
    elif fault=='denominator':evidence['evalReport']['metrics']['samples']=2
    elif fault=='protocol':binding['protocolDigest']=D
    elif fault=='budget':binding['budgetIds']=['other-budget']
    elif fault=='cost':binding['queryCost']=0
    elif fault=='request':binding['requestDigest']=D
    elif fault=='missing-report':evidence.pop('evalReport')
    elif fault=='status':evidence['evalReport']['status']='fail'
    elif fault=='private-record':
        _,intent=service.box._load('evaluation','submit','query');path=service._path(intent)
        record=codec.parse(path.read_bytes());record['correct']=0;path.write_bytes(codec.canonical(record));path.chmod(0o600)
    elif fault=='dataset-declaration':
        manifest=codec.parse(service.dataset_manifest_bytes);manifest['owner']='other';service.dataset_manifest_bytes=codec.canonical(manifest)
    elif fault=='revoked':state['revoked']=True
    before=tuple(db.connection.iterdump())
    with pytest.raises((CandidateError,ValueError)):
        service.consume_evidence('query',evidence,actor='account-a' if fault=='actor' else 'admin',now=103)
    assert tuple(db.connection.iterdump())==before and runtime.calls==1


def test_C12_private_reads_require_separate_installed_subject_and_preserve_failure_denominator(evaluation):
    db,_,service,runtime,state,candidate=evaluation;runtime.output=b'[1,1]'
    service.evaluate(candidate,'query',actor='account-a',now=101)
    with pytest.raises(CandidateError):service.prepare_evidence('query',actor='account-a',now=102)
    evidence=service.prepare_evidence('query',actor='admin',now=102)
    assert evidence['evalReport']['status']=='fail' and evidence['evalReport']['metrics']==dict(correct=0,samples=6,failedSamples=6)
    with pytest.raises(CandidateError,match='failed evaluation'):
        service.consume_evidence('query',evidence,actor='admin',now=102)
    state['revoked']=True
    with pytest.raises(CandidateError):service.prepare_evidence('query',actor='admin',now=103)
    state['revoked']=False
    assert service.prepare_evidence('query',actor='admin',now=104)==evidence
    assert db.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==2 and runtime.calls==1


@pytest.mark.parametrize('now',[True,float('nan'),float('inf'),'102',None,99])
def test_C12_private_reader_rejects_invalid_or_regressed_time_without_mutation(evaluation,now):
    db,_,service,runtime,_,candidate=evaluation
    service.evaluate(candidate,'query',actor='account-a',now=101)
    evidence=service.prepare_evidence('query',actor='admin',now=102);before=tuple(db.connection.iterdump())
    with pytest.raises((CandidateError,CoordinationError)):
        service.prepare_evidence('query',actor='admin',now=now)
    with pytest.raises((CandidateError,CoordinationError)):
        service.consume_evidence('query',evidence,actor='admin',now=now)
    assert tuple(db.connection.iterdump())==before and runtime.calls==1


def test_score_feedback_and_alias_replay_preserve_original_cost_and_selection(evaluation):
    db,_,service,runtime,_,candidate=evaluation
    assert service.evaluate(candidate,'query',actor='account-a',now=101) is None
    assert service.evaluate(candidate,'query',actor='account-b',now=102) is None
    assert runtime.calls==1 and db.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==2
    assert service.feedback('query','release',actor='account-a',now=103)==b'TOP\n'
    assert service.feedback('query','release',actor='account-b',now=104)==b'TOP\n'
    assert db.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==3
    assert service.select_candidate(candidate,'release',actor='account-b',now=105)=='adaptive'
    assert db.connection.execute("SELECT COUNT(*) FROM audit WHERE event='sealed_feedback_used_for_selection'").fetchone()[0]==1
    assert not db.connection.execute('SELECT * FROM completions').fetchall()
    db.check_integrity()


@pytest.mark.parametrize('output',[b'[]',b'[true,true,true,false,false,false]',b'{"PASS":true}',b'private-log\n[1,1,1,0,0,0]'])
def test_failed_and_malformed_predictions_keep_the_complete_original_denominator(evaluation,output):
    _,_,service,runtime,_,candidate=evaluation;runtime.output=output
    service.evaluate(candidate,'bad',actor='account-a',now=101)
    row,intent=service.box._load('evaluation','submit','bad');record,_=service._private(intent)
    assert row['state']=='confirmed' and record['denominator']==6 and record['correct']==0
    assert record['validPredictions'] is False
    assert service.feedback('bad','release',actor='account-a',now=102)==b'LOW\n'


def test_unknown_runtime_is_lookup_only_without_refund_or_feedback(evaluation):
    db,_,service,runtime,_,candidate=evaluation;runtime.stopped=False
    service.evaluate(candidate,'unknown',actor='account-a',now=101)
    service.evaluate(candidate,'unknown',actor='account-b',now=102)
    assert runtime.calls==1 and db.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==2
    with pytest.raises(CandidateError,match='confirmed'):service.feedback('unknown','release',actor='account-a',now=103)
    assert service.box._load('evaluation','submit','unknown')[0]['state']=='unknown'


def test_revocation_blocks_cached_feedback_and_recovery_does_not_reset_history(evaluation):
    db,_,service,runtime,state,candidate=evaluation
    service.evaluate(candidate,'query',actor='account-a',now=101)
    assert service.feedback('query','release',actor='account-a',now=102)==b'TOP\n'
    checkpoint=db.checkpoint();state['revoked']=True
    with pytest.raises(CandidateError,match='authorization'):service.feedback('query','release',actor='account-b',now=103)
    assert db.checkpoint()==checkpoint and db.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==3
    state['revoked']=False
    assert service.feedback('query','release',actor='account-b',now=104)==b'TOP\n'
    assert runtime.calls==1 and db.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==3


def test_unknown_account_or_changed_dataset_cannot_reset_or_rebind_budget(evaluation):
    db,_,service,runtime,_,candidate=evaluation
    with pytest.raises(CandidateError,match='unknown'):service.evaluate(candidate,'query',actor='unknown',now=101)
    service.evaluate(candidate,'query',actor='account-a',now=101)
    service.protocol=SyntheticProtocol('synthetic-six',(4,6,8,9,11,13),(0,0,0,1,1,1))
    with pytest.raises(CoordinationError,match='immutable'):service.evaluate(candidate,'query',actor='account-b',now=102)
    with pytest.raises(CandidateError,match='scope'):service.feedback('query','release',actor='account-b',now=102)
    assert runtime.calls==1 and db.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==2


def test_private_original_tamper_blocks_feedback_without_new_disclosure_cost(evaluation):
    db,_,service,_,_,candidate=evaluation
    service.evaluate(candidate,'query',actor='account-a',now=101)
    _,intent=service.box._load('evaluation','submit','query');record,_=service._private(intent)
    record['correct']=0;service._path(intent).write_bytes(codec.canonical(record))
    checkpoint=db.checkpoint()
    with pytest.raises(CandidateError,match='retained'):service.feedback('query','release',actor='account-a',now=102)
    assert db.checkpoint()==checkpoint and db.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==2


def test_reserved_input_directory_rejects_before_charging_or_running(evaluation,tmp_path):
    db,store,service,runtime,_,_=evaluation
    source=tmp_path/'reserved';source.mkdir()
    candidate=receive(store,fixture(source,content={INPUT_NAME+'/hidden.py':(b'pass\n',False)}))['candidateDigest']
    checkpoint=db.checkpoint()
    with pytest.raises(CandidateError,match='namespace'):
        service.evaluate(candidate,'query',actor='account-a',now=101)
    assert db.checkpoint()==checkpoint and runtime.calls==0


def test_changed_installed_scorer_cannot_release_cached_feedback(evaluation):
    db,_,service,runtime,_,candidate=evaluation
    service.evaluate(candidate,'query',actor='account-a',now=101)
    checkpoint=db.checkpoint();service.tool_digest='sha256:'+'9'*64
    with pytest.raises(CandidateError,match='tool'):
        service.feedback('query','release',actor='account-b',now=102)
    assert db.checkpoint()==checkpoint and runtime.calls==1


def test_other_installed_protocol_cannot_relabel_feedback_history(evaluation):
    db,_,service,_,_,candidate=evaluation
    service.evaluate(candidate,'query',actor='account-a',now=101)
    service.feedback('query','release',actor='account-a',now=102)
    checkpoint=db.checkpoint()
    service.protocol=SyntheticProtocol('other-protocol',(3,5,7,8,10,12),(1,1,1,0,0,0))
    with pytest.raises(CandidateError,match='scope'):
        service.select_candidate(candidate,'release',actor='account-b',now=103)
    assert db.checkpoint()==checkpoint


def test_generic_confirmed_inspect_is_not_sealed_feedback_history(evaluation):
    db,_,service,_,_,candidate=evaluation
    db.reserve(KEY,resource_id='evaluation',action_class='inspect',business_id='generic',
        original_actor='account-a',request_digest=D,budget_ids=['shared'],cost=1,cycle=1,
        actor='account-a',now=101,authorize=service._guard('feedback'))
    for expected,target in [('reserved','dispatched'),('dispatched','confirmed')]:
        kwargs={} if target=='dispatched' else dict(receipt_digest=codec.digest({'generic':True}),receipt_bytes=codec.canonical({'generic':True}))
        db.transition_action('evaluation','inspect','generic',expected=expected,target=target,
            actor='account-a',now=101,authorize=service._guard('feedback'),**kwargs)
    checkpoint=db.checkpoint()
    with pytest.raises(CandidateError,match='feedback'):
        service.select_candidate(candidate,'generic',actor='account-b',now=102)
    assert db.checkpoint()==checkpoint
