"""Actual source SQL facts -> deterministic non-authoritative projection."""
import copy
import hashlib
import sqlite3

import pytest

from dasops.protected.candidates.projection import completion_projection, render_projection
from dasops.protected.candidates import CandidateError
from dasops.protected.sqlite.store import TaskKey, CoordinationError
from dasops.standards_contracts import exact_json as codec
from tests.protected.test_version_trees import setup, KEY, D, authorized
from tests.protected.test_integration_chain import chain, integrate, complete


def read_scope(connection, actor, epoch, key):
    return connection.in_transaction and actor == 'reader' and epoch == 1 and key == KEY


def project(db, key=KEY, **changes):
    return completion_projection(db,key,**(dict(actor='reader',now=102,authorize=read_scope)|changes))


def test_candidate_done_cannot_create_completion_and_projection_is_regenerated(chain,tmp_path):
    db,store,_,_,_,source,_,_=chain
    original=store.verify(source); digest=source
    candidate=tmp_path/'tasks.md'; candidate.write_text('# Tasks\n- [x] task DONE --force\n')
    checkpoint=db.checkpoint()
    first=project(db); text=render_projection(first)
    assert first['status']=='TODO' and first['completion'] is None
    assert b'**TODO**' in text and b'not evaluated' in text
    candidate.write_bytes(text.replace(b'**TODO**',b'**DONE**'))
    assert render_projection(project(db))==text
    assert store.verify(digest)==original and not db.connection.execute('SELECT * FROM completions').fetchall()
    assert db.checkpoint()==checkpoint


def test_actual_unique_completion_projects_exact_original_without_new_effect_or_qualification(chain,tmp_path):
    db=chain[0]; _,raw=integrate(chain); native=complete(chain)
    checkpoint=db.checkpoint(); projected=project(db)
    assert projected['status']=='DONE' and projected['completion']==native
    assert projected['completion']['integrationReceiptDigest']=='sha256:'+hashlib.sha256(raw).hexdigest()
    # Keep original bytes and their distinct hashes; output never changes C/I.
    assert projected['completionDigest']==codec.digest(native)
    text=render_projection(projected)
    (tmp_path/'tasks.md').write_bytes(text.replace(b'**DONE**',b'**TODO**'))
    assert render_projection(project(db))==text and db.checkpoint()==checkpoint
    assert projected['currentQualification']=='not_evaluated'
    assert projected['authority'] is False and projected['qualification'] is False
    assert db.connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0]==1
    db.check_integrity()


def test_old_cycle_done_is_history_and_never_completes_rework(chain):
    db=chain[0]; integrate(chain); complete(chain)
    old=project(db); assert old['status']=='DONE'
    db.rework(KEY,expected_cycle=1,actor='worker',now=103,authorize=authorized)
    checkpoint=db.checkpoint(); current=project(db,now=103)
    assert current['taskCycle']==2 and current['status']=='TODO' and current['completion'] is None
    assert db.connection.execute('SELECT COUNT(*) FROM completion_bindings').fetchone()[0]==1
    assert db.checkpoint()==checkpoint


def test_registered_same_local_id_in_another_change_has_its_own_unfinished_projection(chain):
    db=chain[0]; integrate(chain); complete(chain)
    other=TaskKey('domain','project','another-change',KEY.task_id)
    db.create_change(other.project_id,other.change_id,actor='worker',now=103,authorize=authorized)
    db.add_task(other,D,actor='worker',now=103,authorize=authorized)
    def two_read_scopes(connection,actor,epoch,key):
        return connection.in_transaction and actor=='reader' and epoch==1 and key in (KEY,other)
    checkpoint=db.checkpoint()
    assert project(db,now=103,authorize=two_read_scopes)['status']=='DONE'
    separate=project(db,key=other,now=103,authorize=two_read_scopes)
    assert separate['status']=='TODO' and separate['completion'] is None
    assert separate['taskKey']['changeId']=='another-change' and db.checkpoint()==checkpoint


@pytest.mark.parametrize('statement',['UPDATE metadata SET authority_epoch=2 WHERE singleton=1','COMMIT','ROLLBACK'])
def test_read_authorizer_cannot_turn_the_projection_snapshot_into_a_writer(chain,statement):
    db=chain[0]; checkpoint=db.checkpoint()
    def bad_reader(connection,actor,epoch,key):
        connection.execute(statement)
        return True
    with pytest.raises(CoordinationError,match='approval modified'):
        project(db,authorize=bad_reader)
    assert project(db)['status']=='TODO' and db.checkpoint()==checkpoint
    assert db.connection.execute('SELECT authority_epoch FROM metadata').fetchone()[0]==1


def test_generic_coordination_fact_without_native_completion_is_never_a_done_projection(chain):
    db=chain[0]; _,raw=integrate(chain)
    # The original trusted staging coordination API is not a qualified native
    # Completion. Preserve it, but never treat its supplied hash as that record.
    db.record_completion(KEY,cycle=1,revision=1,resource_id='target',action_class='integrate',
        business_id='forward',receipt_digest='sha256:'+hashlib.sha256(raw).hexdigest(),
        evidence_digest=D,actor='worker',now=102,authorize=authorized)
    checkpoint=db.checkpoint()
    with pytest.raises(CandidateError,match='one binding'): project(db)
    assert db.checkpoint()==checkpoint and not db.connection.execute('SELECT * FROM completion_bindings').fetchall()


@pytest.mark.parametrize('change',[
    dict(actor='unmapped-reader'),dict(now=99),
    dict(key=TaskKey('domain','project','another-change','task')),
    dict(key=TaskKey('other-domain','project','change','task')),
])
def test_scoped_current_reader_rejects_wrong_actor_time_and_namespace_without_writing(chain,change):
    checkpoint=chain[0].checkpoint()
    with pytest.raises(CandidateError): project(chain[0],**change)
    assert chain[0].checkpoint()==checkpoint and not chain[0].connection.in_transaction


@pytest.mark.parametrize('field,value',[('status','TODO'),('qualification',True),('taskCycle',2),('completionDigest',D)])
def test_edited_projection_is_rejected_without_mutating_original_completion(chain,field,value):
    integrate(chain); complete(chain); db=chain[0]; original=project(db); changed=copy.deepcopy(original)
    changed[field]=value; assert changed!=original
    checkpoint=db.checkpoint()
    with pytest.raises(CandidateError): render_projection(changed)
    assert project(db)==original and db.checkpoint()==checkpoint


@pytest.mark.parametrize('revisions',[1,2])
def test_rebound_completion_projection_preserves_original_bytes_and_explicit_mapping(chain,revisions):
    db=chain[0];integrate(chain);original=complete(chain)
    for revision in range(1,revisions+1):
        db.clarify_task(KEY,revision=revision,cycle=1,obligation=D,
            clarification_digest=codec.digest({'revision':revision+1}),review_digest=D,
            review=lambda c,x: x['evidenceDigest']==codec.digest(original),actor='admin',now=103,authorize=authorized)
    value=project(db,now=103)
    assert value['taskRevision']==revisions+1 and value['completion']==original
    assert len(value['revisionBindings'])==revisions and value['status']=='DONE'
    assert b'**DONE**' in render_projection(value)
    assert value['currentQualification']=='not_evaluated'
    broken=copy.deepcopy(value);broken['revisionBindings'][0]['evidenceDigest']=D
    with pytest.raises(CandidateError):render_projection(broken)
    del value['revisionBindings']
    with pytest.raises(CandidateError):render_projection(value)
