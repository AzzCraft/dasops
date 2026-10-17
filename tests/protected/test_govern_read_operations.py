"""Actual scoped reference reads; TEST service identity, no deployment approval."""
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import os
import socket
import sqlite3
import struct
import threading

import pytest

from dasops.protected.candidates import CandidateError, CandidateStore
from dasops.protected.candidates.govern import GovernDriver, invoke
from dasops.protected.candidates.versions import VersionTreeManager
from dasops.protected.sqlite.store import CoordinationDatabase, CoordinationError, TaskKey
from dasops.bootstrap.ipc import deadline, read_exact, write_all
from dasops.bootstrap import ipc
from dasops.standards_contracts import exact_json as codec
from tests.protected.test_version_trees import setup, KEY, OWNERS, D, authorized, target
from tests.protected.test_integration_chain import chain, integration_plan
from jsonschema.exceptions import ValidationError


@pytest.fixture
def service(setup):
    db,store,kernel,before,_=setup
    state={'allow':True,'write_attempt':False,'opened':0,'identities':[],'now':101,'unavailable':False}
    def read_authorization(connection,operation,actor,epoch):
        state['identities'].append((operation,actor,epoch))
        if state['unavailable']:
            raise CandidateError('current read authorization unavailable')
        if state['write_attempt']:
            connection.execute('UPDATE metadata SET authority_epoch=authority_epoch+1')
        return (connection.in_transaction and operation=='govern_inspect'
                and actor=='worker' and epoch==1 and state['allow'] and state['now']<=102)
    @contextmanager
    def managed():
        state['opened']+=1
        connection=CoordinationDatabase(db.path,authority_domain=KEY.authority_domain)
        objects=CandidateStore(store.root)
        try:
            yield VersionTreeManager(connection,objects,ownership=OWNERS,tool_digest=D,policy_digest=D)
        finally:
            objects.close();connection.close()
    driver=GovernDriver(manager_context=managed,authorize=read_authorization,
        peer_actors={os.getuid():'worker'},task_keys=[KEY],resource='target',instance='instance',trusted_now=lambda:state['now'])
    request=dict(contractIdentity='das-resource-action-intent/v1',taskKey=dict(
        authorityDomain='domain',projectId='project',changeId='change',taskId='task'),
        taskRevision=1,taskCycle=1,resourceId='target',resourceInstance='instance',targetGeneration=1,
        action='inspect',businessActionId='inspect-current',originalActor='worker',
        parameters={'candidateDigest':before},toolDigest=D,policyDigest=D,budgetIds=['shared'],cost=1)
    return db,store,driver,state,request


def test_authenticated_inspect_reads_actual_target_without_write_configuration(service):
    db,store,driver,_,request=service;checkpoint=db.checkpoint()
    raw=driver.dispatch(request)
    assert codec.digest(codec.parse(raw))==request['parameters']['candidateDigest']
    assert codec.parse(raw)==store.verify(request['parameters']['candidateDigest'])
    assert db.checkpoint()==checkpoint and target(db)==(1,request['parameters']['candidateDigest'])
    assert db.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==0
    assert not db.connection.execute('SELECT * FROM business_actions').fetchall()


@pytest.mark.parametrize('field,value',[
    ('taskRevision',2),('taskCycle',2),('policyDigest','sha256:'+'2'*64),
    ('toolDigest','sha256:'+'2'*64),('resourceId','other'),('resourceInstance','other'),
    ('targetGeneration',2),('originalActor','admin'),
    ('parameters',{'candidateDigest':'sha256:'+'2'*64}),
    ('parameters',{'candidateDigest':D,'authority':True}),
    ('taskKey',dict(authorityDomain='domain',projectId='project',changeId='other',taskId='task')),
])
def test_authenticated_inspect_denies_changed_scope_without_writing(service,field,value):
    db,_,driver,_,request=service;request=deepcopy(request);request[field]=value;checkpoint=db.checkpoint()
    with pytest.raises((CandidateError,codec.ExactJsonError)):driver.dispatch(request)
    assert db.checkpoint()==checkpoint
    assert db.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==0


def test_inspect_still_requires_current_read_authorization(service):
    db,_,driver,state,request=service;checkpoint=db.checkpoint();state['allow']=False
    with pytest.raises(CandidateError,match='authorization'):driver.dispatch(request)
    assert db.checkpoint()==checkpoint


@pytest.mark.parametrize('parameters',[
    {'candidateDigest':D,'view':'preview'},
    {'candidateDigest':D,'view':True},
    {'candidateDigest':D,'view':None},
    {'candidateDigest':D,'view':'context-pack','scope':'caller-selected'},
])
def test_unsupported_read_view_cannot_select_configuration_or_open_manager(service,parameters):
    db,_,driver,state,request=service;request=deepcopy(request);request['parameters']=parameters
    checkpoint=db.checkpoint()
    with pytest.raises((CandidateError,codec.ExactJsonError)):driver.dispatch(request)
    assert state['opened']==0 and db.checkpoint()==checkpoint


@pytest.mark.parametrize('operation',['inspect','plan'])
@pytest.mark.parametrize('destination',['document','git','policy','link','concurrent'])
def test_read_request_cannot_select_privileged_output_or_replace_real_files(service,tmp_path,operation,destination):
    db,_,driver,state,request=service
    owned=tmp_path/'user-project';owned.mkdir()
    documents={owned/'SPECIFICATION.md':b'TEST user document\n',
               owned/'.git/config':b'TEST original Git config\n',
               owned/'policies/current.json':b'{"TEST":"original policy"}\n'}
    for path,raw in documents.items():path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
    alias=owned/'document-alias';alias.symlink_to(owned/'SPECIFICATION.md')
    destinations=dict(document=owned/'SPECIFICATION.md',git=owned/'.git',policy=owned/'policies',
                      link=alias,concurrent=owned/'new-diagnostic.json')
    refused=deepcopy(request);refused['action']=operation
    refused['parameters']=dict(candidateDigest=request['parameters']['candidateDigest']) if operation=='inspect' else dict(planDigest=D)
    refused['parameters']['output']=str(destinations[destination])
    checkpoint=db.checkpoint()
    if destination=='concurrent':
        import threading
        start=threading.Barrier(2)
        def other_writer():
            start.wait()
            with destinations[destination].open('xb') as stream:stream.write(b'TEST independent concurrent file\n')
        with ThreadPoolExecutor(max_workers=1) as pool:
            writer=pool.submit(other_writer);start.wait()
            with pytest.raises(codec.ExactJsonError):driver.dispatch(refused)
            writer.result(timeout=5)
        assert destinations[destination].read_bytes()==b'TEST independent concurrent file\n'
    else:
        with pytest.raises(codec.ExactJsonError):driver.dispatch(refused)
    assert state['opened']==0 and db.checkpoint()==checkpoint
    assert all(path.read_bytes()==raw for path,raw in documents.items())
    assert alias.is_symlink() and alias.resolve()==owned/'SPECIFICATION.md'
    assert db.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==0


def test_read_diagnostic_caller_can_publish_one_new_exclusive_artifact_without_mutation(service,tmp_path):
    db,store,driver,_,request=service;checkpoint=db.checkpoint()
    # Existing read returns bytes only. The caller owns the output permission and
    # exclusive creation; the service receives no destination or fallback writer.
    raw=driver.dispatch(request)
    output=tmp_path/'isolated-output';output.mkdir(mode=0o700)
    path=output/'inspect.json'
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'wb') as stream:stream.write(raw)
    assert codec.parse(path.read_bytes())==store.verify(request['parameters']['candidateDigest'])
    assert db.checkpoint()==checkpoint and target(db)==(1,request['parameters']['candidateDigest'])
    before=hashlib.sha256(path.read_bytes()).digest()
    with pytest.raises(FileExistsError):os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    assert hashlib.sha256(path.read_bytes()).digest()==before
    assert not db.connection.execute('SELECT * FROM business_actions').fetchall()


def test_current_pack_requires_installed_reader_without_breaking_ordinary_inspect(service):
    db,_,driver,_,request=service;checkpoint=db.checkpoint()
    with pytest.raises(CandidateError,match='installed current Bundle reader'):
        driver.dispatch(dict(request,parameters=dict(request['parameters'],view='context-pack')))
    assert codec.digest(codec.parse(driver.dispatch(request)))==request['parameters']['candidateDigest']
    assert db.checkpoint()==checkpoint


def test_inspect_authorizer_cannot_write_through_read_snapshot(service):
    db,_,driver,state,request=service;checkpoint=db.checkpoint();state['write_attempt']=True
    with pytest.raises(CoordinationError,match='approval modified'):driver.dispatch(request)
    assert db.checkpoint()==checkpoint


@pytest.mark.parametrize('command',['COMMIT','ROLLBACK','script','query-policy','authorizer'])
def test_read_approval_cannot_end_or_reconfigure_owning_snapshot(service,command):
    db,_,driver,state,request=service;before=tuple(db.connection.iterdump())
    def approval(connection,operation,actor,epoch):
        allowed=connection.in_transaction and actor=='worker' and epoch==1
        try:
            if command=='script':connection.executescript('SELECT 1;')
            elif command=='query-policy':connection.execute('PRAGMA query_only=OFF')
            elif command=='authorizer':connection.set_authorizer(lambda *_:sqlite3.SQLITE_OK)
            else:connection.execute(command)
        except (sqlite3.DatabaseError,CoordinationError):pass  # swallowed violations must still deny
        return allowed
    driver.authorize=approval
    with pytest.raises(CoordinationError,match='approval modified'):driver.dispatch(request)
    assert tuple(db.connection.iterdump())==before and target(db)==(1,request['parameters']['candidateDigest'])


def test_inspect_real_unix_peer_and_client_use_the_same_original_binding(service):
    db,_,driver,_,request=service;checkpoint=db.checkpoint()
    server,client=socket.socketpair()
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(driver.serve_once,server.fileno())
            observed=invoke(client,request,expected_server_uid=os.getuid())
            assert codec.canonical(observed)==future.result(timeout=10)
        assert codec.digest(observed)==request['parameters']['candidateDigest']
        assert db.checkpoint()==checkpoint
    finally:
        server.close();client.close()


@pytest.mark.parametrize('fault',['none','revoked','unavailable','expired','clock-backwards','write-at-release'])
def test_prepared_inspect_rechecks_current_permission_at_actual_send(service,monkeypatch,fault):
    db,_,driver,state,request=service
    before=tuple(db.connection.iterdump())
    staged=threading.Event();resume=threading.Event()
    original_ready=ipc._ready
    def ready(channel,limit,*,write=False):
        if write and threading.current_thread().name.startswith('ThreadPoolExecutor'):
            staged.set()
            assert resume.wait(5), 'TEST permission change did not reach the send barrier'
        return original_ready(channel,limit,write=write)
    monkeypatch.setattr(ipc,'_ready',ready)
    server,client=socket.socketpair()
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(driver.serve_once,server.fileno())
            raw=codec.canonical(request)
            write_all(client,len(raw).to_bytes(8,'big')+raw,deadline())
            assert staged.wait(5), 'TEST read never reached actual transport readiness'
            if fault=='revoked':state['allow']=False
            elif fault=='unavailable':state['unavailable']=True
            elif fault=='expired':state['now']=103
            elif fault=='clock-backwards':state['now']=100
            elif fault=='write-at-release':state['write_attempt']=True
            resume.set()
            if fault=='none':
                size=int.from_bytes(read_exact(client,8,deadline()),'big')
                raw=read_exact(client,size,deadline())
                assert codec.digest(codec.parse(raw))==request['parameters']['candidateDigest']
                assert future.result(timeout=5)==raw
            else:
                assert client.recv(4096)==b'', 'prepared protected bytes escaped after current denial'
                with pytest.raises((CandidateError,sqlite3.OperationalError,CoordinationError)):future.result(timeout=5)
    finally:
        resume.set();server.close();client.close()
    assert tuple(db.connection.iterdump())==before


@pytest.mark.parametrize('actor',['admin','owner','approver'])
@pytest.mark.parametrize('transport',['local','unix'])
def test_self_reported_role_cannot_replace_actual_identity_or_write(service,actor,transport):
    db,store,driver,state,request=service
    request=deepcopy(request);request['originalActor']=actor
    before=tuple(db.connection.iterdump())
    retained=codec.canonical(store.verify(request['parameters']['candidateDigest']))
    if transport=='local':
        with pytest.raises(CandidateError,match='authorization'):driver.dispatch(request)
    else:
        server,client=socket.socketpair()
        try:
            # Observe the kernel identity independently of the JSON claim.
            pid,uid,gid=struct.unpack('3i',server.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            assert (pid,uid,gid)==(os.getpid(),os.getuid(),os.getgid())
            assert driver.peer_actors[uid]=='worker' and actor!=driver.peer_actors[uid]
            with ThreadPoolExecutor(max_workers=1) as pool:
                future=pool.submit(driver.serve_once,server.fileno())
                with pytest.raises(CandidateError,match='unknown'):
                    invoke(client,request,expected_server_uid=os.getuid())
                with pytest.raises(CandidateError,match='authorization'):future.result(timeout=10)
        finally:
            server.close();client.close()
    assert state['identities']==[], 'claimed actor reached the installed authorizer'
    assert tuple(db.connection.iterdump())==before
    assert codec.canonical(store.verify(request['parameters']['candidateDigest']))==retained
    assert target(db)==(1,request['parameters']['candidateDigest'])


@pytest.mark.parametrize('fault',['digest','project','domain','uri','purpose','revoked'])
def test_valid_foreign_digest_never_grants_read_or_export(service,fault):
    db,store,driver,state,request=service
    request=deepcopy(request)
    original=store.verify(request['parameters']['candidateDigest'])
    retained=store.root/request['parameters']['candidateDigest'][7:]
    foreign=deepcopy(original);foreign['taskKey']['projectId']='other-project'
    foreign_digest=store.receive(codec.canonical(foreign),commit_bytes=(retained/'commit.bin').read_bytes(),
        archive_bytes=(retained/'archive.bin').read_bytes(),external_materials={})['candidateDigest']
    assert store.verify(foreign_digest)==foreign and codec.digest(foreign)==foreign_digest
    assert foreign['taskKey']['projectId']!=original['taskKey']['projectId']
    foreign_key=TaskKey('domain','other-project','change','task')
    db.create_change('other-project','change',actor='admin',now=100,authorize=authorized)
    db.add_task(foreign_key,D,actor='admin',now=100,authorize=authorized)
    with driver.manager_context() as manager:
        manager.register_candidate(foreign_digest,actor='worker',now=100,authorize=authorized)
        manager.install_target('foreign-target','instance',foreign_digest,actor='admin',now=100,authorize=authorized)
    foreign_driver=GovernDriver(manager_context=driver.manager_context,authorize=driver.authorize,
        peer_actors=driver.peer_actors,task_keys=[foreign_key],resource='foreign-target',
        instance='instance',trusted_now=lambda:state['now'])
    foreign_request=deepcopy(request)
    foreign_request.update(taskKey=foreign['taskKey'],resourceId='foreign-target',
        parameters={'candidateDigest':foreign_digest})
    # Both objects and full tasks exist, and are legally readable at their own
    # authenticated resource entry. Same TEST UID does not claim role independence.
    legal_before=tuple(db.connection.iterdump())
    for actual_driver,actual_request in ((driver,request),(foreign_driver,foreign_request)):
        server,client=socket.socketpair()
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                future=pool.submit(actual_driver.serve_once,server.fileno())
                value=invoke(client,actual_request,expected_server_uid=os.getuid())
                assert codec.canonical(value)==future.result(timeout=10)
                assert codec.digest(value)==actual_request['parameters']['candidateDigest']
        finally:server.close();client.close()
    assert tuple(db.connection.iterdump())==legal_before
    if fault=='digest':request['parameters']['candidateDigest']=foreign_digest
    elif fault=='project':request['taskKey']['projectId']='other-project';request['parameters']['candidateDigest']=foreign_digest
    elif fault=='domain':request['taskKey']['authorityDomain']='other-domain'
    elif fault=='uri':request['parameters'].update(candidateDigest=foreign_digest,uri=(store.root/foreign_digest[7:]).as_uri())
    elif fault=='purpose':request['action']='audit'  # A digest cannot select a diagnostic export purpose.
    elif fault=='revoked':state['allow']=False
    before=tuple(db.connection.iterdump());checkpoint=db.checkpoint()
    server,client=socket.socketpair()
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(driver.serve_once,server.fileno())
            with pytest.raises(CandidateError,match='unknown'):
                invoke(client,request,expected_server_uid=os.getuid())
            with pytest.raises((CandidateError,codec.ExactJsonError)):future.result(timeout=10)
    finally:
        server.close();client.close()
    assert tuple(db.connection.iterdump())==before and db.checkpoint()==checkpoint
    assert tuple(db.connection.execute("SELECT generation,candidate_digest FROM version_targets WHERE resource_id='target' AND resource_instance='instance'").fetchone())==(1,codec.digest(original))
    assert tuple(db.connection.execute("SELECT generation,candidate_digest FROM version_targets WHERE resource_id='foreign-target' AND resource_instance='instance'").fetchone())==(1,foreign_digest)
    assert store.verify(foreign_digest)==foreign


@pytest.mark.parametrize('field,value',[
    ('taskCycle',2),('policyDigest','sha256:'+'2'*64),
    ('taskKey',dict(authorityDomain='domain',projectId='project',changeId='other',taskId='task')),
])
@pytest.mark.parametrize('operation',['inspect','submit','submission-audit'])
def test_inspect_client_rejects_valid_response_hash_with_wrong_task_binding(service,field,value,operation):
    _,store,_,_,request=service;request=deepcopy(request)
    forged=deepcopy(store.verify(request['parameters']['candidateDigest']));forged[field]=value
    request['parameters']['candidateDigest']=codec.digest(forged)
    request['action']='audit' if operation=='submission-audit' else operation
    if operation=='submission-audit':request['parameters'].update(originalAction='submit',originalRequestDigest=D)
    raw=codec.canonical(forged);server,client=socket.socketpair()
    def wrong_subject_server():
        limit=deadline();size=int.from_bytes(read_exact(server,8,limit),'big')
        read_exact(server,size,limit)
        write_all(server,len(raw).to_bytes(8,'big')+raw,limit)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(wrong_subject_server)
            with pytest.raises(CandidateError,match='unknown'):invoke(client,request,expected_server_uid=os.getuid())
            future.result(timeout=10)
    finally:
        server.close();client.close()


@pytest.mark.parametrize('field',['taskRevision','taskCycle','expectedGeneration','imageSize'])
@pytest.mark.parametrize('value',[codec.parse(b'1.000000000000000001'),True,2**53])
def test_creation_nested_counters_reject_before_rounding_or_opening_manager(service,chain,field,value):
    db,_,driver,state,request=service
    _,plan=integration_plan(chain);request=deepcopy(request)
    request.update(action='plan',parameters=dict(plan=deepcopy(plan)))
    if field=='imageSize':request['parameters']['plan']['changes'][0]['preimage']['size']=value
    else:request['parameters']['plan'][field]=value
    checkpoint=db.checkpoint()
    with pytest.raises(ValidationError):driver.dispatch(request)
    assert state['opened']==0 and db.checkpoint()==checkpoint
