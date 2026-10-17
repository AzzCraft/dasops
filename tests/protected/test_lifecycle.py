from __future__ import annotations

import base64
import os
from pathlib import Path
import subprocess

import pytest

from dasops.protected.claim import (
    ProtectedClaimError,
    activate_claim,
    activation_response,
    claim_ready,
    issue_activation_challenge,
    read_worker_lock,
)
from dasops.protected import canonical_bytes, with_self_digest
from dasops.protected.git_canonical import BareCanonicalRepo
from dasops.protected.lifecycle import reclaim_expired_claim, release_claim, renew_claim
from dasops.protected.state_store import ProtectedStateStore, atomic_write


TASKS = """# Tasks

| Task ID | Title | Owner | Status | Depends on | Verify gate |
|---|---|---|---|---|---|
| T-001 | Foundation | - | DONE | - | `verify-one` |
| T-002 | Pull me | - | TODO | T-001 | `verify-two` |

### T-001: Foundation
- Owner: -
- Status: DONE

### T-002: Pull me
- Owner: -
- Status: TODO
"""


def run(*args: str, cwd: Path | None = None) -> str:
    result = subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=True)
    return result.stdout.strip()


def seeded_bare(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    source.mkdir(parents=True)
    run("git", "init", "-b", "main", cwd=source)
    run("git", "config", "user.name", "Test", cwd=source)
    run("git", "config", "user.email", "test@example.invalid", cwd=source)
    tasks = source / "openspec" / "changes" / "demo" / "tasks.md"
    tasks.parent.mkdir(parents=True)
    tasks.write_text(TASKS, encoding="utf-8")
    run("git", "add", ".", cwd=source)
    run("git", "commit", "-m", "seed", cwd=source)
    bare = tmp_path / "canonical.git"
    run("git", "init", "--bare", str(bare))
    os.chmod(bare, 0o700)
    run("git", "push", str(bare), "main:main", cwd=source)
    run("git", f"--git-dir={bare}", "symbolic-ref", "HEAD", "refs/heads/main")
    return bare


def active_claim(tmp_path: Path) -> tuple[BareCanonicalRepo, ProtectedStateStore, Path]:
    repo = BareCanonicalRepo(seeded_bare(tmp_path))
    store = ProtectedStateStore(repo)
    store.initialize(
        {
            "schema": "protected-task-policy/v1",
            "policyId": "POLICY-LIFECYCLE-001",
            "canonicalRepoPath": str(repo.path),
            "canonicalRef": "refs/heads/main",
            "allowedOperations": ["activate", "claim", "reclaim", "release", "renew"],
            "leaseSecondsMin": 60,
            "leaseSecondsMax": 3600,
            "toolDigests": {"dasops": "sha256:" + "a" * 64},
        }
    )
    worker_lock = tmp_path / "worker" / "T-002.lock"
    claim_ready(
        repo=repo,
        store=store,
        change_id="demo",
        owner="worker-01",
        worker_lock_path=worker_lock,
        idempotency_key="lifecycle-claim-worker-0001",
    )
    challenge = issue_activation_challenge(
        store=store,
        change_id="demo",
        task_id="T-002",
        owner="worker-01",
    )
    lock = read_worker_lock(worker_lock, store)
    response = activation_response(base64.urlsafe_b64decode(lock["tokenBase64"] + "="), challenge)
    activate_claim(
        store=store,
        change_id="demo",
        task_id="T-002",
        owner="worker-01",
        worker_lock_path=worker_lock,
        challenge_id=challenge["challengeId"],
        response=response,
    )
    return repo, store, worker_lock


def authorize(
    store: ProtectedStateStore,
    worker_lock: Path,
    operation: str,
) -> tuple[dict, bytes]:
    challenge = issue_activation_challenge(
        store=store,
        change_id="demo",
        task_id="T-002",
        owner="worker-01",
        operation=operation,
    )
    lock = read_worker_lock(worker_lock, store)
    token = base64.urlsafe_b64decode(lock["tokenBase64"] + "=")
    return challenge, activation_response(token, challenge)


def test_renew_rotates_token_advances_generation_and_requires_new_activation(tmp_path: Path) -> None:
    repo, store, worker_lock = active_claim(tmp_path)
    head_before = repo.head()
    prior_lock = read_worker_lock(worker_lock, store)
    prior_token = base64.urlsafe_b64decode(prior_lock["tokenBase64"] + "=")
    challenge, response = authorize(store, worker_lock, "renewal_authorization")
    result = renew_claim(
        store=store,
        change_id="demo",
        task_id="T-002",
        owner="worker-01",
        worker_lock_path=worker_lock,
        challenge_id=challenge["challengeId"],
        response=response,
        idempotency_key="renew-worker-01-generation-0002",
        lease_seconds=600,
    )
    assert repo.head() == head_before
    assert result["outcome"] == "renewal_pending_activation"
    assert result["priorLeaseGeneration"] == 1
    assert result["newLeaseGeneration"] == 2
    assert result["priorTokenHash"] != result["newTokenHash"]
    state = store.read_state("demo", "T-002")
    assert state is not None and state["status"] == "renewal_pending"
    assert state["leaseGeneration"] == 2
    renewed_lock = read_worker_lock(worker_lock, store)
    assert renewed_lock["status"] == "renewal_pending"

    activation = issue_activation_challenge(
        store=store,
        change_id="demo",
        task_id="T-002",
        owner="worker-01",
        operation="renewal_activation",
    )
    with pytest.raises(ProtectedClaimError, match="response mismatch"):
        activate_claim(
            store=store,
            change_id="demo",
            task_id="T-002",
            owner="worker-01",
            worker_lock_path=worker_lock,
            challenge_id=activation["challengeId"],
            response=activation_response(prior_token, activation),
        )
    new_token = base64.urlsafe_b64decode(renewed_lock["tokenBase64"] + "=")
    receipt = activate_claim(
        store=store,
        change_id="demo",
        task_id="T-002",
        owner="worker-01",
        worker_lock_path=worker_lock,
        challenge_id=activation["challengeId"],
        response=activation_response(new_token, activation),
    )
    assert receipt["activationKind"] == "renewal_activation"
    assert store.read_state("demo", "T-002")["status"] == "active"

    raw_new_token = renewed_lock["tokenBase64"].encode()
    for path in repo.path.rglob("*"):
        if path.is_file():
            assert raw_new_token not in path.read_bytes()


def test_release_is_single_path_cas_deletes_lock_and_next_claim_advances_generations(tmp_path: Path) -> None:
    repo, store, worker_lock = active_claim(tmp_path)
    base = repo.head()
    challenge, response = authorize(store, worker_lock, "release_authorization")
    result = release_claim(
        repo=repo,
        store=store,
        change_id="demo",
        task_id="T-002",
        owner="worker-01",
        worker_lock_path=worker_lock,
        challenge_id=challenge["challengeId"],
        response=response,
        idempotency_key="release-worker-01-generation-0001",
    )
    assert result["outcome"] == "released"
    assert result["baseCommit"] == base
    assert result["candidateCommit"] == repo.head()
    assert not worker_lock.exists()
    assert store.read_state("demo", "T-002")["status"] == "released"
    changed = repo._run("diff", "--name-only", base, repo.head()).stdout.decode().splitlines()
    assert changed == ["openspec/changes/demo/tasks.md"]
    tasks = repo.read_path(repo.head(), "openspec/changes/demo/tasks.md").decode()
    assert "| T-002 | Pull me | - | TODO |" in tasks
    assert "- Owner: -" in tasks
    assert "- Status: TODO" in tasks

    retry = release_claim(
        repo=repo,
        store=store,
        change_id="demo",
        task_id="T-002",
        owner="worker-01",
        worker_lock_path=worker_lock,
        challenge_id=challenge["challengeId"],
        response=response,
        idempotency_key="release-worker-01-generation-0001",
    )
    assert retry == result
    head_after_release = repo.head()
    next_lock = tmp_path / "worker" / "T-002-generation-2.lock"
    next_claim = claim_ready(
        repo=repo,
        store=store,
        change_id="demo",
        owner="worker-02",
        worker_lock_path=next_lock,
        idempotency_key="lifecycle-claim-worker-02-0002",
    )
    assert next_claim["claimGeneration"] == 2
    assert read_worker_lock(next_lock, store)["leaseGeneration"] == 2
    assert repo._run("rev-parse", f"{repo.head()}^").stdout.decode().strip() == head_after_release


def test_lifecycle_authorization_is_operation_bound(tmp_path: Path) -> None:
    repo, store, worker_lock = active_claim(tmp_path)
    challenge, response = authorize(store, worker_lock, "renewal_authorization")
    with pytest.raises(ProtectedClaimError, match="operation mismatch"):
        release_claim(
            repo=repo,
            store=store,
            change_id="demo",
            task_id="T-002",
            owner="worker-01",
            worker_lock_path=worker_lock,
            challenge_id=challenge["challengeId"],
            response=response,
            idempotency_key="release-with-renew-auth-0001",
        )
    assert store.read_state("demo", "T-002")["status"] == "active"
    assert worker_lock.exists()


def test_reclaim_requires_expiry_and_distinct_externally_verified_roles(tmp_path: Path) -> None:
    repo, store, worker_lock = active_claim(tmp_path)
    state = store.read_state("demo", "T-002")
    assert state is not None
    expired_state = dict(state)
    expired_state.pop("recordDigest")
    expired_state["leaseExpiresAt"] = "2000-01-01T00:00:00Z"
    expired_state = with_self_digest(expired_state)
    store.write_state(expired_state)
    lock = read_worker_lock(worker_lock, store)
    lock["leaseExpiresAt"] = expired_state["leaseExpiresAt"]
    atomic_write(worker_lock, canonical_bytes(lock), mode=0o600)
    authorization = with_self_digest(
        {
            "schema": "protected-reclaim-authorization/v1",
            "authorizationId": "RECLAIM-AUTH-0001",
            "authorityRef": "test-root/epoch-1",
            "approvalSetDigest": "sha256:" + "b" * 64,
            "changeId": "demo",
            "taskId": "T-002",
            "expectedOwner": "worker-01",
            "claimGeneration": expired_state["claimGeneration"],
            "leaseGeneration": expired_state["leaseGeneration"],
            "canonicalCommit": expired_state["canonicalCommit"],
            "priorStateDigest": expired_state["recordDigest"],
            "reason": "lease_expired",
            "requiredRoles": ["anchor_owner", "task_governance", "verifier"],
            "issuedAt": "2020-01-01T00:00:00Z",
            "expiresAt": "2099-01-01T00:00:00Z",
        }
    )
    kwargs = dict(
        repo=repo,
        store=store,
        change_id="demo",
        task_id="T-002",
        prior_owner="worker-01",
        worker_lock_path=worker_lock,
        authorization=authorization,
        idempotency_key="reclaim-expired-worker-0001",
    )
    with pytest.raises(ProtectedClaimError, match="independent.*verifier"):
        reclaim_expired_claim(**kwargs, authorization_verifier=None)
    with pytest.raises(ProtectedClaimError, match="distinct"):
        reclaim_expired_claim(
            **kwargs,
            authorization_verifier=lambda _authorization, _subject: {
                "anchor_owner": "same-person",
                "task_governance": "same-person",
                "verifier": "same-person",
            },
        )
    result = reclaim_expired_claim(
        **kwargs,
        authorization_verifier=lambda _authorization, _subject: {
            "anchor_owner": "owner-identity",
            "task_governance": "governance-identity",
            "verifier": "verifier-identity",
        },
    )
    assert result["outcome"] == "reclaimed"
    assert result["authorizationDigest"] == authorization["recordDigest"]
    assert store.read_state("demo", "T-002")["status"] == "reclaimed"
    assert not worker_lock.exists()
    tasks = repo.read_path(repo.head(), "openspec/changes/demo/tasks.md").decode()
    assert "| T-002 | Pull me | - | TODO |" in tasks


def test_renewal_retry_recovers_after_new_lock_replaced_before_state_commit(tmp_path: Path) -> None:
    _repo, store, worker_lock = active_claim(tmp_path)
    challenge, response = authorize(store, worker_lock, "renewal_authorization")
    original_write_state = store.write_state
    crashed = False

    def crash_once(value: dict):
        nonlocal crashed
        if value["status"] == "renewal_pending" and not crashed:
            crashed = True
            raise RuntimeError("simulated process loss after lock replacement")
        return original_write_state(value)

    store.write_state = crash_once  # type: ignore[method-assign]
    kwargs = dict(
        store=store,
        change_id="demo",
        task_id="T-002",
        owner="worker-01",
        worker_lock_path=worker_lock,
        challenge_id=challenge["challengeId"],
        response=response,
        idempotency_key="renew-crash-recovery-0001",
        lease_seconds=600,
    )
    with pytest.raises(RuntimeError, match="simulated process loss"):
        renew_claim(**kwargs)
    assert read_worker_lock(worker_lock, store)["status"] == "renewal_pending"
    assert store.read_state("demo", "T-002")["status"] == "active"
    store.write_state = original_write_state  # type: ignore[method-assign]
    result = renew_claim(**kwargs)
    assert result["outcome"] == "renewal_pending_activation"
    assert store.read_state("demo", "T-002")["status"] == "renewal_pending"
    assert not list(worker_lock.parent.glob("*.pending"))


def test_release_retry_recovers_lost_response_after_cas(tmp_path: Path) -> None:
    repo, store, worker_lock = active_claim(tmp_path)
    challenge, response = authorize(store, worker_lock, "release_authorization")
    original_append_wal = store.append_wal
    crashed = False

    def crash_once(value: dict):
        nonlocal crashed
        if value["phase"] == "cas_applied" and not crashed:
            crashed = True
            raise RuntimeError("simulated response loss after CAS")
        return original_append_wal(value)

    store.append_wal = crash_once  # type: ignore[method-assign]
    kwargs = dict(
        repo=repo,
        store=store,
        change_id="demo",
        task_id="T-002",
        owner="worker-01",
        worker_lock_path=worker_lock,
        challenge_id=challenge["challengeId"],
        response=response,
        idempotency_key="release-crash-recovery-0001",
    )
    with pytest.raises(RuntimeError, match="simulated response loss"):
        release_claim(**kwargs)
    published_head = repo.head()
    assert store.read_state("demo", "T-002")["status"] == "release_pending"
    store.append_wal = original_append_wal  # type: ignore[method-assign]
    result = release_claim(**kwargs)
    assert result["candidateCommit"] == published_head == repo.head()
    assert store.read_state("demo", "T-002")["status"] == "released"
    assert not worker_lock.exists()


LIFECYCLE_EXIT_PROGRAM = r'''
import base64,json,os,sys
from datetime import datetime,timezone
from pathlib import Path
from dasops.protected.claim import activation_response,read_worker_lock
from dasops.protected.git_canonical import BareCanonicalRepo
from dasops.protected.state_store import ProtectedStateStore
import dasops.protected.lifecycle as module
repo=BareCanonicalRepo(Path(sys.argv[1]));store=ProtectedStateStore(repo)
options=json.loads(Path(sys.argv[2]).read_text());kind=options.pop('kind');boundary=options.pop('boundary')
worker=Path(options.pop('worker'));now=options.pop('clock')
module._now=lambda:datetime.fromtimestamp(now,timezone.utc)
append=store.append_wal;write=store.write_state;receipt=store.write_receipt;cas=repo.cas
new=module._write_new_worker_lock;replace=module._replace_worker_lock;unlink=module._unlink_owner_file

def after_append(value):
 result=append(value)
 if value['phase']==boundary:os._exit(82)
 return result

def after_state(value):
 result=write(value)
 if boundary==('terminal-state' if value['status']=='reclaimed' else 'state'):os._exit(82)
 return result

def after_receipt(*args):
 result=receipt(*args)
 if boundary=='receipt':os._exit(82)
 return result

def after_cas(**kwargs):
 result=cas(**kwargs)
 if boundary=='cas':os._exit(82)
 return result

def after_new(*args):
 result=new(*args)
 if boundary=='pending-lock':os._exit(82)
 return result

def after_replace(*args):
 result=replace(*args)
 if boundary=='lock':os._exit(82)
 return result

def after_unlink(*args):
 result=unlink(*args)
 if boundary=='unlink':os._exit(82)
 return result
store.append_wal=after_append;store.write_state=after_state;store.write_receipt=after_receipt;repo.cas=after_cas
module._write_new_worker_lock=after_new;module._replace_worker_lock=after_replace;module._unlink_owner_file=after_unlink
if kind in ('renew','release'):
 challenge=store.read_challenge(options['challenge_id']);lock=read_worker_lock(worker,store)
 response=activation_response(base64.urlsafe_b64decode(lock['tokenBase64']+'='),challenge)
 if kind=='renew':module.renew_claim(store=store,worker_lock_path=worker,response=response,**options)
 else:module.release_claim(repo=repo,store=store,worker_lock_path=worker,response=response,**options)
else:
 module.reclaim_expired_claim(repo=repo,store=store,worker_lock_path=worker,
  authorization_verifier=lambda *args:dict(anchor_owner='TEST-owner',task_governance='TEST-governance',verifier='TEST-verifier'),**options)
raise AssertionError('real lifecycle exit not reached')
'''


@pytest.mark.parametrize('kind,boundary', [('renew',p) for p in
    ('intent','pending-lock','candidate_prepared','lock','lock_replaced','state','state_committed','unlink','receipt','readback_complete')]
    + [('reclaim',p) for p in ('intent','candidate_prepared','lock','state','cas','cas_applied','terminal-state','unlink','worker_lock_deleted','receipt','readback_complete')]
    + [('release',p) for p in ('unlink','receipt','readback_complete')])
def test_original_lifecycle_real_exit_closes_original_history_for_import(tmp_path,monkeypatch,kind,boundary):
    import json,sys
    from datetime import datetime,timedelta,timezone
    import dasops.protected.lifecycle as module
    from dasops.protected.sqlite import CoordinationDatabase,import_legacy
    repo,store,worker=active_claim(tmp_path/'old')
    state=store.read_state('demo','T-002');clock=int(datetime.now(timezone.utc).timestamp())
    if kind in ('renew','release'):
        challenge,response=authorize(store,worker,'renewal_authorization' if kind=='renew' else 'release_authorization')
        options=dict(kind=kind,boundary=boundary,worker=str(worker),clock=clock,change_id='demo',task_id='T-002',owner='worker-01',
                     challenge_id=challenge['challengeId'],idempotency_key='real-'+kind+'-window-0001')
        if kind=='renew':options['lease_seconds']=600
    else:
        clock=int(datetime.fromisoformat(state['leaseExpiresAt'].replace('Z','+00:00')).timestamp())+5
        authorization=with_self_digest(dict(schema='protected-reclaim-authorization/v1',authorizationId='TEST-RECLAIM-WINDOW',authorityRef='TEST/root',
            approvalSetDigest='sha256:'+'b'*64,changeId='demo',taskId='T-002',expectedOwner='worker-01',claimGeneration=state['claimGeneration'],
            leaseGeneration=state['leaseGeneration'],canonicalCommit=state['canonicalCommit'],priorStateDigest=state['recordDigest'],reason='lease_expired',
            requiredRoles=['anchor_owner','task_governance','verifier'],issuedAt='2020-01-01T00:00:00Z',expiresAt='2099-01-01T00:00:00Z'))
        options=dict(kind=kind,boundary=boundary,worker=str(worker),clock=clock,change_id='demo',task_id='T-002',prior_owner='worker-01',
                     authorization=authorization,idempotency_key='real-reclaim-window-0001')
    input_path=tmp_path/'original-input.json';input_path.write_text(json.dumps(options))
    child=subprocess.run([sys.executable,'-B','-c',LIFECYCLE_EXIT_PROGRAM,str(repo.path),str(input_path)],
        cwd=Path(__file__).resolve().parents[2],capture_output=True,timeout=15)
    assert child.returncode==82,child.stderr.decode()
    monkeypatch.setattr(module,'_now',lambda:datetime.fromtimestamp(clock,timezone.utc))
    call={k:v for k,v in options.items() if k not in ('kind','boundary','worker','clock')}
    if kind=='renew':
        result=renew_claim(store=store,worker_lock_path=worker,response=response,**call)
        assert renew_claim(store=store,worker_lock_path=worker,response=response,**call)==result
        # Original renewal is not usable until independent new-token activation.
        challenge,response_new=authorize(store,worker,'renewal_activation')
        activate_claim(store=store,change_id='demo',task_id='T-002',owner='worker-01',worker_lock_path=worker,
            challenge_id=challenge['challengeId'],response=response_new)
        assert store.read_state('demo','T-002')['leaseGeneration']==2
    elif kind=='release':
        result=release_claim(repo=repo,store=store,worker_lock_path=worker,response=response,**call)
        assert release_claim(repo=repo,store=store,worker_lock_path=worker,response=response,**call)==result
        assert not worker.exists()
    else:
        roles=lambda *args:dict(anchor_owner='TEST-owner',task_governance='TEST-governance',verifier='TEST-verifier')
        result=reclaim_expired_claim(repo=repo,store=store,worker_lock_path=worker,authorization_verifier=roles,**call)
        assert reclaim_expired_claim(repo=repo,store=store,worker_lock_path=worker,authorization_verifier=roles,**call)==result
        assert not worker.exists()
    operation=result['operationId'];assert store.wal(operation,'readback_complete') is not None
    final=store.read_state('demo','T-002');now=max(clock,int(datetime.fromisoformat(final['leaseExpiresAt'].replace('Z','+00:00')).timestamp()))+5
    target=tmp_path/'new';target.mkdir(mode=0o700)
    db=CoordinationDatabase.create(target/'staged.db',authority_domain='domain',instance_id='staged')
    try:
        imported=import_legacy(store,db,project_id='project',mappings=[dict(changeId='demo',taskId='T-002',obligationDigest='sha256:'+'1'*64,revision=3,cycle=4)],
                              actor='admin',now=now,approve=lambda c,o,a,e,s:bool(s) and a=='admin')
        assert imported and db.connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0]==0
        assert db.connection.execute('SELECT COUNT(*) FROM business_actions').fetchone()[0]==0
        body=json.loads(db.connection.execute("SELECT body FROM audit WHERE event='legacy_import_staged'").fetchone()[0])
        assert body['source']['originals'][str(store.receipt_path(operation,'renewal-result' if kind=='renew' else kind+'-result').relative_to(store.root))]==canonical_bytes(result).decode()
    finally:db.close()


@pytest.mark.parametrize('kind',['renew','release','reclaim'])
@pytest.mark.parametrize('fault',['policy','owner','generation'])
def test_lifecycle_receipt_tail_refuses_drift_before_wal_publication(tmp_path,monkeypatch,kind,fault):
    from datetime import datetime,timedelta,timezone
    import dasops.protected.lifecycle as module
    repo,store,worker=active_claim(tmp_path)
    if kind=='reclaim':
        state=store.read_state('demo','T-002')
        future=datetime.fromisoformat(state['leaseExpiresAt'].replace('Z','+00:00'))+timedelta(seconds=1)
        monkeypatch.setattr(module,'_now',lambda:future)
        auth=with_self_digest(dict(schema='protected-reclaim-authorization/v1',authorizationId='TEST-RECLAIM-TAIL',authorityRef='TEST/root',
            approvalSetDigest='sha256:'+'b'*64,changeId='demo',taskId='T-002',expectedOwner='worker-01',claimGeneration=state['claimGeneration'],leaseGeneration=state['leaseGeneration'],
            canonicalCommit=state['canonicalCommit'],priorStateDigest=state['recordDigest'],reason='lease_expired',requiredRoles=['anchor_owner','task_governance','verifier'],issuedAt='2020-01-01T00:00:00Z',expiresAt='2099-01-01T00:00:00Z'))
        kwargs=dict(repo=repo,store=store,change_id='demo',task_id='T-002',prior_owner='worker-01',worker_lock_path=worker,authorization=auth,
                    authorization_verifier=lambda *args:dict(anchor_owner='TEST-owner',task_governance='TEST-governance',verifier='TEST-verifier'),idempotency_key='TEST-reclaim-tail-0001')
        call=reclaim_expired_claim
    else:
        challenge,response=authorize(store,worker,'renewal_authorization' if kind=='renew' else 'release_authorization')
        kwargs=dict(store=store,change_id='demo',task_id='T-002',owner='worker-01',worker_lock_path=worker,challenge_id=challenge['challengeId'],response=response,idempotency_key='TEST-'+kind+'-tail-0001')
        if kind=='release':kwargs['repo']=repo
        call=renew_claim if kind=='renew' else release_claim
    append=store.append_wal
    def lost(value):
        if value['phase']=='readback_complete':raise OSError('TEST receipt returned before final WAL')
        return append(value)
    store.append_wal=lost
    with pytest.raises(OSError):call(**kwargs)
    store.append_wal=append;operation=module._operation_id(kind,kwargs['idempotency_key'])
    if fault=='policy':
        policy=store.policy();policy['allowedOperations'].remove(kind);(store.root/'policy.json').write_bytes(canonical_bytes(policy))
    elif fault=='owner':kwargs['prior_owner' if kind=='reclaim' else 'owner']='other'
    else:
        path=store.receipt_path(operation,'renewal-result' if kind=='renew' else kind+'-result')
        value=store.read_receipt(operation,'renewal-result' if kind=='renew' else kind+'-result');value.pop('recordDigest')
        value['newLeaseGeneration' if kind=='renew' else 'leaseGeneration']+=1
        path.write_bytes(canonical_bytes(with_self_digest(value)))
    before={str(p):p.read_bytes() for cat in ('operations','states','receipts') for p in (store.root/cat).rglob('*.json')};head=repo.head()
    with pytest.raises(ProtectedClaimError):call(**kwargs)
    assert store.wal(operation,'readback_complete') is None and repo.head()==head
    assert before=={str(p):p.read_bytes() for cat in ('operations','states','receipts') for p in (store.root/cat).rglob('*.json')}
