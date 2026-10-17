from __future__ import annotations

import base64
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

from dasops.protected.claim import (
    ProtectedClaimError,
    activate_claim,
    activation_response,
    claim_ready,
    issue_activation_challenge,
    read_worker_lock,
)
from dasops.protected.git_canonical import BareCanonicalRepo, CanonicalRepoError
from dasops.protected.state_store import ProtectedStateStore
from dasops.protected.canonical import canonical_bytes, load_canonical_json


TASKS = """# Tasks

| Task ID | Title | Owner | Status | Depends on | Verify gate |
|---|---|---|---|---|---|
| T-001 | Foundation | - | DONE | - | `verify-one` |
| T-002 | Pull me | - | TODO | T-001 | `verify-two` |
| T-003 | Wait | - | BLOCKED | T-002 | `verify-three` |

### T-001: Foundation
- Owner: -
- Status: DONE

### T-002: Pull me
- Owner: -
- Status: TODO

### T-003: Wait
- Owner: -
- Status: BLOCKED
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


def initialized_store(tmp_path: Path) -> tuple[BareCanonicalRepo, ProtectedStateStore]:
    repo = BareCanonicalRepo(seeded_bare(tmp_path))
    store = ProtectedStateStore(repo)
    store.initialize(
        {
            "schema": "protected-task-policy/v1",
            "policyId": "POLICY-TEST-001",
            "canonicalRepoPath": str(repo.path),
            "canonicalRef": "refs/heads/main",
            "allowedOperations": ["activate", "claim"],
            "leaseSecondsMin": 60,
            "leaseSecondsMax": 3600,
            "toolDigests": {"dasops": "sha256:" + "a" * 64},
        }
    )
    return repo, store


def test_claim_publishes_one_task_without_exposing_token_and_requires_activation(tmp_path: Path) -> None:
    repo, store = initialized_store(tmp_path)
    base = repo.head()
    worker_lock = tmp_path / "worker" / "T-002.lock"
    result = claim_ready(
        repo=repo,
        store=store,
        change_id="demo",
        owner="worker-01",
        worker_lock_path=worker_lock,
        idempotency_key="claim-demo-worker-01-0001",
    )
    assert result["outcome"] == "claimed_pending_activation"
    assert result["taskId"] == "T-002"
    assert result["baseCommit"] == base
    assert result["candidateCommit"] == repo.head() != base
    assert stat.S_IMODE(worker_lock.stat().st_mode) == 0o600
    assert repo._run("rev-parse", f"{repo.head()}^").stdout.decode().strip() == base
    changed = repo._run("diff", "--name-only", base, repo.head()).stdout.decode().splitlines()
    assert changed == ["openspec/changes/demo/tasks.md"]
    published_tasks = repo.read_path(repo.head(), "openspec/changes/demo/tasks.md").decode()
    assert "| T-002 | Pull me | worker-01 | IN_PROGRESS |" in published_tasks
    assert "- Owner: worker-01" in published_tasks
    assert "- Status: IN_PROGRESS" in published_tasks

    lock = read_worker_lock(worker_lock, store)
    assert lock["status"] == "claimed_pending_activation"
    token_text = lock["tokenBase64"].encode()
    assert len(base64.urlsafe_b64decode(lock["tokenBase64"] + "=")) == 32
    for path in repo.path.rglob("*"):
        if path.is_file() and path != worker_lock:
            assert token_text not in path.read_bytes()
    state = store.read_state("demo", "T-002")
    assert state is not None and state["status"] == "claimed_pending_activation"
    assert "tokenBase64" not in state
    for phase in ("intent", "candidate_prepared", "cas_pending", "cas_applied", "readback_complete"):
        assert store.wal(result["operationId"], phase) is not None

    challenge = issue_activation_challenge(
        store=store,
        change_id="demo",
        task_id="T-002",
        owner="worker-01",
    )
    token = base64.urlsafe_b64decode(lock["tokenBase64"] + "=")
    response = activation_response(token, challenge)
    receipt = activate_claim(
        store=store,
        change_id="demo",
        task_id="T-002",
        owner="worker-01",
        worker_lock_path=worker_lock,
        challenge_id=challenge["challengeId"],
        response=response,
    )
    assert receipt["outcome"] == "matched"
    assert store.read_state("demo", "T-002")["status"] == "active"
    assert read_worker_lock(worker_lock, store)["status"] == "active"


def test_claim_retry_returns_identical_receipt_and_does_not_publish_again(tmp_path: Path) -> None:
    repo, store = initialized_store(tmp_path)
    lock = tmp_path / "worker" / "T-002.lock"
    kwargs = dict(
        repo=repo,
        store=store,
        change_id="demo",
        owner="worker-01",
        worker_lock_path=lock,
        idempotency_key="claim-demo-worker-01-retry",
    )
    first = claim_ready(**kwargs)
    head = repo.head()
    second = claim_ready(**kwargs)
    assert second == first
    assert repo.head() == head


def test_wrong_activation_response_does_not_authorize_work(tmp_path: Path) -> None:
    repo, store = initialized_store(tmp_path)
    lock = tmp_path / "worker" / "T-002.lock"
    claim_ready(
        repo=repo,
        store=store,
        change_id="demo",
        owner="worker-01",
        worker_lock_path=lock,
        idempotency_key="claim-demo-worker-01-wrong-response",
    )
    challenge = issue_activation_challenge(
        store=store,
        change_id="demo",
        task_id="T-002",
        owner="worker-01",
    )
    with pytest.raises(ProtectedClaimError, match="mismatch"):
        activate_claim(
            store=store,
            change_id="demo",
            task_id="T-002",
            owner="worker-01",
            worker_lock_path=lock,
            challenge_id=challenge["challengeId"],
            response=b"x" * 32,
        )
    assert store.read_state("demo", "T-002")["status"] == "claimed_pending_activation"


def test_non_bare_or_active_hook_is_rejected(tmp_path: Path) -> None:
    ordinary = tmp_path / "ordinary"
    ordinary.mkdir()
    ordinary.chmod(0o700)
    run("git", "init", cwd=ordinary)
    with pytest.raises(CanonicalRepoError, match="bare"):
        BareCanonicalRepo(ordinary)

    bare = seeded_bare(tmp_path / "hooked")
    hook = bare / "hooks" / "update"
    hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    hook.chmod(0o755)
    with pytest.raises(CanonicalRepoError, match="hooks"):
        BareCanonicalRepo(bare)


def test_cli_claim_and_fd_activation_flow_never_prints_raw_token(tmp_path: Path) -> None:
    bare = seeded_bare(tmp_path)
    policy = tmp_path / "policy.json"
    policy.write_bytes(
        canonical_bytes(
            {
                "schema": "protected-task-policy/v1",
                "policyId": "POLICY-CLI-001",
                "canonicalRepoPath": str(bare.resolve()),
                "canonicalRef": "refs/heads/main",
                "allowedOperations": ["activate", "claim"],
                "leaseSecondsMin": 60,
                "leaseSecondsMax": 3600,
                "toolDigests": {"dasops": "sha256:" + "a" * 64},
            }
        )
    )
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    init = subprocess.run(
        [sys.executable, "-m", "dasops", "protected-state-init", "--repo-root", str(bare), "--policy", str(policy), "--json"],
        cwd=Path(__file__).resolve().parents[2],
        env=env,
        capture_output=True,
        check=True,
    )
    assert b'"ok":true' in init.stdout
    worker_lock = tmp_path / "worker" / "T-002.lock"
    claim = subprocess.run(
        [
            sys.executable,
            "-m",
            "dasops",
            "protected-claim-ready",
            "--repo-root",
            str(bare),
            "--change-id",
            "demo",
            "--owner",
            "worker-cli",
            "--worker-lock",
            str(worker_lock),
            "--idempotency-key",
            "cli-claim-worker-0001",
            "--json",
        ],
        cwd=Path(__file__).resolve().parents[2],
        env=env,
        capture_output=True,
        check=True,
    )
    lock_value = load_canonical_json(worker_lock.read_bytes())
    assert lock_value["tokenBase64"].encode() not in claim.stdout + claim.stderr
    challenge_run = subprocess.run(
        [
            sys.executable,
            "-m",
            "dasops",
            "protected-activation-challenge",
            "--repo-root",
            str(bare),
            "--change-id",
            "demo",
            "--task-id",
            "T-002",
            "--owner",
            "worker-cli",
            "--json",
        ],
        cwd=Path(__file__).resolve().parents[2],
        env=env,
        capture_output=True,
        check=True,
    )
    challenge = load_canonical_json(challenge_run.stdout)
    read_fd, write_fd = os.pipe()
    try:
        response_run = subprocess.run(
            [
                sys.executable,
                "-m",
                "dasops",
                "protected-activation-respond",
                "--repo-root",
                str(bare),
                "--worker-lock",
                str(worker_lock),
                "--challenge-id",
                challenge["challengeId"],
                "--response-fd",
                str(write_fd),
            ],
            cwd=Path(__file__).resolve().parents[2],
            env=env,
            pass_fds=(write_fd,),
            capture_output=True,
            check=True,
        )
        os.close(write_fd)
        write_fd = -1
        response = os.read(read_fd, 33)
        assert len(response) == 32
        assert response_run.stdout == b""
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)
    response_read, response_write = os.pipe()
    os.write(response_write, response)
    os.close(response_write)
    try:
        activated = subprocess.run(
            [
                sys.executable,
                "-m",
                "dasops",
                "protected-activate-claim",
                "--repo-root",
                str(bare),
                "--change-id",
                "demo",
                "--task-id",
                "T-002",
                "--owner",
                "worker-cli",
                "--worker-lock",
                str(worker_lock),
                "--challenge-id",
                challenge["challengeId"],
                "--response-fd",
                str(response_read),
                "--json",
            ],
            cwd=Path(__file__).resolve().parents[2],
            env=env,
            pass_fds=(response_read,),
            capture_output=True,
            check=True,
        )
    finally:
        os.close(response_read)
    assert b'"outcome":"matched"' in activated.stdout
    assert lock_value["tokenBase64"].encode() not in activated.stdout + activated.stderr


def test_two_simultaneous_cli_pull_claims_publish_exactly_one_claim(tmp_path: Path) -> None:
    repo, store = initialized_store(tmp_path)
    del store
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    cwd = Path(__file__).resolve().parents[2]
    processes = []
    for number in (1, 2):
        command = [
            sys.executable,
            "-m",
            "dasops",
            "protected-claim-ready",
            "--repo-root",
            str(repo.path),
            "--change-id",
            "demo",
            "--owner",
            f"worker-{number}",
            "--worker-lock",
            str(tmp_path / f"worker-{number}" / "T-002.lock"),
            "--idempotency-key",
            f"simultaneous-worker-{number}-0001",
            "--json",
        ]
        processes.append(subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE))
    completed = [process.communicate(timeout=10) + (process.returncode,) for process in processes]
    assert sorted(item[2] for item in completed) == [0, 1]
    assert sum((tmp_path / f"worker-{number}" / "T-002.lock").exists() for number in (1, 2)) == 1
    published = repo.read_path(repo.head(), "openspec/changes/demo/tasks.md").decode()
    assert published.count("| IN_PROGRESS |") == 1
    assert sum(f"worker-{number} | IN_PROGRESS" in published for number in (1, 2)) == 1


CLAIM_EXIT_BOUNDARIES = ('intent', 'lock', 'candidate_prepared', 'pending-state', 'cas',
                         'cas_applied', 'final-lock', 'final-state', 'receipt', 'readback_complete')
CLAIM_EXIT_PROGRAM = r'''
import os,sys
from pathlib import Path
from dasops.protected.claim import claim_ready
import dasops.protected.claim as module
from dasops.protected.git_canonical import BareCanonicalRepo
from dasops.protected.state_store import ProtectedStateStore
repo=BareCanonicalRepo(Path(sys.argv[1]));store=ProtectedStateStore(repo);boundary=sys.argv[3]
append=store.append_wal;write=store.write_state;receipt=store.write_receipt;cas=repo.cas
newlock=module._write_new_worker_lock;replace=module._replace_worker_lock

def after_append(value):
    result=append(value)
    if value['phase']==boundary:os._exit(81)
    return result

def after_state(value):
    result=write(value)
    if boundary==('pending-state' if value['status']=='claim_pending' else 'final-state'):os._exit(81)
    return result

def after_receipt(*args):
    result=receipt(*args)
    if boundary=='receipt':os._exit(81)
    return result

def after_cas(**kwargs):
    result=cas(**kwargs)
    if boundary=='cas':os._exit(81)
    return result

def after_lock(*args):
    result=newlock(*args)
    if boundary=='lock':os._exit(81)
    return result

def after_replace(*args):
    result=replace(*args)
    if boundary=='final-lock':os._exit(81)
    return result
store.append_wal=after_append;store.write_state=after_state;store.write_receipt=after_receipt
repo.cas=after_cas;module._write_new_worker_lock=after_lock;module._replace_worker_lock=after_replace
claim_ready(repo=repo,store=store,change_id='demo',owner='worker-01',
    worker_lock_path=Path(sys.argv[2]),idempotency_key='claim-recovery-original-0001')
raise AssertionError('requested real exit not reached')
'''


def interrupted_claim(tmp_path, boundary):
    repo, store = initialized_store(tmp_path)
    worker = tmp_path/'worker/T-002.lock'
    child = subprocess.run([sys.executable, '-B', '-c', CLAIM_EXIT_PROGRAM,
        str(repo.path), str(worker), boundary], cwd=Path(__file__).resolve().parents[2], capture_output=True, timeout=15)
    assert child.returncode == 81, child.stderr.decode()
    kwargs = dict(repo=repo, store=store, change_id='demo', owner='worker-01',
                  worker_lock_path=worker, idempotency_key='claim-recovery-original-0001')
    return repo, store, worker, kwargs


def claim_files(store, worker):
    return {str(p):p.read_bytes() for directory in ('operations', 'states', 'receipts')
            for p in (store.root/directory).rglob('*.json')} | (
                {str(worker):worker.read_bytes()} if worker.exists() else {})


@pytest.mark.parametrize('boundary', CLAIM_EXIT_BOUNDARIES)
def test_claim_real_exit_resumes_exact_original_or_refuses_missing_token(tmp_path, boundary):
    repo, store, worker, kwargs = interrupted_claim(tmp_path, boundary)
    head = repo.head(); before = claim_files(store,worker)
    if boundary == 'intent':
        with pytest.raises(ProtectedClaimError, match='token is missing'):claim_ready(**kwargs)
        assert repo.head()==head and claim_files(store,worker)==before
        return
    lock = read_worker_lock(worker,store)
    result = claim_ready(**kwargs); assert claim_ready(**kwargs)==result
    final_lock = read_worker_lock(worker,store); state=store.read_state('demo','T-002')
    assert result['candidateCommit']==repo.head()
    assert repo._run('rev-list','--count',result['baseCommit']+'..'+repo.head()).stdout.strip()==b'1'
    assert all(final_lock[k]==lock[k] for k in ('tokenBase64','tokenHash','claimGeneration','leaseGeneration','leaseExpiresAt'))
    assert state['status']=='claimed_pending_activation'
    assert all(claim_files(store,worker)[p]==raw for p,raw in before.items() if '/operations/' in p or '/receipts/' in p)
    challenge=issue_activation_challenge(store=store,change_id='demo',task_id='T-002',owner='worker-01')
    token=base64.urlsafe_b64decode(final_lock['tokenBase64']+'=')
    activate_claim(store=store,change_id='demo',task_id='T-002',owner='worker-01',worker_lock_path=worker,
        challenge_id=challenge['challengeId'],response=activation_response(token,challenge))
    assert store.read_state('demo','T-002')['status']=='active'
    assert claim_ready(**kwargs)==result


@pytest.mark.parametrize('fault', ['owner','change','worker-path','missing-token','wrong-token','generation',
    'state','candidate-content','candidate-parent','head','wal','wal-kind','policy','lease','receipt-kind','receipt-generation'])
def test_claim_recovery_refuses_original_drift_without_publishing(tmp_path,fault):
    import dasops.protected.claim as module
    from dasops.protected.canonical import with_self_digest
    boundary='receipt' if fault.startswith('receipt-') else 'cas_applied' if fault=='state' else 'candidate_prepared'
    repo,store,worker,kwargs=interrupted_claim(tmp_path,boundary)
    operation=module._operation_id(kwargs['idempotency_key'])
    if fault=='owner':kwargs['owner']='other'
    if fault=='change':kwargs['change_id']='other'
    if fault=='worker-path':kwargs['worker_lock_path']=tmp_path/'other/T-002.lock'
    if fault=='missing-token':worker.unlink()
    if fault in ('wrong-token','generation','lease'):
        lock=read_worker_lock(worker,store)
        if fault=='wrong-token':lock['tokenBase64']='A'*43
        elif fault=='generation':lock['leaseGeneration']+=1
        else:lock['leaseExpiresAt']=lock['updatedAt']
        worker.write_bytes(canonical_bytes(lock))
    if fault=='state':
        state=store.read_state('demo','T-002');state.pop('recordDigest');state['owner']='other';store.write_state(with_self_digest(state))
    if fault in ('candidate-content','candidate-parent'):
        wal=store.wal(operation,'candidate_prepared')
        if fault=='candidate-content':
            candidate,_=repo.build_single_path_commit(base_commit=wal['baseCommit'],path='openspec/changes/demo/tasks.md',
                content=TASKS.replace('Pull me','Other obligation').encode(),message='TEST changed obligation',timestamp=wal['createdAt'],scratch_root=store.scratch_root)
        else:
            tree=repo._run('rev-parse',wal['candidateCommit']+'^{tree}').stdout.decode().strip()
            candidate=repo._run('commit-tree',tree,'-p',wal['baseCommit'],'-p',wal['candidateCommit'],
                input_bytes=b'TEST multiple parents\n',extra_env={'GIT_AUTHOR_NAME':'TEST','GIT_AUTHOR_EMAIL':'test@example.invalid','GIT_COMMITTER_NAME':'TEST','GIT_COMMITTER_EMAIL':'test@example.invalid'}).stdout.decode().strip()
        wal.pop('recordDigest');wal['candidateCommit']=candidate
        (store.operation_dir(operation)/'candidate_prepared.json').write_bytes(canonical_bytes(with_self_digest(wal)))
    if fault=='head':
        wal=store.wal(operation,'candidate_prepared');repo.cas(old_commit=repo.head(),new_commit=wal['candidateCommit'])
        candidate,_=repo.build_single_path_commit(base_commit=repo.head(),path='openspec/changes/demo/tasks.md',content=TASKS.replace('Pull me','Changed definition').encode(),message='TEST independent drift',timestamp=wal['createdAt'],scratch_root=store.scratch_root)
        repo.cas(old_commit=repo.head(),new_commit=candidate)
    if fault in ('wal','wal-kind'):
        wal=store.wal(operation,'candidate_prepared');wal.pop('recordDigest');wal['owner']='other' if fault=='wal' else wal['owner']
        if fault=='wal-kind':wal['operation']='release'
        (store.operation_dir(operation)/'candidate_prepared.json').write_bytes(canonical_bytes(with_self_digest(wal)))
    if fault=='policy':
        policy=store.policy();policy['allowedOperations']=['activate'];(store.root/'policy.json').write_bytes(canonical_bytes(policy))
    if fault.startswith('receipt-'):
        value=store.read_receipt(operation,'claim-result');value.pop('recordDigest')
        if fault=='receipt-generation':value['leaseGeneration']+=1
        else:
            value.pop('workerLockSha256');value.update(schema='protected-release-result/v1',outcome='released',claimOperationId=operation,
                releasedAt='2026-07-16T10:00:00Z',workerLockDisposition='deleted_with_filesystem_residuals_unclaimed',
                authorizationChallengeDigest='sha256:'+'1'*64,authorizationResponseDigest='sha256:'+'1'*64)
        (store.receipt_path(operation,'claim-result')).write_bytes(canonical_bytes(with_self_digest(value)))
    before=claim_files(store,worker);head=repo.head()
    with pytest.raises(ProtectedClaimError):claim_ready(**kwargs)
    assert repo.head()==head and claim_files(store,worker)==before


def test_same_key_claim_recovery_competitors_keep_one_candidate_and_receipt(tmp_path):
    repo,store,worker,kwargs=interrupted_claim(tmp_path,'cas')
    code='''import sys
from pathlib import Path
from dasops.protected.claim import claim_ready
from dasops.protected.git_canonical import BareCanonicalRepo
from dasops.protected.state_store import ProtectedStateStore
repo=BareCanonicalRepo(Path(sys.argv[1]));store=ProtectedStateStore(repo)
claim_ready(repo=repo,store=store,change_id='demo',owner='worker-01',worker_lock_path=Path(sys.argv[2]),idempotency_key='claim-recovery-original-0001')
'''
    head=repo.head();lock=read_worker_lock(worker,store)
    processes=[subprocess.Popen([sys.executable,'-B','-c',code,str(repo.path),str(worker)],cwd=Path(__file__).resolve().parents[2],stdout=subprocess.PIPE,stderr=subprocess.PIPE) for _ in range(2)]
    for child in processes:
        stdout,stderr=child.communicate(timeout=15);assert child.returncode==0,stderr.decode()
    assert repo.head()==head and read_worker_lock(worker,store)['tokenHash']==lock['tokenHash']
    assert len(list((store.root/'receipts').rglob('claim-result.json')))==1
    assert len(list((store.root/'operations').glob('*')))==1
    assert claim_ready(**kwargs)['candidateCommit']==head


def test_claim_repeated_recovery_preserves_original_lease_and_time(tmp_path,monkeypatch):
    from datetime import datetime,timedelta
    import dasops.protected.claim as module
    repo,store,worker,kwargs=interrupted_claim(tmp_path,'cas')
    original=read_worker_lock(worker,store);head=repo.head();append=store.append_wal
    def failed(value):
        result=append(value)
        if value['phase']=='cas_applied':raise OSError('TEST repeated readback loss')
        return result
    store.append_wal=failed
    for offset in (2,4):
        monkeypatch.setattr(module,'_now',lambda offset=offset:datetime.fromisoformat(original['updatedAt'].replace('Z','+00:00'))+timedelta(seconds=offset))
        with pytest.raises(OSError):claim_ready(**kwargs)
        assert repo.head()==head and read_worker_lock(worker,store)==original
    store.append_wal=append
    result=claim_ready(**kwargs)
    final=read_worker_lock(worker,store)
    assert all(final[k]==original[k] for k in ('tokenBase64','tokenHash','claimGeneration','leaseGeneration','leaseExpiresAt','updatedAt'))
    assert claim_ready(**kwargs)==result
