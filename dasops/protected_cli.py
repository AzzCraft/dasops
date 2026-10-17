from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

from .protected.canonical import canonical_bytes, load_canonical_json
from .protected.encoding import strict_urlsafe_b64decode
from .protected.claim import (
    NoReadyTask,
    activate_claim,
    activation_response,
    claim_ready,
    issue_activation_challenge,
    read_worker_lock,
)
from .protected.git_canonical import BareCanonicalRepo
from .protected.lifecycle import release_claim, renew_claim
from .protected.state_store import ProtectedStateStore


COMMANDS = {
    "protected-state-init",
    "protected-claim-ready",
    "protected-activation-challenge",
    "protected-activation-respond",
    "protected-activate-claim",
    "protected-renew-claim",
    "protected-release-claim",
}


def add_protected_parsers(sub: argparse._SubParsersAction) -> None:
    initialize = sub.add_parser("protected-state-init", help="Initialize protected state in an access-controlled bare repository")
    initialize.add_argument("--repo-root", required=True, help="Absolute path to the bare canonical repository")
    initialize.add_argument("--policy", required=True, help="Canonical protected-task-policy/v1 JSON")
    initialize.add_argument("--json", action="store_true")

    claim = sub.add_parser("protected-claim-ready", help="Atomically pull the next dependency-ready task from bare canonical main")
    claim.add_argument("--repo-root", required=True)
    claim.add_argument("--change-id", required=True)
    claim.add_argument("--owner", required=True)
    claim.add_argument("--worker-lock", required=True)
    claim.add_argument("--idempotency-key", required=True)
    claim.add_argument("--json", action="store_true")

    challenge = sub.add_parser("protected-activation-challenge", help="Issue a fresh public challenge for a pending protected claim")
    challenge.add_argument("--repo-root", required=True)
    challenge.add_argument("--change-id", required=True)
    challenge.add_argument("--task-id", required=True)
    challenge.add_argument("--owner", required=True)
    challenge.add_argument(
        "--operation",
        choices=(
            "claim_activation",
            "renewal_authorization",
            "renewal_activation",
            "release_authorization",
        ),
        default="claim_activation",
    )
    challenge.add_argument("--lifetime-seconds", type=int, default=300)
    challenge.add_argument("--json", action="store_true")

    respond = sub.add_parser("protected-activation-respond", help="Use the mode-0600 worker lock to write a challenge response to a file descriptor")
    respond.add_argument("--repo-root", required=True)
    respond.add_argument("--worker-lock", required=True)
    respond.add_argument("--challenge-id", required=True)
    respond.add_argument("--response-fd", required=True, type=int)

    activate = sub.add_parser("protected-activate-claim", help="Validate a challenge response and activate a protected claim")
    activate.add_argument("--repo-root", required=True)
    activate.add_argument("--change-id", required=True)
    activate.add_argument("--task-id", required=True)
    activate.add_argument("--owner", required=True)
    activate.add_argument("--worker-lock", required=True)
    activate.add_argument("--challenge-id", required=True)
    activate.add_argument("--response-fd", required=True, type=int)
    activate.add_argument("--json", action="store_true")

    renew = sub.add_parser("protected-renew-claim", help="Rotate an active lease token and require fresh activation")
    renew.add_argument("--repo-root", required=True)
    renew.add_argument("--change-id", required=True)
    renew.add_argument("--task-id", required=True)
    renew.add_argument("--owner", required=True)
    renew.add_argument("--worker-lock", required=True)
    renew.add_argument("--challenge-id", required=True)
    renew.add_argument("--response-fd", required=True, type=int)
    renew.add_argument("--idempotency-key", required=True)
    renew.add_argument("--lease-seconds", type=int)
    renew.add_argument("--json", action="store_true")

    release = sub.add_parser("protected-release-claim", help="Return an active task to unassigned TODO by exact-base CAS")
    release.add_argument("--repo-root", required=True)
    release.add_argument("--change-id", required=True)
    release.add_argument("--task-id", required=True)
    release.add_argument("--owner", required=True)
    release.add_argument("--worker-lock", required=True)
    release.add_argument("--challenge-id", required=True)
    release.add_argument("--response-fd", required=True, type=int)
    release.add_argument("--idempotency-key", required=True)
    release.add_argument("--json", action="store_true")


def _repo_store(path: str) -> tuple[BareCanonicalRepo, ProtectedStateStore]:
    repo = BareCanonicalRepo(Path(path))
    return repo, ProtectedStateStore(repo)


def _emit(value: dict, *, as_json: bool) -> None:
    if as_json:
        sys.stdout.buffer.write(canonical_bytes(value))
    else:
        print(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True))


def _read_exact_fd(fd: int, expected: int) -> bytes:
    if fd < 3:
        raise SystemExit("protected response descriptor must be fd 3 or greater")
    chunks: list[bytes] = []
    remaining = expected + 1
    while remaining:
        chunk = os.read(fd, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    value = b"".join(chunks)
    if len(value) != expected:
        raise SystemExit(f"protected response descriptor must contain exactly {expected} bytes")
    return value


def handle_protected(args: argparse.Namespace) -> int | None:
    if args.cmd not in COMMANDS:
        return None
    repo, store = _repo_store(args.repo_root)
    if args.cmd == "protected-state-init":
        policy = load_canonical_json(Path(args.policy).expanduser().resolve().read_bytes())
        store.initialize(policy)
        _emit({"ok": True, "operation": "protected-state-init", "repo": str(repo.path)}, as_json=args.json)
        return 0
    store.policy()
    if args.cmd == "protected-claim-ready":
        try:
            result = claim_ready(
                repo=repo,
                store=store,
                change_id=args.change_id,
                owner=args.owner,
                worker_lock_path=Path(args.worker_lock),
                idempotency_key=args.idempotency_key,
            )
        except NoReadyTask:
            _emit({"ok": False, "error": "no_ready_task", "changeId": args.change_id}, as_json=args.json)
            return 1
        _emit(result, as_json=args.json)
        return 0
    if args.cmd == "protected-activation-challenge":
        value = issue_activation_challenge(
            store=store,
            change_id=args.change_id,
            task_id=args.task_id,
            owner=args.owner,
            operation=args.operation,
            lifetime_seconds=args.lifetime_seconds,
        )
        _emit(value, as_json=args.json)
        return 0
    if args.cmd == "protected-renew-claim":
        response = _read_exact_fd(args.response_fd, 32)
        value = renew_claim(
            store=store,
            change_id=args.change_id,
            task_id=args.task_id,
            owner=args.owner,
            worker_lock_path=Path(args.worker_lock),
            challenge_id=args.challenge_id,
            response=response,
            idempotency_key=args.idempotency_key,
            lease_seconds=args.lease_seconds,
        )
        _emit(value, as_json=args.json)
        return 0
    if args.cmd == "protected-release-claim":
        response = _read_exact_fd(args.response_fd, 32)
        value = release_claim(
            repo=repo,
            store=store,
            change_id=args.change_id,
            task_id=args.task_id,
            owner=args.owner,
            worker_lock_path=Path(args.worker_lock),
            challenge_id=args.challenge_id,
            response=response,
            idempotency_key=args.idempotency_key,
        )
        _emit(value, as_json=args.json)
        return 0
    if args.cmd == "protected-activation-respond":
        if args.response_fd < 3:
            raise SystemExit("protected response descriptor must be fd 3 or greater")
        challenge = store.read_challenge(args.challenge_id)
        lock = read_worker_lock(Path(args.worker_lock).expanduser().resolve(), store)
        token = strict_urlsafe_b64decode(lock["tokenBase64"], expected_size=32)
        if "sha256:" + hashlib.sha256(token).hexdigest() != lock["tokenHash"]:
            raise SystemExit("worker-lock token hash mismatch")
        response = activation_response(token, challenge)
        written = 0
        while written < len(response):
            written += os.write(args.response_fd, response[written:])
        return 0
    if args.cmd == "protected-activate-claim":
        response = _read_exact_fd(args.response_fd, 32)
        value = activate_claim(
            store=store,
            change_id=args.change_id,
            task_id=args.task_id,
            owner=args.owner,
            worker_lock_path=Path(args.worker_lock),
            challenge_id=args.challenge_id,
            response=response,
        )
        _emit(value, as_json=args.json)
        return 0
    raise AssertionError(args.cmd)
