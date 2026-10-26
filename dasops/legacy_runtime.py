"""Identity checks for explicitly pinned Cadence installs in 1.4 products.

Also shipped verbatim as scripts/cadence_runtime.py; uses only the stdlib.
"""
from __future__ import annotations

import argparse
try:
    import fcntl
except ImportError:
    fcntl = None
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


def read(path):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError(f"not a regular installation file: {path}")
    return path.read_bytes()


def load(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate installation field: {key}")
            result[key] = value
        return result
    value = json.loads(read(path), object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("installation object required")
    return value


def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def git(source, *args):
    return subprocess.check_output(['git', '-C', str(source), *args], stderr=subprocess.PIPE)


def source_identity(source, commit):
    if not isinstance(commit, str) or not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('a full lowercase 40-character Cadence commit is required')
    if source.is_symlink() or Path(git(source, 'rev-parse', '--show-toplevel').decode().strip()).resolve() != source.resolve():
        raise ValueError('Cadence source must be an independent Git checkout')
    if git(source, 'rev-parse', 'HEAD').decode().strip() != commit:
        raise ValueError('installed Cadence commit differs')
    if git(source, 'status', '--porcelain', '--untracked-files=all') or git(source, 'ls-files', '--others'):
        raise ValueError('Cadence source is modified; reinstall the selected commit')
    names = git(source, 'ls-files', '-z').decode().split('\0')
    files = {}
    for name in sorted(filter(None, names)):
        path = source / name
        if not path.resolve().is_relative_to(source.resolve()):
            raise ValueError('Cadence source escapes its checkout')
        files[name] = digest(read(path))
    if not files:
        raise ValueError('empty Cadence source')
    return digest(json.dumps(files, sort_keys=True, separators=(',', ':')).encode())


def binary_identity(binary, commit, release, expected_digest):
    if digest(read(binary)) != expected_digest:
        raise ValueError('installed Cadence binary digest differs')
    identity = json.loads(subprocess.check_output([str(binary), 'version', '--json'], timeout=10))
    expected = dict(sourceRevision=commit, sourceModified=False,
                    releaseVersion=release, binarySha256=expected_digest)
    if (not isinstance(identity, dict) or identity.get('sourceModified') is not False
            or any(identity.get(k) != v for k, v in expected.items())):
        raise ValueError('Cadence binary/source/version identity differs')


def runtime_selection(root, commit):
    lock = load(root / 'tooling_lock.json')
    ref = lock.get('verifyRuntime')
    if (lock.get('standardManifestVersion') != '1.4.0' or not isinstance(ref, dict)
            or ref.get('kind') != 'git' or ref.get('pinType') != 'commit'
            or ref.get('floating') is not False or not isinstance(ref.get('uri'), str)
            or not ref['uri'].strip() or not isinstance(commit, str)
            or not re.fullmatch(r'[0-9a-f]{40}', commit) or ref.get('pinValue') != commit):
        raise ValueError('tooling_lock.json verifyRuntime must declare the selected fixed Git commit; '
                         'create with --runtime-commit or update the existing runtime declaration explicitly')
    return ref


def resource_path(root, name):
    if not isinstance(name, str) or not name or Path(name).is_absolute() or '..' in Path(name).parts:
        raise ValueError('invalid installed resource path')
    path = root
    for part in ('', *Path(name).parts):
        path = path / part
        if path.is_symlink():
            raise ValueError('linked runtime resource refused')
    return path


def record(root, base, commit, source):
    binary = base / '.cadence/bin/cadence'
    source_digest = source_identity(source, commit)
    release = read(source / 'VERSION').decode().strip()
    binary_digest = digest(read(binary))
    binary_identity(binary, commit, release, binary_digest)
    # Keep the same finite registry/resource closure as the 1.5 installer.
    # Compiler sources, fault fixtures and Git databases are build inputs only.
    names = ['cadence-registry/registry.json', 'VERSION', 'LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md']
    registry = load(source / names[0])
    if not registry.get('registryId') or not isinstance(registry.get('entries'), list):
        raise ValueError('native registry required')
    for entry in registry['entries']:
        path = source / 'cadence-registry' / entry['ref']
        if not path.resolve().is_relative_to(source.resolve()):
            raise ValueError('registry target escapes Cadence')
        name = str(path.resolve().relative_to(source.resolve()))
        if digest(read(resource_path(source, name))) != entry['digest']:
            raise ValueError('registry target digest differs: ' + entry['id'])
        names.append(name)
    resources = {}
    for name in sorted(set(names)):
        content = read(resource_path(source, name))
        destination = base / 'cadence-oss' / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        resources[name] = digest(content)
    data = dict(sourceCommit=commit, sourceDigest=source_digest,
                releaseVersion=release, binaryDigest=binary_digest,
                declaredRuntime=runtime_selection(root, commit), resourceDigests=resources)
    (base / '.dasops-install.json').write_text(json.dumps(data, indent=2) + '\n')


def installed(root):
    root = Path(root).resolve()
    base = root / 'vendor/cadence'
    for path in (root / 'vendor', base, base / '.cadence', base / '.cadence/bin'):
        if path.is_symlink():
            raise ValueError('linked Cadence installation refused')
    data = load(base / '.dasops-install.json')
    if data['declaredRuntime'] != runtime_selection(root, data['sourceCommit']):
        raise ValueError('product runtime declaration changed; reinstall explicitly')
    if not isinstance(data.get('resourceDigests'), dict) or not data['resourceDigests']:
        raise ValueError('runtime resource record missing; reinstall explicitly')
    for name, expected in data['resourceDigests'].items():
        if digest(read(resource_path(base / 'cadence-oss', name))) != expected:
            raise ValueError('installed Cadence resource differs: ' + name)
    binary = base / '.cadence/bin/cadence'
    binary_identity(binary, data['sourceCommit'], data['releaseVersion'], data['binaryDigest'])
    return binary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('select', 'record', 'run'))
    parser.add_argument('--repo-root', type=Path, required=True)
    parser.add_argument('--staged', type=Path)
    parser.add_argument('--commit')
    parser.add_argument('--source', type=Path)
    args, forwarded = parser.parse_known_args()
    if args.operation == 'select':
        if forwarded or args.staged is not None or args.source is not None or args.commit is None:
            parser.error('select requires --commit without other arguments')
        runtime_selection(args.repo_root, args.commit)
        return 0
    if args.operation == 'record':
        if forwarded or args.staged is None or args.commit is None or args.source is None:
            parser.error('record requires --staged, --source and --commit, without extra arguments')
        record(args.repo_root, args.staged, args.commit, args.source)
        return 0
    if args.staged is not None or args.source is not None or args.commit is not None or not forwarded or forwarded[0] != '--':
        parser.error('run requires -- followed by Cadence arguments')
    root = args.repo_root.resolve()
    if fcntl is None:
        raise ValueError('local Cadence execution requires Linux file locking')
    guard_dir = root / '.cadence/tmp'
    for path in (root / '.cadence', guard_dir):
        if path.is_symlink():
            raise ValueError('linked install guard refused')
    guard_dir.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(guard_dir/'install.guard', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'r+b') as guard:
        fcntl.flock(guard.fileno(), fcntl.LOCK_SH)
        binary = installed(root)
        print(f"cadencew: verified local runtime {binary}", file=sys.stderr)
        os.chdir(root)
        # Retain the read guard through native execution, so --force cannot
        # replace binary/resources between identity checking and consumption.
        os.set_inheritable(guard.fileno(), True)
        os.execv(str(binary), [str(binary), *forwarded[1:]])


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(f'Cadence installation check failed: {exc}', file=sys.stderr)
        raise SystemExit(1)
