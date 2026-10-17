"""Installed facts -> one native resolver -> read-only Bundle/Context Pack.

Only the service installer supplies loaders, authorization and executable pins.
An RPC body must never supply them. Control reads use short snapshots of the
same existing database, before and after native work. Loaders read precollected
originals, never network or candidate code. Resolving applicability grants no business action or conformance result.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import io
from importlib.resources import files
import json
import os
from pathlib import Path
import sys
import sqlite3
import stat
import tempfile
import time
import re
import unicodedata
import zipfile
import zlib

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

from dasops.bundle_preview import (CadenceDependencyError, _run, facts_binding,
                                  pin_native, validate_preview_response)
from dasops.standards_contracts import exact_json as codec
from dasops.protected.sqlite.store import CoordinationDatabase, CoordinationError


class BundleError(ValueError):
    pass


def _validate(name, value):
    schema = json.loads(files('dasops.standards_contracts').joinpath(name + '.schema.json').read_text())
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)


def _stamp(value):
    stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if stamp.tzinfo is None:
        raise BundleError('current control interval must include a timezone')
    return stamp


def _same_json(left, right):
    """Compare the already bounded original without reencoding large catalogs.

    Host types must agree: bool cannot equal an integer in current control.
    Recursion/width are bounded by the validated original, even for bad refresh.
    """
    if type(left) is not type(right): return False
    if isinstance(left, dict):
        return len(left) == len(right) and all(name in right and _same_json(value, right[name]) for name, value in left.items())
    if isinstance(left, list):
        return len(left) == len(right) and all(_same_json(a, b) for a, b in zip(left, right))
    return left == right


def _standard_path(value):
    if (not isinstance(value, str) or not 1 <= len(value.encode('utf-8')) <= 240
            or unicodedata.normalize('NFC', value) != value
            or any(char in value for char in '\\:')
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
            or len(value.split('/')) > 16
            or any(part in ('', '.', '..') for part in value.split('/'))):
        raise BundleError('noncanonical Standard member path')
    return value.split('/')


def _standard_member(root_fd, name, deadline):
    """Read data through directory handles; never execute package validators."""
    descriptor = os.dup(root_fd)
    try:
        parts = _standard_path(name)
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            os.close(descriptor); descriptor = child
            info = os.fstat(descriptor)
            if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
                raise BundleError('Standard member parent must be installer controlled')
        member = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=descriptor)
        try:
            before = os.fstat(member)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_uid not in (0, os.getuid()) or before.st_mode & 0o022
                    or before.st_size > codec.MAX_BYTES):
                raise BundleError('Standard member must be a bounded exclusive regular file')
            raw = bytearray()
            while len(raw) <= codec.MAX_BYTES:
                if time.clock_gettime(time.CLOCK_BOOTTIME) >= deadline:
                    raise BundleError('Standard content deadline expired')
                chunk = os.read(member, min(65536, codec.MAX_BYTES + 1 - len(raw)))
                if not chunk: break
                raw.extend(chunk)
            after = os.fstat(member)
            named = os.stat(parts[-1], dir_fd=descriptor, follow_symlinks=False)
            if (len(raw) != before.st_size or len(raw) > codec.MAX_BYTES
                    or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)
                    or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                raise BundleError('Standard member changed during consumption')
            return bytes(raw)
        finally: os.close(member)
    finally: os.close(descriptor)


def _standard_content(root, snapshot_sha256, standard_version, deadline, *, retain_sources=()):
    """Verify the existing non-circular content format against an installer pin.

    Approval, publication, semantic migration and activation stay separate. The
    root and exact RAW snapshot digest come only from the service installer.
    """
    if (root is None or not isinstance(snapshot_sha256, str)
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', snapshot_sha256)):
        raise BundleError('installed complete Standard root and snapshot pin required')
    root = Path(root)
    if not root.is_absolute() or root == root.parent or str(root) != os.path.normpath(str(root)):
        raise BundleError('normalized absolute Standard root required')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(root.anchor, flags)
    try:
        for part in root.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor); descriptor = child
        info = os.fstat(descriptor)
        if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
            raise BundleError('Standard root must be installer controlled')
        raw = _standard_member(descriptor, 'release_snapshot_manifest.json', deadline)
        if 'sha256:' + hashlib.sha256(raw).hexdigest() != snapshot_sha256:
            raise BundleError('Standard snapshot differs from installed raw-byte pin')
        snapshot = codec.parse(raw)
        codec.closed_object(snapshot, ['schemaVersion','standardVersion','standardManifestVersion','snapshotKind',
            'createdAt','buildRef','sourceRepoRef','bundleDigestAlgorithm','bundleDigest','artifacts','mirrorRules'], ['$schema'])
        if (snapshot['schemaVersion'] != '1.0.0' or snapshot['snapshotKind'] != 'standard_content_bundle'
                or snapshot['bundleDigestAlgorithm'] != 'sha256'
                or snapshot['standardVersion'] != standard_version
                or snapshot['standardManifestVersion'] != standard_version):
            raise BundleError('installed Standard content edition or format changed')
        entries = snapshot['artifacts']
        if not isinstance(entries, list) or not 1 <= len(entries) <= 2048:
            raise BundleError('bounded Standard content inventory required')
        paths = []
        total = len(raw)
        metadata = {}
        source_bytes = {}
        for entry in entries:
            codec.closed_object(entry, ['path','sha256','artifactClass','required'])
            name = entry['path']; _standard_path(name); paths.append(name)
            if (entry['required'] is not True or not isinstance(entry['sha256'], str)
                    or not re.fullmatch(r'[0-9a-f]{64}', entry['sha256'])
                    or entry['artifactClass'] not in ('normative','supporting','repo_metadata','schema','example','script','ci')):
                raise BundleError('invalid Standard content member declaration')
            data = _standard_member(descriptor, name, deadline)
            total += len(data)
            if total > 32 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != entry['sha256']:
                raise BundleError('Standard content member changed or exceeded total limit')
            if name in ('standard_manifest.json','standard_modules.json','standard_requirements.json','VERSION'):
                metadata[name] = data
            if name in retain_sources:
                source_bytes[name] = data
        if paths != sorted(set(paths)) or len({name.casefold() for name in paths}) != len(paths):
            raise BundleError('Standard content inventory must be unique and canonical')
        manifest = codec.parse(metadata['standard_manifest.json'])
        required = manifest['requiredArtifacts']
        if (not isinstance(required, list) or any(not isinstance(name, str) for name in required)
                or len(required) != len(set(required))
                or set(required) != set(paths) | {'release_snapshot_manifest.json'}
                or 'release_snapshot_manifest.json' in paths
                or manifest['standardVersion'] != standard_version
                or metadata['VERSION'].decode('utf-8').strip() != standard_version):
            raise BundleError('Standard manifest/version/member closure changed')
        joined = '\n'.join(f"{entry['path']}:{entry['sha256']}" for entry in entries).encode('utf-8')
        content_digest = hashlib.sha256(joined).hexdigest()
        if content_digest != snapshot['bundleDigest']:
            raise BundleError('Standard content digest changed')
        metadata['memberPaths'] = frozenset(paths)
        metadata['memberDigests'] = {entry['path']: entry['sha256'] for entry in entries}
        metadata['snapshotBytes'] = raw
        metadata['sourceBytes'] = source_bytes
        return dict(snapshotDigest=snapshot_sha256, contentDigest='sha256:' + content_digest), metadata
    finally: os.close(descriptor)


def _standard_distribution(archive, archive_sha256, members, deadline):
    """Bind one installed flat content ZIP to the already verified snapshot.

    This finite data-only profile supports stored/deflated regular members,
    exactly the declared content plus its raw snapshot. No extraction, package
    scripts, download, signature approval or activation occurs here. Archive,
    snapshot and logical content retain their separate digest domains.
    """
    path = Path(archive)
    if (not path.is_absolute() or str(path) != os.path.normpath(str(path))
            or not isinstance(archive_sha256, str)
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', archive_sha256)):
        raise BundleError('exact installed Standard distribution path and raw-byte pin required')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(path.anchor, flags)
    try:
        for part in path.parent.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor); descriptor = child
        info = os.fstat(descriptor)
        if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
            raise BundleError('Standard distribution parent must be installer controlled')
        raw = _standard_member(descriptor, path.name, deadline)
    finally: os.close(descriptor)
    if 'sha256:' + hashlib.sha256(raw).hexdigest() != archive_sha256:
        raise BundleError('Standard distribution differs from installed raw-byte pin')
    expected = dict(members['memberDigests'])
    expected['release_snapshot_manifest.json'] = hashlib.sha256(members['snapshotBytes']).hexdigest()
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zipped:
            entries = zipped.infolist()
            names = [entry.filename for entry in entries]
            if len(names) != len(expected) or len(set(names)) != len(names) or set(names) != set(expected):
                raise BundleError('Standard distribution must preserve the exact installed content closure')
            total = 0
            for entry in entries:
                _standard_path(entry.filename)
                mode = entry.external_attr >> 16
                if (entry.is_dir() or stat.S_IFMT(mode) not in (0, stat.S_IFREG)
                        or entry.flag_bits & ~0x808
                        or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                        or entry.file_size > codec.MAX_BYTES):
                    raise BundleError('unsupported Standard distribution member or size')
                total += entry.file_size
                if total > 32 * 1024 * 1024:
                    raise BundleError('Standard distribution exceeds installed content budget')
                digest = hashlib.sha256(); size = 0
                with zipped.open(entry) as stream:
                    while True:
                        if time.clock_gettime(time.CLOCK_BOOTTIME) >= deadline:
                            raise BundleError('Standard distribution deadline expired')
                        chunk = stream.read(min(65536, codec.MAX_BYTES + 1 - size))
                        if not chunk: break
                        size += len(chunk); digest.update(chunk)
                        if size > codec.MAX_BYTES:
                            raise BundleError('Standard distribution member exceeded content budget')
                if size != entry.file_size or digest.hexdigest() != expected[entry.filename]:
                    raise BundleError('Standard distribution member differs from installed snapshot')
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError, zlib.error) as exc:
        raise BundleError('invalid Standard content distribution ZIP') from exc
    return archive_sha256


def _standard_references(sources, references, deadline):
    """Cross-check catalog reading spans against already verified physical bytes.

    Text fragments use the author's Unicode-column/normalized-line hash domain;
    the enclosing files still use their separate exact physical-byte digests.
    All memoization is local to this bounded consumption, never an approval.
    """
    lines, checked = {}, set()
    for ref in references:
        if time.clock_gettime(time.CLOCK_BOOTTIME) >= deadline:
            raise BundleError('Standard source-reference deadline expired')
        path = ref['path']
        first, last, start, end = (ref[name] for name in
            ('startLine','endLine','startColumn','endColumn'))
        if path not in sources or any(type(value) is not int for value in (first,last,start,end)):
            raise BundleError('Standard source reference lacks its physical author or exact span')
        if path not in lines:
            lines[path] = sources[path].decode('utf-8').splitlines()
        key = (path,first,last,start,end,ref['textSha256'])
        if key in checked:
            continue
        if not 1 <= first <= last <= len(lines[path]):
            raise BundleError('Standard source reference has invalid physical line range')
        text = '\n'.join(lines[path][first-1:last])
        if not 0 <= start < end <= len(text):
            raise BundleError('Standard source reference has invalid Unicode column range')
        if hashlib.sha256(text[start:end].encode('utf-8')).hexdigest() != ref['textSha256']:
            raise BundleError('Standard source reference differs from its physical normative author')
        checked.add(key)


class NativeBundleResolver:
    """Install once; every resolve rechecks real actor, target, epoch and time.

    ``load_control(connection, actor, epoch, scope, target)`` reads a short
    read-only snapshot of the existing database and returns the existing
    signed-facts input. ``authorize`` has the same arguments and returns True
    only for a real authenticated reader. Neither is supplied per request.
    Returned applicability can remain unknown; complete mapping alone grants no action authority.
    ``standard_root`` and the raw ``snapshot_sha256`` are independent installer
    inputs. Missing pins always reject resolve; no request or same-version
    catalog can select the physical Standard. Member hashes are read twice,
    before/after native work, within the original total deadline.
    """

    def __init__(self, *, binary, binary_sha256, release_version, load_control,
                 authorize, standard_root=None, snapshot_sha256=None, timeout=5,
                 standard_archive=None, standard_archive_sha256=None):
        if (sys.platform != 'linux' or not Path(binary).is_absolute()
                or not callable(load_control) or not callable(authorize)
                or not isinstance(release_version, str) or not 0 < len(release_version) <= 128
                or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not 0 < timeout <= 5):
            raise BundleError('installed Linux consumer, current control and bounded deadline required')
        if (standard_archive is None) != (standard_archive_sha256 is None):
            raise BundleError('Standard distribution path and exact pin must be installed together')
        if standard_archive is not None and (not Path(standard_archive).is_absolute()
                or not isinstance(standard_archive_sha256, str)
                or not re.fullmatch(r'sha256:[0-9a-f]{64}', standard_archive_sha256)):
            raise BundleError('exact installed Standard distribution path and raw-byte pin required')
        # canonical exact digest spelling; no path/version inference.
        if not isinstance(binary_sha256, str) or len(binary_sha256) != 71:
            raise BundleError('exact installed binary digest required')
        self.fd = None
        try:
            self.fd = pin_native(binary, binary_sha256, release_version, timeout)
        except CadenceDependencyError as exc:
            raise BundleError('installed Bundle consumer unavailable') from exc
        self.binary_sha256, self.release_version = binary_sha256, release_version
        self.load_control, self.authorize, self.timeout = load_control, authorize, timeout
        self.standard_root, self.snapshot_sha256 = standard_root, snapshot_sha256
        self._distribution = (standard_archive, standard_archive_sha256) if standard_archive is not None else None
        self._prepared_confirmation = None

    @property
    def standard_artifact_digest(self):
        """Installer's artifact subject, or the explicit development snapshot profile."""
        return self._distribution[1] if self._distribution is not None else self.snapshot_sha256

    def _content(self, standard_version, deadline, **kwargs):
        ref, members = _standard_content(self.standard_root, self.snapshot_sha256,
            standard_version, deadline, **kwargs)
        if self._distribution is not None:
            _standard_distribution(*self._distribution, members, deadline)
        return ref, members

    def close(self):
        self._prepared_confirmation = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def confirm_current(self, connection, bundle, *, actor, epoch, remaining):
        """Confirm the latest verified preparation at the action transaction.

        Exact original bytes, trust and current bindings must still match the
        native-verified preparation. Observation times are freshly checked.
        Changed originals require preparation again outside the writer; no
        stale allow or second evaluator is used. One in-memory preparation is
        retained, scoped by its entire record; it is never durable authority.
        """
        if (self.fd is None or not connection.in_transaction or isinstance(remaining, bool)
                or not 0 < remaining <= self.timeout or self._prepared_confirmation is None):
            raise BundleError('current transaction and live bounded Bundle preparation required')
        prepared, original, payload = self._prepared_confirmation
        if not _same_json(prepared, bundle) or bundle['status'] != 'resolved':
            raise BundleError('adoption does not match the latest verified preparation')
        deadline = time.clock_gettime(time.CLOCK_BOOTTIME) + remaining
        changes = connection.total_changes
        metadata = dict(connection.execute('SELECT authority_domain,authority_epoch FROM metadata WHERE singleton=1').fetchone())
        scope, target = bundle['scope'], deepcopy(bundle['target'])
        if (metadata['authority_domain'] != bundle['current']['authorityDomain']
                or metadata['authority_epoch'] != epoch or bundle['current']['authorityEpoch'] != epoch
                or self.authorize(connection, actor, epoch, scope, deepcopy(target)) is not True):
            raise BundleError('current adoption reader or authority changed')
        request = deepcopy(self.load_control(connection, actor, epoch, scope, deepcopy(target)))
        if connection.total_changes != changes:
            raise BundleError('current Bundle loader must not write inside the action transaction')
        # Only three observation fields can change. Envelope/payload bytes,
        # all keys/principals/roles/thresholds, issuer, current revocations,
        # generations, policy, actor, scope, target and full catalogs stay exact.
        # _same_json also refuses bool/integer and other scalar reinterpretation.
        current = request['controlContext']
        refreshed = deepcopy(request)
        for name in ('earliest', 'latest', 'observedAt'):
            refreshed['controlContext'][name] = original['controlContext'][name]
        if not _same_json(original, refreshed):
            raise BundleError('current facts/trust/policy differ from verified preparation')
        _validate('approved_facts_preview_input', request)
        earliest, latest, observed = (_stamp(current[name]) for name in ('earliest', 'latest', 'observedAt'))
        now = datetime.now(timezone.utc)
        rest = deadline - time.clock_gettime(time.CLOCK_BOOTTIME)
        if (rest <= 0 or not earliest <= now < latest or observed > earliest
                or (latest-observed).total_seconds() > codec.safe_integer(current['maxStalenessSeconds'])
                or earliest < _stamp(payload['notBefore']) or latest >= _stamp(payload['expiresAt'])
                or (latest-now).total_seconds() < rest):
            raise BundleError('current adoption interval cannot cover its action deadline')
        standard_ref, _ = self._content(payload['standardVersion'], deadline)
        if (standard_ref != bundle['standardRef'] or self.binary_sha256 != bundle['resolver']['binarySha256']
                or self.release_version != bundle['resolver']['releaseVersion']):
            raise BundleError('adoption Standard content or installed resolver changed')
        if (time.clock_gettime(time.CLOCK_BOOTTIME) >= deadline or not earliest <= datetime.now(timezone.utc) < latest):
            raise BundleError('adoption confirmation expired before its action')

    def resolve(self, database, *, actor, epoch, scope, target, retain_preparation=True):
        # An authenticated reading view must not replace an action's exact
        # preparation. This flag is an installed consumer choice, not an RPC.
        if type(retain_preparation) is not bool:
            raise BundleError('explicit preparation-retention boolean required')
        if retain_preparation:
            self._prepared_confirmation = None
        if self.fd is None or not isinstance(database, CoordinationDatabase) or database.connection.in_transaction:
            raise BundleError('installed consumer and read preparation before writer required')
        started = time.clock_gettime(time.CLOCK_BOOTTIME)
        try:
            epoch = codec.safe_integer(epoch)
            target = codec.parse(codec.canonical(target))
            with database.read_snapshot() as connection:
                metadata = dict(connection.execute('SELECT authority_domain,authority_epoch FROM metadata WHERE singleton=1').fetchone())
                if (epoch != metadata['authority_epoch']
                        or self.authorize(connection, actor, epoch, scope, deepcopy(target)) is not True):
                    raise BundleError('current authenticated Bundle reader is not authorized')
                original = deepcopy(self.load_control(connection, actor, epoch, scope, deepcopy(target)))
            encoded = codec.canonical_catalog(original)
            request = codec.parse_catalog(encoded)
            proposal, payload, raw_payload = facts_binding(request)
            source_paths = {name for module in request['catalog']['modules']
                for field in ('normativeSources','requiredArtifactRefs') for name in module[field]}
            references = []
            for row in request['requirementsCatalog']['requirements'] + request['requirementsCatalog']['editionRequirements']:
                for field in ('strengthRef','bodyRefs','contextRefs','conditionRefs'):
                    refs = row.get(field, [])
                    references.extend(refs if isinstance(refs, list) else [refs])
            source_paths.update(ref['path'] for ref in references)
            standard_ref, standard_bytes = self._content(payload['standardVersion'], started + self.timeout,
                retain_sources={ref['path'] for ref in references})
            for field, name in (('catalog','standard_modules.json'), ('requirementsCatalog','standard_requirements.json')):
                if request[field] != codec.parse_catalog(standard_bytes[name]):
                    raise BundleError('approved facts catalog differs from installed Standard content')
            if not source_paths <= standard_bytes['memberPaths']:
                raise BundleError('Standard catalog references content outside its physical member closure')
            _standard_references(standard_bytes['sourceBytes'], references, started + self.timeout)
            current = request['controlContext']
            if (current['callerPrincipal'] != actor or current['scope'] != scope
                    or current['target'] != target or current['policyRef']['authorityEpoch'] != epoch):
                raise BundleError('installed facts context does not bind the actual actor/epoch/scope/target')
            earliest, latest = _stamp(current['earliest']), _stamp(current['latest'])
            now = datetime.now(timezone.utc)
            remaining = self.timeout - (time.clock_gettime(time.CLOCK_BOOTTIME) - started)
            if earliest > now or remaining <= 0 or (latest - now).total_seconds() < remaining:
                raise BundleError('current interval cannot cover bounded native resolution')
            with tempfile.TemporaryDirectory(prefix='das-current-bundle-') as directory:
                remaining = self.timeout - (time.clock_gettime(time.CLOCK_BOOTTIME) - started)
                if remaining <= 0:
                    raise BundleError('Bundle deadline expired before native consumption')
                checked = codec.parse(_run(self.fd, ['resolve', '--check-facts-refs'], encoded, directory, remaining))
            _validate('approved_facts_check_v2', checked)
            resolution = validate_preview_response(proposal, checked['preview'])
            refs = checked['checkedRefs']
            normalized_payload = dict(payload, facts=sorted(payload['facts'], key=lambda fact: (fact['key'], fact['sourceRef'])))
            if (refs['envelopeDigest'] != codec.digest(request['factsEnvelope'])
                    or refs['payloadDigest'] != codec.digest(payload)
                    or refs['approvedFactsDigest'] != codec.digest(normalized_payload)
                    or refs['payloadBytesDigest'] != 'sha256:' + hashlib.sha256(raw_payload).hexdigest()
                    or refs['controlContextDigest'] != codec.digest(current)
                    or actor in refs['principals']
                    or len(refs['principals']) < codec.safe_integer(current['threshold'])
                    or len(refs['keyFingerprints']) < codec.safe_integer(current['threshold'])):
                raise BundleError('native approval references changed or lost independent threshold')
            # A loader that changes current references while native work runs
            # cannot bless its older result. Original inputs remain immutable.
            with database.read_snapshot() as connection:
                refreshed_metadata = dict(connection.execute('SELECT authority_domain,authority_epoch FROM metadata WHERE singleton=1').fetchone())
                if (refreshed_metadata != metadata
                        or self.authorize(connection, actor, epoch, scope, deepcopy(target)) is not True):
                    raise BundleError('installed current epoch or reader changed during resolution')
                refreshed = deepcopy(self.load_control(connection, actor, epoch, scope, deepcopy(target)))
            if not _same_json(original, refreshed):
                raise BundleError('installed current facts/policy/trust changed during resolution')
            current_standard, _ = self._content(payload['standardVersion'], started + self.timeout)
            if current_standard != standard_ref:
                raise BundleError('installed Standard content changed during resolution')
            if (time.clock_gettime(time.CLOCK_BOOTTIME) - started >= self.timeout
                    or not earliest <= datetime.now(timezone.utc) < latest):
                raise BundleError('Bundle current validity expired before consumption')
            strengths = {leaf['id']: leaf['strength'] for leaf in
                request['requirementsCatalog']['requirements'] + request['requirementsCatalog']['editionRequirements']}
            unresolved = (resolution['unresolvedModules'] or any(
                row['state'] in ('unknown', 'conflict') and strengths[row['requirementId']] == 'MUST'
                for row in resolution['requirementTrace']))
            status = ('migration_incomplete' if not resolution['leafMigrationComplete']
                      else 'unresolved' if unresolved else 'resolved')
            bundle = dict(contractIdentity='das-bundle-resolution/v2', scope=scope,
                standardVersion=payload['standardVersion'], standardRef=standard_ref, policyRef=payload['policyRef'], target=target,
                factsRef=dict(factsId=payload['factsId'], factsGeneration=payload['factsGeneration'], **refs),
                current=dict(authorityDomain=metadata['authority_domain'], authorityEpoch=epoch,
                    **{name: current[name] for name in ('earliest', 'latest', 'observedAt')}),
                resolver=dict(binarySha256=self.binary_sha256, releaseVersion=self.release_version),
                resolution=resolution, authorityVerified=True, qualificationEligible=False,
                status=status, digestMethod=codec.DIGEST_METHOD)
            bundle['bundleDigest'] = codec.digest(bundle_subject(bundle))
            bundle['recordDigest'] = codec.digest(bundle)
            _validate('bundle_resolution_v2' if bundle.get('contractIdentity') == 'das-bundle-resolution/v2' else 'bundle_resolution', bundle)
            if (time.clock_gettime(time.CLOCK_BOOTTIME) - started >= self.timeout
                    or not earliest <= datetime.now(timezone.utc) < latest):
                raise BundleError('current epoch or validity changed before returning the Bundle')
            if retain_preparation:
                self._prepared_confirmation = (deepcopy(bundle), deepcopy(original), deepcopy(payload)) if status == 'resolved' else None
            return bundle, request['requirementsCatalog']
        except BundleError:
            raise
        except (OSError, ValueError, TypeError, KeyError, AttributeError, ValidationError, sqlite3.Error, CoordinationError) as exc:
            # No tolerant parse, last-known allow, empty success or source text
            # normalization can replace a failed native/current check.
            raise BundleError('current approved facts resolution rejected') from exc


def bundle_subject(bundle):
    """Stable approved input/resolver/result identity, without observation evidence.

    recordDigest covers the entire current record. Neither hash is authority;
    the adoption consumer always recomputes current installed verification.
    """
    subject = {name: bundle[name] for name in (
        'contractIdentity', 'scope', 'standardVersion', 'policyRef', 'target',
        'resolver', 'resolution', 'status', 'digestMethod')} | {
        'authorityDomain': bundle['current']['authorityDomain'],
        'factsRef': {name: bundle['factsRef'][name] for name in ('factsId', 'factsGeneration', 'approvedFactsDigest')}}
    if 'standardRef' in bundle: subject['standardRef'] = bundle['standardRef']
    return subject


def context_pack(bundle, requirements):
    """Generate only a reading view. False rows remain in the full audit trace.

    This function checks content integrity, not installed authority. Governed
    adoption must obtain/recompute the Bundle through NativeBundleResolver.
    """
    try:
        _validate('bundle_resolution_v2' if bundle.get('contractIdentity') == 'das-bundle-resolution/v2' else 'bundle_resolution', bundle)
        subject = dict(bundle)
        record_digest = subject.pop('recordDigest')
        received = bundle['bundleDigest']
        if record_digest != codec.digest(subject) or received != codec.digest(bundle_subject(bundle)):
            raise BundleError('Bundle or current record digest changed')
        resolution = bundle['resolution']
        preview_subject = dict(resolution)
        preview_digest = preview_subject.pop('previewDigest')
        if preview_digest != codec.digest(preview_subject):
            raise BundleError('Context Pack native resolution digest changed')
        if (resolution['scope'] != bundle['scope'] or resolution['standardVersion'] != bundle['standardVersion']
                or resolution['policyDigest'] != bundle['policyRef']['policyDigest']
                or bundle['current']['authorityEpoch'] != bundle['policyRef']['authorityEpoch']
                or (resolution['leafMigrationComplete'] is False and bundle['status'] != 'migration_incomplete')):
            raise BundleError('Context Pack Bundle bindings or migration status changed')
        if codec.digest_catalog(requirements) != resolution['requirementsCatalogDigest']:
            raise BundleError('Context Pack belongs to a different requirement catalog')
        leaves = {leaf['id']: leaf for leaf in requirements['requirements'] + requirements['editionRequirements']}
        trace = resolution['requirementTrace']
        if len(leaves) != len(requirements['requirements']) + len(requirements['editionRequirements']) or [r['requirementId'] for r in trace] != sorted(leaves):
            raise BundleError('Context Pack lost, repeated or reordered the full leaf denominator')
        obligations = []
        for row in trace:
            leaf = leaves[row['requirementId']]
            if row['ownerModule'] != leaf['ownerModule'] or row['parentClause'] != leaf['parentClause']:
                raise BundleError('Context Pack changed requirement ownership or parent')
            if row['state'] != 'false':
                obligations.append(dict(**row, strength=leaf['strength'], strengthRef=leaf['strengthRef'], bodyRefs=leaf['bodyRefs'],
                    contextRefs=leaf['contextRefs'], conditionRefs=leaf.get('conditionRefs', [])))
        pack = dict(contractIdentity=('das-context-pack/v2' if bundle['contractIdentity'] == 'das-bundle-resolution/v2' else 'das-context-pack/v1'), scope=bundle['scope'],
            standardVersion=bundle['standardVersion'], bundleDigest=received,
            policyRef=bundle['policyRef'], target=bundle['target'],
            catalogDigest=resolution['catalogDigest'], requirementsCatalogDigest=resolution['requirementsCatalogDigest'],
            resolvedModules=resolution['resolvedModules'], requirementTrace=trace, obligations=obligations,
            status=bundle['status'], authorityVerified=False, qualificationEligible=False,
            digestMethod=codec.DIGEST_METHOD)
        pack['contextPackDigest'] = codec.digest_catalog(pack)
        _validate('context_pack_v2' if pack['contractIdentity'] == 'das-context-pack/v2' else 'context_pack', pack)
        return codec.parse_catalog(codec.canonical_catalog(pack))
    except BundleError:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError, ValidationError, sqlite3.Error, CoordinationError) as exc:
        raise BundleError('Context Pack generation rejected') from exc
