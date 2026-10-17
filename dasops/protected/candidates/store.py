"""Bounded, no-execution reception of a complete committed Git tree.

The installed service supplies the private storage root and limits. Requests
cannot choose an output path, executable, Git config, decoder or plugin. Git
object/tree identity is reconstructed from the received bytes without invoking
Git or applying checkout/archive attributes. This is a staging kernel: the
importer's OS boundary, approved task/material selection, Worker exclusion and
independent durability checkpoints still belong to service activation.
"""
from __future__ import annotations

from dataclasses import dataclass
from importlib.resources import files
import ctypes
import errno
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import tarfile
import time
import unicodedata
import zlib

from jsonschema import Draft202012Validator, validators

from dasops.standards_contracts import exact_json as codec

SCHEMA = json.loads(files('dasops.standards_contracts').joinpath('candidate_binding.schema.json').read_text())
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
CONTROL_FILES = {'binding.json', 'commit.bin', 'archive.bin'}
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class CandidateError(RuntimeError):
    pass


@dataclass(frozen=True)
class CandidateLimits:
    # Deployment may choose smaller limits, never expand this wire contract.
    max_manifest_bytes: int = 1_048_576
    max_archive_bytes: int = 83_886_080
    max_file_bytes: int = 16_777_216
    max_total_bytes: int = 67_108_864
    max_files: int = 2048
    max_depth: int = 16
    seconds: int = 10

    def validate(self):
        ceiling = CandidateLimits()
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= getattr(ceiling, name):
                raise CandidateError('invalid installed candidate limit: ' + name)
        if not hasattr(time, 'CLOCK_BOOTTIME'):
            raise CandidateError('Linux boot-time deadline is required')


def _hash(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _git_hash(kind, raw, object_format):
    return hashlib.new(object_format, f'{kind} {len(raw)}\0'.encode('ascii') + raw).hexdigest()


def _integer(_, value):
    try:
        codec.safe_integer(value)
        return True
    except ValueError:
        return False


VALIDATOR = validators.extend(Draft202012Validator, type_checker=
    Draft202012Validator.TYPE_CHECKER.redefine('integer', _integer))(SCHEMA)


def _path(value, limits):
    if not isinstance(value, str):
        raise CandidateError('path must be a UTF-8 string')
    try:
        encoded = value.encode('utf-8', 'strict')
    except UnicodeError as exc:
        raise CandidateError('invalid UTF-8 path') from exc
    parts = value.split('/')
    if (not 1 <= len(encoded) <= 240 or len(parts) > limits.max_depth
            or unicodedata.normalize('NFC', value) != value
            or any(char in value for char in '\\:') or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise CandidateError('noncanonical or over-limit candidate path')
    for part in parts:
        stem = part.split('.')[0].casefold()
        if (not part or part in ('.', '..') or part.endswith(('.', ' ')) or part.casefold() == '.git'
                or stem in {'con', 'prn', 'aux', 'nul', *(f'com{i}' for i in range(1, 10)), *(f'lpt{i}' for i in range(1, 10))}):
            raise CandidateError('unsafe candidate path component')
    return parts


def validate_binding(raw, limits):
    if not isinstance(raw, bytes) or len(raw) > limits.max_manifest_bytes:
        raise CandidateError('candidate manifest byte limit')
    try:
        value = codec.parse(raw)
        VALIDATOR.validate(value)
        value['taskRevision'] = codec.safe_integer(value['taskRevision'])
        value['taskCycle'] = codec.safe_integer(value['taskCycle'])
        for item in [*value['files'], *value['externalMaterials']]:
            item['size'] = codec.safe_integer(item['size'])
    except Exception as exc:
        # JSON/schema rejection never falls through to a tolerant legacy reader.
        raise CandidateError('invalid exact candidate binding') from exc
    digests = [value['obligationDigest'], value['policyDigest'], value['source']['commitContentSha256'],
               value['archive']['rawSha256'], value['archive']['decodedSha256']]
    digests += [item['contentSha256'] for item in [*value['files'], *value['externalMaterials']]]
    if any(not DIGEST.fullmatch(digest) for digest in digests):
        raise CandidateError('digest spelling must be exact, without suffix or newline')
    oid_length = 40 if value['source']['objectFormat'] == 'sha1' else 64
    if any(len(value['source'][name]) != oid_length for name in ('commitOid', 'treeOid')):
        raise CandidateError('source object format/identity mismatch')
    inventory = value['files']
    if len(inventory) > limits.max_files or [item['path'] for item in inventory] != sorted(item['path'] for item in inventory):
        raise CandidateError('candidate files must have bounded canonical order')
    nodes = {}
    for item in inventory:
        parts = _path(item['path'], limits)
        if len(item['blobOid']) != oid_length or item['size'] > limits.max_file_bytes:
            raise CandidateError('blob identity or size exceeds the installed contract')
        for count in range(1, len(parts) + 1):
            path = '/'.join(parts[:count])
            key = path.casefold()
            kind = 'file' if count == len(parts) else 'directory'
            prior = nodes.get(key)
            if prior is not None and (prior != (path, kind) or kind == 'file'):
                raise CandidateError('duplicate, colliding or file/directory candidate path')
            nodes[key] = (path, kind)
    materials = value['externalMaterials']
    identifiers = [item['materialId'] for item in materials]
    if identifiers != sorted(set(identifiers)) or len({name.casefold() for name in identifiers}) != len(identifiers):
        raise CandidateError('external material IDs must be unique and ordered')
    for name in identifiers:
        _path(name, limits)
    if any(item['size'] > limits.max_file_bytes for item in materials):
        raise CandidateError('external material exceeds the installed byte limit')
    if sum(item['size'] for item in [*inventory, *materials]) > limits.max_total_bytes:
        raise CandidateError('cumulative candidate material byte limit')
    canonical = codec.canonical(value)
    if len(canonical) > limits.max_manifest_bytes:
        raise CandidateError('canonical candidate manifest byte limit')
    return value, canonical


def _deadline(limits):
    return time.clock_gettime(time.CLOCK_BOOTTIME) + limits.seconds


def _check_time(deadline):
    if time.clock_gettime(time.CLOCK_BOOTTIME) >= deadline:
        raise CandidateError('cumulative candidate reception deadline')


def _decode(raw, record, limits, deadline):
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= limits.max_archive_bytes or _hash(raw) != record['rawSha256']:
        raise CandidateError('raw archive limit or byte-domain digest mismatch')
    _check_time(deadline)
    if record['encoding'] == 'tar-ustar':
        decoded = raw
    else:
        # Exactly one gzip member, including verified CRC/ISIZE and complete EOF.
        # No library auto-decoding, concatenated members, ignored trailer or
        # unbounded decompress() allocation is accepted.
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        output = bytearray()
        try:
            for offset in range(0, len(raw), 65536):
                _check_time(deadline)
                chunk = raw[offset:offset + 65536]
                while chunk:
                    expanded = decoder.decompress(chunk, min(65536, limits.max_archive_bytes + 1 - len(output)))
                    output.extend(expanded)
                    if len(output) > limits.max_archive_bytes:
                        raise CandidateError('expanded archive byte limit')
                    if decoder.eof:
                        if decoder.unused_data or offset + 65536 < len(raw):
                            raise CandidateError('trailing or concatenated gzip member')
                        break
                    chunk = decoder.unconsumed_tail
                    _check_time(deadline)
        except zlib.error as exc:
            raise CandidateError('invalid gzip archive trailer or stream') from exc
        if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            raise CandidateError('incomplete gzip stream')
        decoded = bytes(output)
    if len(decoded) > limits.max_archive_bytes or _hash(decoded) != record['decodedSha256']:
        raise CandidateError('decoded archive limit or byte-domain digest mismatch')
    return decoded


def _cstring(raw):
    value, separator, padding = raw.partition(b'\0')
    if separator and any(padding):
        raise CandidateError('noncanonical USTAR string padding')
    return value


def _octal(raw):
    # Base-256, signs and alternate numeric dialects are not this contract.
    text = raw.rstrip(b'\0 ').lstrip(b' ')
    if not text:
        return 0
    if any(char not in b'01234567' for char in text):
        raise CandidateError('unsupported USTAR numeric encoding')
    return int(text, 8)


def _archive_files(raw, binding, limits, deadline):
    decoded = _decode(raw, binding['archive'], limits, deadline)
    if len(decoded) % 512:
        raise CandidateError('truncated USTAR block')
    inventory = {item['path']: item for item in binding['files']}
    received = {}
    offset = 0
    consumed = 0
    while offset + 512 <= len(decoded):
        _check_time(deadline)
        header = decoded[offset:offset + 512]
        offset += 512
        if not any(header):
            if len(decoded) - offset < 512 or any(decoded[offset:]):
                raise CandidateError('missing USTAR terminator or nonzero trailing data')
            if set(received) != set(inventory):
                raise CandidateError('archive omits required committed-tree files')
            return received
        if header[257:265] != b'ustar\00000' or any(header[500:512]):
            raise CandidateError('only complete USTAR regular-file members are supported')
        if _octal(header[148:156]) != sum(header[:148]) + 8 * 32 + sum(header[156:]):
            raise CandidateError('USTAR header checksum mismatch')
        if header[156:157] not in (b'0', b'\0') or _cstring(header[157:257]):
            raise CandidateError('archive links, directories and special/extension members are forbidden')
        if _octal(header[329:337]) or _octal(header[337:345]):
            raise CandidateError('archive device numbers are forbidden')
        _octal(header[108:116]); _octal(header[116:124]); _octal(header[136:148])
        _cstring(header[265:297]); _cstring(header[297:329])
        name = _cstring(header[:100])
        prefix = _cstring(header[345:500])
        try:
            path = (prefix + b'/' + name if prefix else name).decode('utf-8', 'strict')
        except UnicodeError as exc:
            raise CandidateError('archive path must be strict UTF-8') from exc
        _path(path, limits)
        item = inventory.get(path)
        size = _octal(header[124:136])
        mode = _octal(header[100:108])
        if (item is None or path in received or size != item['size'] or size > limits.max_file_bytes
                or mode != (0o755 if item['mode'] == '100755' else 0o644)):
            raise CandidateError('duplicate, undeclared or mismatched archive member')
        end = offset + size
        padded_end = end + (-size % 512)
        consumed += size
        if padded_end > len(decoded) or consumed > limits.max_total_bytes or any(decoded[end:padded_end]):
            raise CandidateError('truncated, over-limit or noncanonical archive content')
        content = decoded[offset:end]
        if (_hash(content) != item['contentSha256'] or
                _git_hash('blob', content, binding['source']['objectFormat']) != item['blobOid']):
            raise CandidateError('archive content does not match the pinned Git blob and SHA-256')
        if content.startswith(b'version https://git-lfs.github.com/spec/v1\n'):
            raise CandidateError('unexpanded LFS pointer requires a separately approved material mapping')
        received[path] = content
        offset = padded_end
    raise CandidateError('archive has no complete two-block terminator')


def _tree_oid(inventory, object_format):
    root = {}
    for item in inventory:
        cursor = root
        parts = item['path'].split('/')
        for part in parts[:-1]:
            cursor = cursor.setdefault(part, {})
        cursor[parts[-1]] = (item['mode'], item['blobOid'])

    def encode(directory):
        entries = []
        for name, item in directory.items():
            encoded = name.encode('utf-8')
            if isinstance(item, tuple):
                mode, oid = item
                suffix = b'\0'
            else:
                mode, oid, suffix = '40000', encode(item), b'/'
            entries.append((encoded + suffix, mode.encode() + b' ' + encoded + b'\0' + bytes.fromhex(oid)))
        return _git_hash('tree', b''.join(entry[1] for entry in sorted(entries)), object_format)

    return encode(root)


def _commit(raw, binding):
    source = binding['source']
    if (not isinstance(raw, bytes) or not 1 <= len(raw) <= 262144
            or _hash(raw) != source['commitContentSha256']
            or _git_hash('commit', raw, source['objectFormat']) != source['commitOid']):
        raise CandidateError('commit content or exact object identity mismatch')
    headers, separator, _ = raw.partition(b'\n\n')
    lines = headers.split(b'\n')
    expected = ('tree ' + source['treeOid']).encode()
    if (not separator or lines[0] != expected or any(line.startswith(b'tree ') for line in lines[1:])
            or _tree_oid(binding['files'], source['objectFormat']) != source['treeOid']):
        raise CandidateError('complete committed Git tree closure mismatch')


def _integration_entries(binding):
    return {**{'tree/'+item['path']:item for item in binding['files']},
            **{'materials/'+item['materialId']:item for item in binding['externalMaterials']}}


def _integration_commit(before_digest, before, source_digest, source, entries):
    """Fixed data-only whole-file merge; never invoke Git or candidate hooks."""
    if before['source']['objectFormat'] != source['source']['objectFormat']:
        raise CandidateError('integration inputs use different Git object formats')
    tree = _tree_oid([item for path,item in entries.items() if path.startswith('tree/')], source['source']['objectFormat'])
    raw = (f"tree {tree}\nparent {before['source']['commitOid']}\nparent {source['source']['commitOid']}\n"
           'author DAS Integration <integration@local> 0 +0000\n'
           'committer DAS Integration <integration@local> 0 +0000\n\n'
           f'DAS whole-file integration v1\nB {before_digest}\nC {source_digest}\n').encode('ascii')
    return tree, raw


def _private_directory(path):
    requested = Path(path)
    if not requested.is_absolute() or str(requested) != str(path) or any(part in ('.', '..') for part in str(path).split('/')):
        raise CandidateError('installed storage root must be a normalized absolute directory')
    descriptor = os.open('/', DIRECTORY_FLAGS)
    try:
        for part in requested.parts[1:]:
            child = os.open(part, DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise CandidateError('installed storage root must be private and owner controlled')
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _identity(descriptor):
    info = os.fstat(descriptor)
    return info.st_dev, info.st_ino


def _directory_version(descriptor):
    info = os.fstat(descriptor)
    return info.st_mode, info.st_uid, info.st_nlink, info.st_mtime_ns, info.st_ctime_ns


def _check_directory_version(descriptor, previous):
    if _directory_version(descriptor) != previous:
        raise CandidateError('stored directory changed during verification')


def _check_directory_name(parent, name, descriptor):
    actual = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (actual.st_dev, actual.st_ino) != _identity(descriptor):
        raise CandidateError('stored directory was replaced during verification')


def _read_file(directory, name, maximum, deadline=None):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid()
                or info.st_size > maximum or stat.S_IMODE(info.st_mode) not in (0o400, 0o500)):
            raise CandidateError('stored file is not a sealed, exclusive regular object')
        data = bytearray()
        while len(data) <= maximum:
            if deadline is not None:
                _check_time(deadline)
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
        actual = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (len(data) > maximum or len(data) != info.st_size or
                (actual.st_dev, actual.st_ino) != (info.st_dev, info.st_ino) or
                (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise CandidateError('stored file changed or exceeded its byte limit')
        return bytes(data), stat.S_IMODE(info.st_mode)
    finally:
        os.close(descriptor)


def _write_file(directory, name, content, executable=False, deadline=None, readable=False):
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=directory)
    try:
        view = memoryview(content)
        while view:
            if deadline is not None:
                _check_time(deadline)
            written = os.write(descriptor, view[:65536])
            if written <= 0:
                raise CandidateError('artifact write made no progress')
            view = view[written:]
        os.fchmod(descriptor, (0o555 if executable else 0o444) if readable else (0o500 if executable else 0o400))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _mkdir(directory, name):
    os.mkdir(name, 0o700, dir_fd=directory)
    return os.open(name, DIRECTORY_FLAGS, dir_fd=directory)


def _write_tree(directory, inventory, content, deadline, readable=False):
    # Keep O(depth) open handles, rather than one per directory in a legal tree.
    # Holding the whole inventory can exhaust the service's descriptor budget.
    trie = {}
    for item in inventory:
        cursor = trie
        parts = item['path'].split('/')
        for part in parts[:-1]:
            cursor = cursor.setdefault(part, {})
        cursor[parts[-1]] = (item['path'], item['mode'])

    def write(descriptor, entries):
        for name, item in entries.items():
            _check_time(deadline)
            if isinstance(item, tuple):
                _write_file(descriptor, name, content[item[0]], item[1] == '100755', deadline, readable)
            else:
                child = _mkdir(descriptor, name)
                try:
                    write(child, item)
                finally:
                    os.close(child)
        os.fchmod(descriptor, 0o555 if readable else 0o500)
        os.fsync(descriptor)
    write(directory, trie)


def _rename_absent(directory, source, target):
    # Linux RENAME_NOREPLACE publishes a whole prepared tree and cannot replace
    # even an empty competing directory. A check followed by os.rename is unsafe.
    library = ctypes.CDLL(None, use_errno=True)
    operation = getattr(library, 'renameat2', None)
    if operation is None:
        raise CandidateError('atomic no-replace directory publication is unavailable')
    operation.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    operation.restype = ctypes.c_int
    if operation(directory, os.fsencode(source), directory, os.fsencode(target), 1) != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            return False
        raise OSError(error, 'atomic candidate publication failed')
    return True


def _directory(directory, name):
    descriptor = os.open(name, DIRECTORY_FLAGS, dir_fd=directory)
    info = os.fstat(descriptor)
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o500:
        os.close(descriptor)
        raise CandidateError('stored tree directory is not sealed and owner controlled')
    return descriptor


def _names(directory, maximum):
    result = []
    with os.scandir(directory) as iterator:
        for entry in iterator:
            if len(result) >= maximum:
                raise CandidateError('stored directory entry limit')
            result.append(entry.name)
    return sorted(result)


def _tree_inventory(directory, limits, deadline, prefix='', budget=None):
    previous = _directory_version(directory)
    if budget is None:
        budget = [0, 0, 0]  # actual files, bytes, directory entries across recursion
    observed = {}
    for name in _names(directory, limits.max_files * limits.max_depth):
        _check_time(deadline)
        budget[2] += 1
        if budget[2] > limits.max_files * limits.max_depth:
            raise CandidateError('cumulative materialized directory entry limit')
        path = prefix + name
        _path(path, limits)
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            descriptor = _directory(directory, name)
            try:
                child = _tree_inventory(descriptor, limits, deadline, path + '/', budget)
                if not child:
                    raise CandidateError('unexpected empty directory in materialized tree')
                actual = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if (actual.st_dev, actual.st_ino) != _identity(descriptor):
                    raise CandidateError('materialized directory was replaced during verification')
                observed.update(child)
            finally:
                os.close(descriptor)
        else:
            budget[0] += 1
            if budget[0] > limits.max_files:
                raise CandidateError('cumulative materialized file limit')
            raw, mode = _read_file(directory, name,
                min(limits.max_file_bytes, limits.max_total_bytes - budget[1]), deadline)
            budget[1] += len(raw)
            observed[path] = (raw, mode)
        if len(observed) > limits.max_files:
            raise CandidateError('materialized inventory exceeds its file limit')
    _check_time(deadline)
    _check_directory_version(directory, previous)
    return observed


class CandidateStore:
    """A fixed private artifact destination; deliberately no in-place apply API.

    Read-only modes detect drift and reduce accidental edits; they do not prove
    Worker exclusion when Worker and service share an OS principal. Activation
    must enforce that independent boundary. Library callers are trusted control
    code, not authenticated remote requesters.
    """
    def __init__(self, root, *, limits=None):
        self.root = Path(root)
        self.limits = limits or CandidateLimits()
        self.limits.validate()
        self._root_fd = _private_directory(root)
        self._root_identity = _identity(self._root_fd)

    def close(self):
        if self._root_fd is not None:
            os.close(self._root_fd)
            self._root_fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _check_root(self):
        if self._root_fd is None:
            raise CandidateError('candidate store is closed')
        current = _private_directory(self.root)
        try:
            if _identity(current) != self._root_identity:
                raise CandidateError('installed storage directory was replaced')
        finally:
            os.close(current)

    @staticmethod
    def _name(digest):
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            raise CandidateError('an exact candidate digest is required')
        return digest[7:]

    def receive(self, binding_bytes, *, commit_bytes, archive_bytes, external_materials=None, elapsed_deadline=None):
        self._check_root()
        deadline = _deadline(self.limits)
        if elapsed_deadline is not None:
            if (type(elapsed_deadline) not in (int,float) or not math.isfinite(elapsed_deadline)
                    or elapsed_deadline<=0):
                raise CandidateError('installed monotonic reception deadline required')
            deadline=min(deadline,elapsed_deadline)
        _check_time(deadline)
        binding, canonical = validate_binding(binding_bytes, self.limits)
        _commit(commit_bytes, binding)
        content = _archive_files(archive_bytes, binding, self.limits, deadline)
        supplied = dict(external_materials or {})
        if set(supplied) != {item['materialId'] for item in binding['externalMaterials']}:
            raise CandidateError('complete exact external material set is required')
        for item in binding['externalMaterials']:
            raw = supplied[item['materialId']]
            if not isinstance(raw, bytes) or len(raw) != item['size'] or _hash(raw) != item['contentSha256']:
                raise CandidateError('external material byte identity mismatch')
        digest = _hash(canonical)
        name = self._name(digest)
        _check_time(deadline)
        try:
            existing = _directory(self._root_fd, name)
        except FileNotFoundError:
            pass
        else:
            os.close(existing)
            self._verify_named(digest, deadline)
            os.fsync(self._root_fd)
            self._check_root()
            return self._receipt(binding, digest, 'already_present')
        # Partial directories have a different namespace and are NEVER eligible
        # references. Failures retain them for controlled diagnosis/recovery;
        # request code does not execute recursive cleanup on arbitrary paths.
        stage = '.pending-' + secrets.token_hex(16)
        directory = _mkdir(self._root_fd, stage)
        try:
            _write_file(directory, 'binding.json', canonical, deadline=deadline)
            _write_file(directory, 'commit.bin', commit_bytes, deadline=deadline)
            _write_file(directory, 'archive.bin', archive_bytes, deadline=deadline)
            tree = _mkdir(directory, 'tree')
            try:
                _write_tree(tree, binding['files'], content, deadline)
            finally:
                os.close(tree)
            materials = _mkdir(directory, 'materials')
            try:
                for item in binding['externalMaterials']:
                    _write_file(materials, item['materialId'], supplied[item['materialId']], deadline=deadline)
                os.fchmod(materials, 0o500)
                os.fsync(materials)
            finally:
                os.close(materials)
            os.fchmod(directory, 0o500)
            os.fsync(directory)
            self._verify_directory(directory, digest, deadline)
            self._check_root()
            _check_time(deadline)
            published = _rename_absent(self._root_fd, stage, name)
            os.fsync(self._root_fd)
            self._check_root()
            # Read the actual published pathname in both cases. Verification of
            # a staging handle cannot certify a name changed during publication.
            # A competing publication must pass the same complete readback.
            self._verify_named(digest, deadline)
            return self._receipt(binding, digest, 'stored' if published else 'already_present')
        finally:
            os.close(directory)

    @staticmethod
    def _receipt(binding, digest, outcome):
        return {'candidateDigest': digest, 'outcome': outcome,
                'fileCount': len(binding['files']), 'totalBytes': sum(item['size'] for item in
                    [*binding['files'], *binding['externalMaterials']]),
                'authority': False, 'qualification': False}

    def _verify_directory(self, directory, digest, deadline):
        previous = _directory_version(directory)
        if set(_names(directory, 5)) != CONTROL_FILES | {'tree', 'materials'}:
            raise CandidateError('candidate control inventory differs from its fixed layout')
        raw, mode = _read_file(directory, 'binding.json', self.limits.max_manifest_bytes, deadline)
        if mode != 0o400:
            raise CandidateError('control files must have data-only storage modes')
        binding, canonical = validate_binding(raw, self.limits)
        if raw != canonical or _hash(raw) != digest:
            raise CandidateError('stored candidate binding identity mismatch')
        commit, mode = _read_file(directory, 'commit.bin', 262144, deadline)
        if mode != 0o400:
            raise CandidateError('control files must have data-only storage modes')
        _commit(commit, binding)
        archive, mode = _read_file(directory, 'archive.bin', self.limits.max_archive_bytes, deadline)
        if mode != 0o400:
            raise CandidateError('control files must have data-only storage modes')
        expected = _archive_files(archive, binding, self.limits, deadline)
        tree = _directory(directory, 'tree')
        try:
            observed = _tree_inventory(tree, self.limits, deadline)
            _check_directory_name(directory, 'tree', tree)
        finally:
            os.close(tree)
        if set(observed) != set(expected):
            raise CandidateError('materialized tree inventory mismatch')
        for item in binding['files']:
            mode = 0o500 if item['mode'] == '100755' else 0o400
            if observed[item['path']] != (expected[item['path']], mode):
                raise CandidateError('materialized tree content or mode mismatch')
        materials = _directory(directory, 'materials')
        try:
            materials_version = _directory_version(materials)
            if set(_names(materials, 64)) != {item['materialId'] for item in binding['externalMaterials']}:
                raise CandidateError('stored external material inventory mismatch')
            for item in binding['externalMaterials']:
                _check_time(deadline)
                material, mode = _read_file(materials, item['materialId'], self.limits.max_file_bytes, deadline)
                if mode != 0o400 or len(material) != item['size'] or _hash(material) != item['contentSha256']:
                    raise CandidateError('stored external material content mismatch')
            _check_directory_version(materials, materials_version)
            _check_directory_name(directory, 'materials', materials)
        finally:
            os.close(materials)
        _check_time(deadline)
        _check_directory_version(directory, previous)
        return binding

    def _verify_named(self, digest, deadline):
        self._check_root()
        directory = _directory(self._root_fd, self._name(digest))
        try:
            result = self._verify_directory(directory, digest, deadline)
            # Reject a pathname swap that occurred while the original handle was
            # being verified; a replacement cannot inherit an old readback.
            actual = os.stat(self._name(digest), dir_fd=self._root_fd, follow_symlinks=False)
            if (actual.st_dev, actual.st_ino) != _identity(directory):
                raise CandidateError('candidate directory was replaced during verification')
            self._check_root()
            return result
        finally:
            os.close(directory)

    def verify(self, digest):
        return self._verify_named(digest, _deadline(self.limits))

    def confirm_for_registration(self, digest):
        """Reconcile publication before committing any DB reference to its bytes.

        This ordering is necessary after a process/API failure. It is not a
        substitute for deployment filesystem/power-loss qualification.
        """
        deadline = _deadline(self.limits)
        self._verify_named(digest, deadline)
        directory = _directory(self._root_fd, self._name(digest))
        try:
            remaining = [self.limits.max_files * self.limits.max_depth + 72]
            def sync_tree(descriptor):
                for name in _names(descriptor, remaining[0]):
                    _check_time(deadline)
                    remaining[0] -= 1
                    if remaining[0] < 0:
                        raise CandidateError('cumulative storage sync entry limit')
                    info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        child = _directory(descriptor, name)
                        try:
                            sync_tree(child)
                        finally:
                            os.close(child)
                    elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                        child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=descriptor)
                        try:
                            os.fsync(child)
                        finally:
                            os.close(child)
                    else:
                        raise CandidateError('unsafe storage object during publication confirmation')
                os.fsync(descriptor)
            sync_tree(directory)
            os.fsync(self._root_fd)
            self._check_root()
            return self._verify_named(digest, deadline)
        finally:
            os.close(directory)

    def compose_integration(self, baseline, source, *, source_paths, deleted_paths, tool_digest):
        """Prepare complete I from exact B/C files, without changing a target.

        An installed service approves the selection and later verifies/signs I.
        This fixed profile does no textual merge or arbitrary generated content.
        Unsupported transformations require a separate reviewed profile.
        """
        self._name(tool_digest)
        deadline = _deadline(self.limits)
        before = self._verify_named(baseline, deadline)
        candidate = self._verify_named(source, deadline)
        b, c = _integration_entries(before), _integration_entries(candidate)
        for selection in (source_paths, deleted_paths):
            if (not isinstance(selection,list) or len(selection)>self.limits.max_files+64
                    or any(not isinstance(path,str) for path in selection)
                    or selection!=sorted(set(selection))):
                raise CandidateError('integration selection must be exact, bounded, sorted and unique')
        if set(source_paths)&set(deleted_paths) or not source_paths and not deleted_paths:
            raise CandidateError('integration selection overlaps or changes nothing')
        if (any(path not in c or c[path]==b.get(path) for path in source_paths)
                or any(path not in b for path in deleted_paths)):
            raise CandidateError('integration selects an absent or unchanged source/deletion')
        entries = dict(b)
        entries.update({path:c[path] for path in source_paths})
        for path in deleted_paths: del entries[path]
        inventory = [entries[path] for path in sorted(entries) if path.startswith('tree/')]
        materials = [entries[path] for path in sorted(entries) if path.startswith('materials/')]
        if not inventory or len(inventory)>self.limits.max_files or sum(x['size'] for x in entries.values())>self.limits.max_total_bytes:
            raise CandidateError('integrated view is empty or exceeds its material budget')
        validate_binding(codec.canonical(dict(candidate,files=inventory,externalMaterials=materials)),self.limits)
        # Check file/directory/case collisions and all original limits BEFORE any
        # publication. receive() repeats the full contract and actual byte checks.
        tree, commit = _integration_commit(baseline,before,source,candidate,entries)
        content = {}
        for digest, binding, selected in ((baseline,before,set(entries)-set(source_paths)),
                                          (source,candidate,set(source_paths))):
            directory = _directory(self._root_fd,self._name(digest))
            try:
                archive,_ = _read_file(directory,'archive.bin',self.limits.max_archive_bytes,deadline)
                original = _archive_files(archive,binding,self.limits,deadline)
                content.update({'tree/'+path:raw for path,raw in original.items() if 'tree/'+path in selected})
                external = _directory(directory,'materials')
                try:
                    for item in binding['externalMaterials']:
                        path = 'materials/'+item['materialId']
                        if path in selected:
                            raw,mode = _read_file(external,item['materialId'],self.limits.max_file_bytes,deadline)
                            if mode!=0o400 or len(raw)!=item['size'] or _hash(raw)!=item['contentSha256']:
                                raise CandidateError('integration external source changed')
                            content[path]=raw
                    _check_directory_name(directory,'materials',external)
                finally: os.close(external)
                _check_directory_name(self._root_fd,self._name(digest),directory)
            finally: os.close(directory)
        output = io.BytesIO()
        try:
            with tarfile.open(fileobj=output,mode='w:',format=tarfile.USTAR_FORMAT,encoding='utf-8') as archive:
                for item in inventory:
                    _check_time(deadline)
                    member = tarfile.TarInfo(item['path'])
                    member.size,member.mode = item['size'],0o755 if item['mode']=='100755' else 0o644
                    archive.addfile(member,io.BytesIO(content['tree/'+item['path']]))
        except (ValueError,UnicodeError) as exc:
            raise CandidateError('integrated path cannot be represented by the fixed USTAR profile') from exc
        raw_archive = output.getvalue()
        binding = dict(candidate,files=inventory,externalMaterials=materials,
            source=dict(kind='git',objectFormat=candidate['source']['objectFormat'],
                commitOid=_git_hash('commit',commit,candidate['source']['objectFormat']),treeOid=tree,
                commitContentSha256=_hash(commit),view='complete-committed-tree'),
            archive=dict(encoding='tar-ustar',rawSha256=_hash(raw_archive),decodedSha256=_hash(raw_archive)))
        try: validate_binding(codec.canonical(binding),self.limits)
        except (ValueError,UnicodeError) as exc: raise CandidateError('integrated view is not representable') from exc
        self._verify_named(baseline,deadline); self._verify_named(source,deadline)
        result = self.receive(codec.canonical(binding),commit_bytes=commit,archive_bytes=raw_archive,
            external_materials={item['materialId']:content['materials/'+item['materialId']] for item in materials})
        _check_time(deadline)
        lineage = self.integration_lineage(baseline,source,result['candidateDigest'],tool_digest=tool_digest)
        _check_time(deadline)
        return dict(result,lineage=lineage,lineageDigest=codec.digest(lineage))

    def integration_lineage(self, baseline, source, integrated, *, tool_digest):
        """Reconstruct the fixed profile from actual immutable B/C/I bytes.

        A relationship is evidence, not authorization. The independently approved
        verification context MUST also bind this exact record's semantic digest.
        """
        self._name(tool_digest)
        deadline = _deadline(self.limits)
        before = self._verify_named(baseline,deadline)
        candidate = self._verify_named(source,deadline)
        actual = self._verify_named(integrated,deadline)
        if any(candidate[name]!=actual[name] for name in ('taskKey','taskRevision','taskCycle','obligationDigest','policyDigest')):
            raise CandidateError('materialized I changed the source task/policy binding')
        b,c,i = map(_integration_entries,(before,candidate,actual))
        selection = sorted(path for path in i if i[path]!=b.get(path))
        deleted = sorted(set(b)-set(i))
        if not selection and not deleted or any(c.get(path)!=i[path] for path in selection):
            raise CandidateError('I has unexplained content or no integration changes')
        tree,expected = _integration_commit(baseline,before,source,candidate,i)
        directory = _directory(self._root_fd,self._name(integrated))
        try:
            raw,_ = _read_file(directory,'commit.bin',262144,deadline)
            _check_directory_name(self._root_fd,self._name(integrated),directory)
        finally: os.close(directory)
        if raw!=expected or actual['source']['treeOid']!=tree or actual['source']['objectFormat']!=candidate['source']['objectFormat']:
            raise CandidateError('actual I does not have the fixed B/C integration lineage')
        _check_time(deadline)
        return dict(profile='das-whole-file-integration/v1',baselineCandidateDigest=baseline,
            sourceCandidateDigest=source,integratedCandidateDigest=integrated,
            toolDigest=tool_digest,policyDigest=candidate['policyDigest'],
            sourcePaths=selection,deletedPaths=deleted,
            preservedBaselinePaths=sorted(set(i)-set(selection)),
            unusedSourcePaths=sorted(set(c)-set(selection)),
            outputInventoryDigest=codec.digest(dict(files=actual['files'],externalMaterials=actual['externalMaterials'])))

    def prepare_reference_view(self, digest):
        """Prepare a fresh readable view for the fixed Python runtime prototype.

        This installed-library call must be preceded by current purpose/read
        authorization in the future service. It exposes no arbitrary path or
        entrypoint operand. The root remains private; the selected child is
        mounted read-only into the separately owned native domain. No current
        policy approval, build provenance or qualification is issued here.
        """
        deadline = _deadline(self.limits)
        binding = self._verify_named(digest, deadline)
        if 'run.py' not in {item['path'] for item in binding['files']}:
            raise CandidateError('fixed Python reference profile requires committed run.py')
        prefix = '.das-external-materials'
        if any(item['path'].split('/')[0].casefold() == prefix for item in binding['files']):
            raise CandidateError('source collides with the fixed external-material mapping')
        source = _directory(self._root_fd, self._name(digest))
        projection = '.reference-pending-' + secrets.token_hex(16)
        target = None
        try:
            content = {}
            inventory = []
            mapping = []
            tree = _directory(source, 'tree')
            try:
                observed = _tree_inventory(tree, self.limits, deadline)
                for item in binding['files']:
                    mode = 0o500 if item['mode'] == '100755' else 0o400
                    raw, stored_mode = observed[item['path']]
                    if stored_mode != mode or _hash(raw) != item['contentSha256']:
                        raise CandidateError('source changed before execution-view preparation')
                    content[item['path']] = raw
                    inventory.append({'path':item['path'], 'mode':item['mode']})
                    mapping.append({'source':'tree/' + item['path'], 'destination':item['path'],
                        'contentSha256':item['contentSha256'], 'sourceMode':item['mode'],
                        'executionMode':'0555' if item['mode']=='100755' else '0444'})
            finally:
                os.close(tree)
            materials = _directory(source, 'materials')
            try:
                for item in binding['externalMaterials']:
                    raw, mode = _read_file(materials,item['materialId'],self.limits.max_file_bytes,deadline)
                    if mode != 0o400 or len(raw) != item['size'] or _hash(raw) != item['contentSha256']:
                        raise CandidateError('external bytes changed before execution-view preparation')
                    path = prefix + '/' + item['materialId']
                    content[path] = raw
                    inventory.append({'path':path, 'mode':'100644'})
                    mapping.append({'source':'materials/' + item['materialId'], 'destination':path,
                        'contentSha256':item['contentSha256'], 'sourceMode':'data', 'executionMode':'0444'})
            finally:
                os.close(materials)
            inventory.sort(key=lambda item:item['path'])
            mapping.sort(key=lambda item:item['destination'])
            target = _mkdir(self._root_fd,projection)
            _write_tree(target,inventory,content,deadline,readable=True)
            self._check_root()
            # Read using the declared execution modes, never silently chmod the
            # original sealed candidate to make its consumer work.
            _verify_reference_tree(target,content,inventory,self.limits,deadline)
            self._verify_named(digest,deadline)
            ready = '.reference-' + secrets.token_hex(16)
            if not _rename_absent(self._root_fd,projection,ready):
                raise CandidateError('fresh execution-view name was already occupied')
            os.fsync(self._root_fd)
            self._check_root()
            published = os.open(ready,DIRECTORY_FLAGS,dir_fd=self._root_fd)
            try:
                if _identity(published) != _identity(target):
                    raise CandidateError('execution-view directory was replaced during publication')
                _verify_reference_tree(published,content,inventory,self.limits,deadline)
                actual = os.stat(ready,dir_fd=self._root_fd,follow_symlinks=False)
                if (actual.st_dev,actual.st_ino) != _identity(published):
                    raise CandidateError('execution-view directory was replaced during readback')
            finally:
                os.close(published)
            self._verify_named(digest,deadline)
            self._check_root()
            return {'profile':'das-python-native-reference-view/v1','candidateDigest':digest,
                    'viewPath':str(self.root / ready),'mapping':mapping,
                    'mappingDigest':codec.digest(mapping),'authority':False,'qualification':False}
        finally:
            os.close(source)
            if target is not None:
                os.close(target)


def _verify_reference_tree(directory,content,inventory,limits,deadline):
    expected = {item['path']:item['mode'] for item in inventory}
    expected_directories = {item['path'].rsplit('/',count)[0] for item in inventory
                            for count in range(1,item['path'].count('/')+1)}
    observed = set()
    maximum_nodes = limits.max_files * limits.max_depth + 128
    state = [0,0]
    def walk(descriptor,prefix=''):
        initial = os.fstat(descriptor)
        if initial.st_uid != os.getuid() or stat.S_IMODE(initial.st_mode) != 0o555:
            raise CandidateError('execution-view directory mode/owner mismatch')
        for name in _names(descriptor,maximum_nodes):
            _check_time(deadline)
            state[0] += 1
            if state[0] > maximum_nodes:
                raise CandidateError('execution-view cumulative member limit')
            path = prefix+name
            info = os.stat(name,dir_fd=descriptor,follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                if path not in expected_directories:
                    raise CandidateError('execution-view has an unexpected directory')
                child = os.open(name,DIRECTORY_FLAGS,dir_fd=descriptor)
                try:
                    if _identity(child) != (info.st_dev,info.st_ino):
                        raise CandidateError('execution-view directory changed before readback')
                    walk(child,path+'/')
                    actual = os.stat(name,dir_fd=descriptor,follow_symlinks=False)
                    if (actual.st_dev,actual.st_ino) != _identity(child):
                        raise CandidateError('execution-view directory was replaced during readback')
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink==1 and path in expected:
                mode = 0o555 if expected[path]=='100755' else 0o444
                if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=mode or info.st_size!=len(content[path]):
                    raise CandidateError('execution-view file mode/owner/size mismatch')
                child = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=descriptor)
                try:
                    opened = os.fstat(child)
                    if (_identity(child)!=(info.st_dev,info.st_ino)
                            or (opened.st_mode,opened.st_uid,opened.st_nlink,opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)
                            != (info.st_mode,info.st_uid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)):
                        raise CandidateError('execution-view file changed before readback')
                    raw=bytearray()
                    while len(raw)<=info.st_size:
                        _check_time(deadline)
                        part=os.read(child,min(65536,info.st_size+1-len(raw)))
                        if not part:break
                        raw.extend(part)
                    after=os.fstat(child)
                    actual=os.stat(name,dir_fd=descriptor,follow_symlinks=False)
                    if (bytes(raw)!=content[path] or (actual.st_dev,actual.st_ino)!=_identity(child)
                            or (opened.st_mode,opened.st_uid,opened.st_nlink,opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)
                            != (after.st_mode,after.st_uid,after.st_nlink,after.st_size,after.st_mtime_ns,after.st_ctime_ns)):
                        raise CandidateError('execution-view content changed during readback')
                finally:
                    os.close(child)
                state[1]+=len(raw)
                if state[1]>limits.max_total_bytes:
                    raise CandidateError('execution-view cumulative byte limit')
                observed.add(path)
            else:
                raise CandidateError('execution-view has unexpected type/member')
        _check_time(deadline)
        after=os.fstat(descriptor)
        if (initial.st_mtime_ns,initial.st_ctime_ns)!=(after.st_mtime_ns,after.st_ctime_ns):
            raise CandidateError('execution-view directory changed during readback')
    walk(directory)
    if observed!=set(expected):
        raise CandidateError('execution-view is incomplete')
