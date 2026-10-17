"""Actual Git/tar/filesystem/process fixtures; source mechanism tests only."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
import gzip
import hashlib
import io
import http.client
import json
import os
from pathlib import Path
import resource
import socket
import stat
import subprocess
import sys
import tarfile
import time
import threading

import pytest

from dasops.protected.candidates import CandidateError, CandidateLimits, CandidateStore
from dasops.protected.candidates import store as implementation
from dasops.protected.candidates.http_reference import receive_candidate_http
from dasops.standards_contracts import exact_json as codec

D = 'sha256:' + '1' * 64


def sha(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def archive_bytes(content, *, members=None):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:', format=tarfile.USTAR_FORMAT, encoding='utf-8') as archive:
        for path in sorted(content) if members is None else members:
            raw, executable = content[path]
            member = tarfile.TarInfo(path)
            member.size = len(raw)
            member.mode = 0o755 if executable else 0o644
            archive.addfile(member, io.BytesIO(raw))
    return output.getvalue()


def fixture(tmp_path, *, content=None, object_format='sha1', encoding='tar-ustar', materials=None):
    content = content or {'README.md': (b'fixture\n', False), 'src/run.py': (b'print("legal")\n', True),
                          'tests/test_source.txt': (b'checks\n', False)}
    repository = tmp_path / 'source'
    repository.mkdir(mode=0o700)
    env = {'HOME': str(tmp_path), 'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_AUTHOR_NAME': 'Source fixture', 'GIT_AUTHOR_EMAIL': 'fixture@local',
           'GIT_COMMITTER_NAME': 'Source fixture', 'GIT_COMMITTER_EMAIL': 'fixture@local',
           'GIT_AUTHOR_DATE': '2026-10-05T00:00:00Z', 'GIT_COMMITTER_DATE': '2026-10-05T00:00:00Z'}

    def git(*args):
        return subprocess.run(['/usr/bin/git', '-C', str(repository), *args], env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout

    git('init', '--object-format=' + object_format)
    for path, (raw, executable) in content.items():
        destination = repository / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        destination.chmod(0o755 if executable else 0o644)
    git('add', '--', '.')
    git('commit', '-m', 'fixed source fixture')
    commit = git('rev-parse', 'HEAD').decode().strip()
    tree = git('rev-parse', 'HEAD^{tree}').decode().strip()
    commit_raw = git('cat-file', 'commit', commit)
    files = []
    # Independent Git plumbing supplies expected OIDs, not the receiver's hash.
    for entry in git('ls-tree', '-r', '-z', '--long', 'HEAD').split(b'\0'):
        if not entry:
            continue
        metadata, path_raw = entry.split(b'\t')
        mode, kind, oid, size = metadata.split()
        assert kind == b'blob'
        path = path_raw.decode()
        files.append(dict(path=path, mode=mode.decode(), size=int(size), blobOid=oid.decode(), contentSha256=sha(content[path][0])))
    files.sort(key=lambda item: item['path'])
    decoded = archive_bytes(content)
    raw = gzip.compress(decoded, mtime=0) if encoding == 'gzip-tar-ustar' else decoded
    external = []
    for name, payload in sorted((materials or {}).items()):
        external.append(dict(materialId=name, role='dependency', size=len(payload), contentSha256=sha(payload), mediaType='application/octet-stream'))
    binding = dict(contractIdentity='das-candidate-binding/v1',
        taskKey=dict(authorityDomain='domain', projectId='project', changeId='change', taskId='task'),
        taskRevision=1, taskCycle=1, obligationDigest=D, policyDigest=D,
        source=dict(kind='git', objectFormat=object_format, commitOid=commit, treeOid=tree,
                    commitContentSha256=sha(commit_raw), view='complete-committed-tree'),
        archive=dict(encoding=encoding, rawSha256=sha(raw), decodedSha256=sha(decoded)), files=files, externalMaterials=external)
    return binding, commit_raw, raw, content


def receive(store, values, *, external_materials=None):
    binding, commit, archive, _ = values
    return store.receive(codec.canonical(binding), commit_bytes=commit, archive_bytes=archive, external_materials=external_materials)


def repack(values, raw, *, decoded=None):
    binding, commit, _, content = values
    binding = deepcopy(binding)
    binding['archive'].update(rawSha256=sha(raw), decodedSha256=sha(raw if decoded is None else decoded))
    return binding, commit, raw, content


def test_receiver_cannot_reset_an_expired_original_dispatch_deadline(tmp_path):
    inputs=tmp_path/'input';inputs.mkdir()
    values=fixture(inputs)
    root=tmp_path/'artifacts';root.mkdir(mode=0o700)
    with CandidateStore(root) as store:
        with pytest.raises(CandidateError,match='deadline'):
            store.receive(codec.canonical(values[0]),commit_bytes=values[1],archive_bytes=values[2],
                          elapsed_deadline=time.clock_gettime(time.CLOCK_BOOTTIME)-1)
        assert list(root.iterdir())==[], 'expired reception created/published candidate bytes'


def new_store(tmp_path, **kwargs):
    root = tmp_path / 'artifacts'
    root.mkdir(mode=0o700)
    return CandidateStore(root, **kwargs)


@pytest.mark.parametrize('variant', [
    'full-identity', 'full-gzip', 'full-gzip-uppercase', 'range-identity', 'range-uppercase', 'range-gzip', 'range-200-reset',
    'wire-decoded-digest-mix', 'decoded-pin-mismatch', 'gzip-crc', 'gzip-incomplete',
    'gzip-extra-member', 'changed-validator', 'missing-validator', 'weak-validator',
    'wrong-range-start', 'unknown-range-total', 'partial-200', 'cache-304-missing',
    'unsolicited-206', 'range-in-200', 'duplicate-length', 'transfer-encoding',
    'required-trailer', 'truncated-body', 'received-byte-budget', 'expanded-byte-budget',
    'cumulative-header-deadline', 'cumulative-body-deadline',
])
def test_actual_http_acquisition_checks_byte_domains_and_complete_object_before_publication(tmp_path, variant):
    """Real TCP response/request bytes, Git identities and final private store.

    Trusted TEST installation pins origin/content/validator; no public-host,
    TLS-provider, shared cache or fully installed reference qualification claim.
    """
    # Exact-budget identity cases need a plain archive: a gzip candidate has
    # a separate larger decoded budget, which would mask the HTTP boundary.
    values = fixture(tmp_path, encoding='tar-ustar' if variant in
                     ('range-200-reset', 'range-identity') else 'gzip-tar-ustar')
    binding, commit, archive, content = values
    encoding = 'gzip' if variant in ('full-gzip', 'full-gzip-uppercase', 'range-gzip', 'wire-decoded-digest-mix',
        'gzip-crc', 'gzip-incomplete', 'gzip-extra-member', 'expanded-byte-budget') else 'identity'
    wire = gzip.compress(archive, mtime=0) if encoding == 'gzip' else archive
    expected = sha(wire)
    prefix = wire[:17] if variant.startswith('range-') or variant in (
        'changed-validator', 'missing-validator', 'weak-validator',
        'wrong-range-start', 'unknown-range-total') else b''
    validator = '"fixture-v1"' if prefix else None
    status = 206 if prefix and variant != 'range-200-reset' else 200
    payload = wire[len(prefix):] if status == 206 else wire
    headers = [('Content-Length', str(len(payload))), ('Content-Encoding', encoding)]
    if status == 206:
        headers.extend([('Content-Range', 'bytes %d-%d/%d' % (len(prefix),len(wire)-1,len(wire))),
                        ('ETag', validator)])
    limits = CandidateLimits()
    if variant == 'full-gzip-uppercase': headers[1] = ('Content-Encoding', ' GZip ')
    if variant == 'range-uppercase': headers[-2] = ('Content-Range', 'Bytes 17-%d/%d' % (len(wire)-1,len(wire)))
    if variant == 'range-200-reset':
        prefix = b'wrong-but-discarded'
        # The full 200 replaces the prefix, including its byte budget. An
        # object exactly at the installed limit must remain a lawful receive.
        limits = replace(limits, max_archive_bytes=len(wire))
    if variant == 'range-identity': limits = replace(limits, max_archive_bytes=len(wire))
    if variant == 'wire-decoded-digest-mix': expected = sha(archive)
    if variant == 'decoded-pin-mismatch': binding['archive']['rawSha256'] = sha(b'other archive')
    if variant == 'gzip-crc': payload = wire[:-8] + bytes([wire[-8] ^ 1]) + wire[-7:]
    if variant == 'gzip-incomplete': payload = wire[:-1]
    if variant == 'gzip-extra-member': payload = wire + gzip.compress(b'extra', mtime=0)
    if variant.startswith('gzip-'):
        expected = sha(payload); headers[0] = ('Content-Length', str(len(payload)))
    if variant == 'changed-validator': headers[-1] = ('ETag', '"fixture-v2"')
    if variant == 'missing-validator': headers.pop()
    if variant == 'weak-validator': headers[-1] = ('ETag', 'W/"fixture-v1"')
    if variant == 'wrong-range-start': headers[-2] = ('Content-Range', 'bytes 18-%d/%d' % (len(wire)-1,len(wire)))
    if variant == 'unknown-range-total': headers[-2] = ('Content-Range', 'bytes 17-%d/*' % (len(wire)-1))
    if variant == 'partial-200':
        payload = wire[:17]; headers[0] = ('Content-Length', '17')
    if variant == 'cache-304-missing': status = 304; payload = b''; headers[0] = ('Content-Length', '0')
    if variant == 'unsolicited-206': status = 206
    if variant == 'range-in-200': headers.append(('Content-Range', 'bytes 0-%d/%d' % (len(wire)-1,len(wire))))
    if variant == 'duplicate-length': headers.append(headers[0])
    if variant == 'transfer-encoding': headers.append(('Transfer-Encoding', 'chunked'))
    if variant == 'required-trailer': headers.append(('Trailer', 'Content-Digest'))
    if variant == 'truncated-body': payload = wire[:-3]
    if variant == 'received-byte-budget': limits = replace(limits, max_archive_bytes=len(wire)-1)
    if variant == 'expanded-byte-budget': limits = replace(limits, max_archive_bytes=len(archive)-1)
    if variant.startswith('cumulative-'): limits = replace(limits, seconds=1)
    raw_headers = ('HTTP/1.1 %d TEST\r\n' % status + ''.join('%s: %s\r\n' % pair for pair in headers)
                   + 'Connection: close\r\n\r\n').encode('ascii')
    observed, failures = {}, []
    listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(1); listener.settimeout(3)
    def serve():
        try:
            channel, _ = listener.accept()
            with channel:
                channel.settimeout(3); request = bytearray()
                while not request.endswith(b'\r\n\r\n'):
                    part = channel.recv(1)
                    if not part: break
                    request.extend(part)
                observed['request'] = bytes(request)
                if variant == 'cumulative-header-deadline':
                    for part in raw_headers:
                        channel.sendall(bytes([part])); time.sleep(.03)
                else:
                    channel.sendall(raw_headers)
                if variant == 'cumulative-body-deadline':
                    for part in payload:
                        channel.sendall(bytes([part])); time.sleep(.03)
                else:
                    channel.sendall(payload)
        except (BrokenPipeError, ConnectionResetError):
            # The client has already refused/closed an unsupported response.
            pass
        except BaseException as exc:
            failures.append(exc)
        finally:
            listener.close()
    server = threading.Thread(target=serve); server.start()
    connection = http.client.HTTPConnection(*listener.getsockname(), timeout=2); connection.connect()
    positive = variant in ('full-identity', 'full-gzip', 'full-gzip-uppercase', 'range-identity',
                           'range-uppercase', 'range-gzip', 'range-200-reset')
    receipt, error = None, None
    started = time.monotonic()
    try:
        with new_store(tmp_path, limits=limits) as store:
            try:
                receipt = receive_candidate_http(store, connection, '/fixed-archive', codec.canonical(binding),
                    commit_bytes=commit, content_sha256=expected, content_encoding=encoding,
                    prefix=prefix, strong_etag=validator)
            except CandidateError as exc:
                error = str(exc)
            assert (receipt is not None) == positive, error or receipt
            if positive:
                assert receipt['authority'] is False and receipt['qualification'] is False
                assert receipt['candidateDigest'] == sha(codec.canonical(binding))
                assert store.verify(receipt['candidateDigest']) == binding
                root = store.root / receipt['candidateDigest'][7:]
                assert (root/'archive.bin').read_bytes() == archive
                assert (root/'commit.bin').read_bytes() == commit
                for path, (raw, _) in content.items(): assert (root/'tree'/path).read_bytes() == raw
                observed['publishedArchiveDigest'] = sha((root/'archive.bin').read_bytes())
            else:
                assert error and list(store.root.iterdir()) == []
            observed['objects'] = [path.name for path in store.root.iterdir()]
    finally:
        connection.close(); server.join(timeout=4)
    assert not server.is_alive() and not failures, failures
    request = observed['request']
    assert b'GET /fixed-archive HTTP/1.1\r\n' in request
    assert (b'Range:' in request) == bool(prefix)
    if prefix: assert ('If-Range: %s\r\n' % validator).encode() in request
    if variant.startswith('cumulative-'): assert time.monotonic()-started < 2.5
    evidence = os.environ.get('DAS_HTTP_ACQUISITION_EVIDENCE_DIR')
    if evidence:
        directory = Path(evidence)/variant; directory.mkdir(parents=True, mode=0o700)
        (directory/'request.raw').write_bytes(request)
        (directory/'response.raw').write_bytes(raw_headers+payload)
        (directory/'binding.json').write_bytes(codec.canonical(binding))
        (directory/'prefix.bin').write_bytes(prefix)
        (directory/'archive.bin').write_bytes(archive)
        (directory/'observation.json').write_text(json.dumps(dict(variant=variant, success=positive,
            receipt=receipt, error=error, contentEncoding=encoding, expectedContentSha256=expected,
            archiveRawSha256=binding['archive']['rawSha256'], archiveDecodedSha256=binding['archive']['decodedSha256'],
            byteLimit=limits.max_archive_bytes, seconds=limits.seconds, requestSha256=sha(request),
            responseSha256=sha(raw_headers+payload), objects=observed['objects'],
            publishedArchiveDigest=observed.get('publishedArchiveDigest')), indent=2)+'\n')


@pytest.mark.parametrize('object_format', ['sha1', 'sha256'])
@pytest.mark.parametrize('encoding', ['tar-ustar', 'gzip-tar-ustar'])
def test_exact_complete_git_tree_and_external_bytes_roundtrip(tmp_path, object_format, encoding):
    materials = {'pinned-wheel': b'offline dependency fixture'}
    values = fixture(tmp_path, object_format=object_format, encoding=encoding, materials=materials)
    with new_store(tmp_path) as store:
        receipt = receive(store, values, external_materials=materials)
        digest = sha(codec.canonical(values[0]))
        assert receipt == dict(candidateDigest=digest, outcome='stored', fileCount=3,
                               totalBytes=sum(len(item[0]) for item in values[3].values()) + len(materials['pinned-wheel']),
                               authority=False, qualification=False)
        assert store.verify(digest) == values[0]
        directory = store.root / digest[7:]
        for item in values[0]['files']:
            actual = directory / 'tree' / item['path']
            assert actual.read_bytes() == values[3][item['path']][0]
            assert stat.S_IMODE(actual.stat().st_mode) == (0o500 if item['mode'] == '100755' else 0o400)
        assert (directory / 'archive.bin').read_bytes() == values[2]
        assert (directory / 'commit.bin').read_bytes() == values[1]
        assert not (directory / 'tree/.git').exists()


def test_attributes_unicode_empty_blob_and_git_directory_sort_are_preserved_without_execution(tmp_path, monkeypatch):
    content = {'.gitattributes': (b'tests/* export-ignore\nREADME.md export-subst\n', False),
               'README.md': (b'$Format:%H$\n', False), 'tests/assertion.txt': (b'must remain', False),
               'a.b': (b'x', False), 'a/blobOid': (b'y', False), 'a/tree': (b'z', False),
               '文档/说明.md': (b'', False), 'blobOid': (b'name is not metadata', False)}
    values = fixture(tmp_path, content=content)
    # Any attempt to run Git, metadata, backend, collect or cleanup here fails.
    monkeypatch.setattr(subprocess, 'run', lambda *args, **kwargs: pytest.fail('candidate reception executed a program'))
    with new_store(tmp_path) as store:
        receipt = receive(store, values)
        assert store.verify(receipt['candidateDigest']) == values[0]
        assert (store.root / receipt['candidateDigest'][7:] / 'tree/tests/assertion.txt').read_bytes() == b'must remain'


def test_omission_cannot_be_hidden_by_a_valid_archive_and_recomputed_manifest_digest(tmp_path):
    values = fixture(tmp_path)
    binding = deepcopy(values[0]); binding['files'] = binding['files'][:-1]
    raw = archive_bytes(values[3], members=[item['path'] for item in binding['files']])
    binding['archive'].update(rawSha256=sha(raw), decodedSha256=sha(raw))
    with new_store(tmp_path) as store, pytest.raises(CandidateError, match='tree closure'):
        receive(store, (binding, values[1], raw, values[3]))
    assert not list((tmp_path / 'artifacts').iterdir())


@pytest.mark.parametrize('mutation', ['task-float', 'unsafe-size', 'casing', 'future-proof', 'source-format', 'duplicate-file', 'duplicate-material', 'mode', 'digest-newline'])
def test_closed_exact_binding_rejects_ambiguous_or_future_evidence(tmp_path, mutation):
    values = fixture(tmp_path, materials={'dependency': b'bytes'})
    binding = deepcopy(values[0])
    if mutation == 'task-float':
        raw = json.dumps(binding).replace('"taskRevision": 1', '"taskRevision": 1.000000000000000001').encode()
    elif mutation == 'unsafe-size':
        raw = json.dumps(binding).replace('"size": 8', '"size": 8.000000000000000001').encode()
    else:
        if mutation == 'casing': binding['TaskRevision'] = binding.pop('taskRevision')
        if mutation == 'future-proof': binding['verificationDigest'] = D
        if mutation == 'source-format': binding['source']['objectFormat'] = 'sha256'
        if mutation == 'duplicate-file': binding['files'].insert(0, binding['files'][0])
        if mutation == 'duplicate-material': binding['externalMaterials'].append(binding['externalMaterials'][0])
        if mutation == 'mode': binding['files'][0]['mode'] = '160000'
        if mutation == 'digest-newline': binding['policyDigest'] += '\n'
        raw = codec.canonical(binding)
    with new_store(tmp_path) as store, pytest.raises(CandidateError):
        store.receive(raw, commit_bytes=values[1], archive_bytes=values[2])
    assert not list((tmp_path / 'artifacts').iterdir())


@pytest.mark.parametrize('path', ['../escape', '/absolute', './alias', 'double//slash', 'back\\slash', 'drive:c',
    '.git/config', '.GIT/config', 'con.txt', 'name.', 'name ', 'bad\nname', 'e\u0301.txt'])
def test_unsafe_manifest_paths_are_rejected_before_output_creation(tmp_path, path):
    values = fixture(tmp_path)
    values[0]['files'][0]['path'] = path
    values[0]['files'].sort(key=lambda item: item['path'])
    with new_store(tmp_path) as store, pytest.raises(CandidateError):
        receive(store, values)
    assert not list((tmp_path / 'artifacts').iterdir())


@pytest.mark.parametrize('path', ['README.md/nested', 'readme.md', 'src/Run.py', 'SRC/second'])
def test_file_directory_case_and_parent_alias_collisions_are_rejected(tmp_path, path):
    values = fixture(tmp_path)
    item = dict(values[0]['files'][0], path=path)
    values[0]['files'].append(item); values[0]['files'].sort(key=lambda item: item['path'])
    with new_store(tmp_path) as store, pytest.raises(CandidateError, match='colliding'):
        receive(store, values)


def changed_header(raw, offset, content):
    raw = bytearray(raw); raw[offset:offset + len(content)] = content
    raw[148:156] = b'        '
    raw[148:156] = f'{sum(raw[:512]):06o}'.encode() + b'\0 '
    return bytes(raw)


@pytest.mark.parametrize('mutation', ['symlink', 'hardlink', 'device', 'directory', 'pax', 'gnu', 'size', 'mode',
    'name', 'checksum', 'content', 'padding', 'one-end-block', 'missing-end', 'trailing-data', 'second-archive', 'partial-block', 'duplicate', 'omitted'])
def test_all_security_rejections_invalidate_the_entire_archive(tmp_path, mutation):
    values = fixture(tmp_path)
    raw = values[2]
    if mutation in ('symlink', 'hardlink', 'device', 'directory', 'pax', 'gnu'):
        flag = {'symlink':b'2', 'hardlink':b'1', 'device':b'3', 'directory':b'5', 'pax':b'x', 'gnu':b'L'}[mutation]
        raw = changed_header(raw, 156, flag)
    if mutation == 'size': raw = changed_header(raw, 124, b'77777777777\0')
    if mutation == 'mode': raw = changed_header(raw, 100, b'0004755\0')
    if mutation == 'name': raw = changed_header(raw, 0, b'../escape\0')
    if mutation == 'checksum': raw = bytes([raw[0] ^ 1]) + raw[1:]
    if mutation == 'content': raw = raw[:512] + b'changed\n' + raw[520:]
    if mutation == 'padding': raw = raw[:520] + b'x' + raw[521:]
    # Three members each occupy a header and one content block.
    if mutation == 'one-end-block': raw = raw[:7 * 512]
    if mutation == 'missing-end': raw = raw[:6 * 512]
    if mutation == 'trailing-data': raw = raw + b'x' + b'\0' * 511
    if mutation == 'second-archive': raw += raw
    if mutation == 'partial-block': raw = raw[:-1]
    if mutation == 'duplicate': raw = archive_bytes(values[3], members=['README.md', 'README.md', 'src/run.py', 'tests/test_source.txt'])
    if mutation == 'omitted': raw = archive_bytes(values[3], members=['README.md', 'src/run.py'])
    with new_store(tmp_path) as store, pytest.raises(CandidateError):
        receive(store, repack(values, raw))
    assert not list((tmp_path / 'artifacts').iterdir())


@pytest.mark.parametrize('mutation', ['crc', 'truncated', 'concatenated', 'trailing', 'wrong-raw-domain', 'wrong-decoded-domain'])
def test_gzip_complete_eof_crc_and_byte_domains(tmp_path, mutation):
    values = fixture(tmp_path, encoding='gzip-tar-ustar')
    decoded = archive_bytes(values[3]); raw = values[2]
    if mutation == 'crc': raw = raw[:-8] + bytes([raw[-8] ^ 1]) + raw[-7:]
    if mutation == 'truncated': raw = raw[:-1]
    if mutation == 'concatenated': raw += gzip.compress(b'additional member', mtime=0)
    if mutation == 'trailing': raw += b'\0'
    changed = repack(values, raw, decoded=decoded)
    if mutation == 'wrong-raw-domain': changed[0]['archive']['rawSha256'] = sha(decoded)
    if mutation == 'wrong-decoded-domain': changed[0]['archive']['decodedSha256'] = sha(raw)
    with new_store(tmp_path) as store, pytest.raises(CandidateError): receive(store, changed)


@pytest.mark.parametrize('limitation', ['expanded', 'total', 'member', 'files', 'depth', 'manifest'])
def test_installed_cumulative_limits_cannot_be_increased_by_candidate(tmp_path, limitation):
    values = fixture(tmp_path, content={'deep/path/file': (b'A' * 20000, False)}, encoding='gzip-tar-ustar')
    limits = CandidateLimits()
    options = dict(expanded=('max_archive_bytes', 15000), total=('max_total_bytes', 19999),
                   member=('max_file_bytes', 19999), files=('max_files', 1), depth=('max_depth', 2), manifest=('max_manifest_bytes', 128))
    if limitation == 'files':
        values[0]['files'].append(dict(values[0]['files'][0], path='second'))
    name, value = options[limitation]
    with new_store(tmp_path, limits=replace(limits, **{name:value})) as store, pytest.raises(CandidateError):
        receive(store, values)
    assert not list((tmp_path / 'artifacts').iterdir())


@pytest.mark.parametrize('materials', [{}, {'dependency':b'wrong'}, {'dependency':b'pinned', 'extra':b'other'}])
def test_external_material_set_must_be_complete_and_exact(tmp_path, materials):
    values = fixture(tmp_path, materials={'dependency':b'pinned'})
    with new_store(tmp_path) as store, pytest.raises(CandidateError): receive(store, values, external_materials=materials)


def test_unexpanded_lfs_pointer_is_not_an_actual_large_file(tmp_path):
    values = fixture(tmp_path, content={'model.bin':(b'version https://git-lfs.github.com/spec/v1\noid sha256:' + b'a'*64 + b'\nsize 999\n', False)})
    with new_store(tmp_path) as store, pytest.raises(CandidateError, match='LFS'): receive(store, values)


def test_concurrent_same_name_publication_is_no_replace_and_read_back(tmp_path):
    values = fixture(tmp_path)
    first = new_store(tmp_path)
    second = CandidateStore(first.root)
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda store: receive(store, values), [first, second]))
        assert sorted(item['outcome'] for item in results) == ['already_present', 'stored']
        assert first.verify(results[0]['candidateDigest']) == values[0]
    finally:
        first.close(); second.close()


def test_existing_empty_object_directory_cannot_be_replaced(tmp_path):
    values = fixture(tmp_path)
    with new_store(tmp_path) as store:
        name = sha(codec.canonical(values[0]))[7:]
        occupied = store.root / name; occupied.mkdir(mode=0o700)
        inode = occupied.stat().st_ino
        with pytest.raises(CandidateError): receive(store, values)
        assert occupied.stat().st_ino == inode and not list(occupied.iterdir())


@pytest.mark.parametrize('mutation', ['file', 'mode', 'symlink', 'hardlink', 'extra', 'missing', 'binding', 'archive', 'external'])
def test_storage_drift_never_inherits_candidate_identity(tmp_path, mutation):
    values = fixture(tmp_path, materials={'dependency':b'pinned'})
    with new_store(tmp_path) as store:
        result = receive(store, values, external_materials={'dependency':b'pinned'})
        directory = store.root / result['candidateDigest'][7:]
        directory.chmod(0o700); tree = directory/'tree'; tree.chmod(0o700); target = tree/'README.md'
        if mutation == 'file': target.chmod(0o600); target.write_bytes(b'changed'); target.chmod(0o400)
        if mutation == 'mode': target.chmod(0o500)
        if mutation == 'symlink': target.unlink(); target.symlink_to(tmp_path/'source/README.md')
        if mutation == 'hardlink': os.link(target, tree/'alias')
        if mutation == 'extra': (tree/'extra').write_bytes(b'unknown')
        if mutation == 'missing': target.unlink()
        if mutation in ('binding', 'archive'):
            member = directory/('binding.json' if mutation == 'binding' else 'archive.bin')
            member.chmod(0o600); member.write_bytes(b'{}'); member.chmod(0o400)
        if mutation == 'external':
            materials = directory/'materials'; materials.chmod(0o700)
            member = materials/'dependency'; member.chmod(0o600); member.write_bytes(b'wrong'); member.chmod(0o400)
            materials.chmod(0o500)
        tree.chmod(0o500); directory.chmod(0o500)
        with pytest.raises((CandidateError, OSError)): store.verify(result['candidateDigest'])


def test_symlink_root_and_replaced_parent_are_rejected_without_writing_replacement(tmp_path):
    values = fixture(tmp_path)
    with new_store(tmp_path) as store:
        alias = tmp_path/'alias'; alias.symlink_to(store.root, target_is_directory=True)
        with pytest.raises(OSError): CandidateStore(alias)
        store.root.rename(tmp_path/'old-artifacts'); store.root.mkdir(mode=0o700)
        with pytest.raises(CandidateError, match='replaced'): receive(store, values)
        assert not list(store.root.iterdir()) and not list((tmp_path/'old-artifacts').iterdir())


def test_last_publication_boundary_parent_swap_is_detected_and_user_edit_is_preserved(tmp_path, monkeypatch):
    values = fixture(tmp_path)
    with new_store(tmp_path) as store:
        rename = implementation._rename_absent
        def replace_parent(directory, source, target):
            store.root.rename(tmp_path/'old-artifacts'); store.root.mkdir(mode=0o700)
            (store.root/'user-edit').write_bytes(b'preserve me')
            return rename(directory, source, target)
        monkeypatch.setattr(implementation, '_rename_absent', replace_parent)
        with pytest.raises(CandidateError, match='replaced'): receive(store, values)
        assert (store.root/'user-edit').read_bytes() == b'preserve me'
        assert len(list(store.root.iterdir())) == 1


def test_process_exit_during_file_writes_leaves_only_ineligible_pending_tree(tmp_path):
    values = fixture(tmp_path)
    root = tmp_path/'artifacts'; root.mkdir(mode=0o700)
    control = tmp_path/'input'; control.mkdir(mode=0o700)
    for name, raw in [('binding',codec.canonical(values[0])), ('commit',values[1]), ('archive',values[2])]:
        (control/name).write_bytes(raw)
    program = '''import os,sys
from pathlib import Path
from dasops.protected.candidates import CandidateStore
from dasops.protected.candidates import store as module
root,control=map(Path,sys.argv[1:]); count=0; original=module._write_file
def interrupted(*args,**kwargs):
    global count
    original(*args,**kwargs); count+=1
    if count==2: os._exit(27)
module._write_file=interrupted
with CandidateStore(root) as store:
    store.receive((control/'binding').read_bytes(),commit_bytes=(control/'commit').read_bytes(),archive_bytes=(control/'archive').read_bytes())
'''
    result = subprocess.run([sys.executable, '-c', program, str(root), str(control)], timeout=10)
    assert result.returncode == 27
    assert all(path.name.startswith('.pending-') for path in root.iterdir())
    with CandidateStore(root) as store:
        with pytest.raises(FileNotFoundError): store.verify(sha(codec.canonical(values[0])))
        assert receive(store, values)['outcome'] == 'stored'


def test_sync_failure_after_name_publication_does_not_return_success_and_can_be_reconciled(tmp_path, monkeypatch):
    values = fixture(tmp_path)
    with new_store(tmp_path) as store:
        sync = os.fsync
        def fail_root(descriptor):
            if descriptor == store._root_fd: raise OSError('injected root sync failure')
            return sync(descriptor)
        monkeypatch.setattr(os, 'fsync', fail_root)
        with pytest.raises(OSError, match='sync failure'): receive(store, values)
        monkeypatch.setattr(os, 'fsync', sync)
        digest = sha(codec.canonical(values[0]))
        assert store.verify(digest) == values[0]
        assert receive(store, values)['outcome'] == 'already_present'
        # This is process/API reconciliation, not proof under a power-loss model.


def test_deadline_failure_leaves_no_published_candidate(tmp_path, monkeypatch):
    values = fixture(tmp_path)
    with new_store(tmp_path, limits=CandidateLimits(seconds=1)) as store:
        original = implementation._write_file
        def too_late(*args, **kwargs):
            original(*args, **kwargs)
            time.sleep(1.05)
        monkeypatch.setattr(implementation, '_write_file', too_late)
        with pytest.raises(CandidateError, match='deadline'): receive(store, values)
        assert all(path.name.startswith('.pending-') for path in store.root.iterdir())


def test_repeated_legal_receipt_does_not_accumulate_duplicate_pending_trees(tmp_path):
    values = fixture(tmp_path)
    with new_store(tmp_path) as store:
        assert receive(store, values)['outcome'] == 'stored'
        for _ in range(4):
            assert receive(store, values)['outcome'] == 'already_present'
        assert len(list(store.root.iterdir())) == 1


@pytest.mark.parametrize('names', [['A','a'], ['CON'], ['NUL']])
def test_external_material_portable_path_collisions_are_rejected(tmp_path,names):
    payloads = {name:b'fixed' for name in names}
    values = fixture(tmp_path, materials=payloads)
    with new_store(tmp_path) as store, pytest.raises(CandidateError):
        receive(store,values,external_materials=payloads)


def test_closed_store_wrong_digest_and_expanded_limits_are_rejected(tmp_path):
    with new_store(tmp_path) as store:
        with pytest.raises(CandidateError): store.verify('../escape')
    with pytest.raises(CandidateError, match='closed'): store.verify(D)
    with pytest.raises(CandidateError): CandidateStore(tmp_path/'artifacts', limits=CandidateLimits(seconds=11))


def test_legal_many_directories_fit_a_small_actual_descriptor_budget(tmp_path):
    values = fixture(tmp_path,content={f'dir-{number:03}/file':(b'fixed',False) for number in range(100)})
    with new_store(tmp_path) as store:
        previous = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE,(64,previous[1]))
        try:
            result = receive(store,values)
            assert store.confirm_for_registration(result['candidateDigest']) == values[0]
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE,previous)


def test_reference_read_view_preserves_candidate_and_explicitly_maps_all_materials(tmp_path):
    content = {'run.py':(b'print("fixed reference")\n',False),'nested/data':(b'bytes',True)}
    values = fixture(tmp_path,content=content,materials={'dependency':b'pinned bytes'})
    with new_store(tmp_path) as store:
        digest = receive(store,values,external_materials={'dependency':b'pinned bytes'})['candidateDigest']
        view = store.prepare_reference_view(digest)
        assert view['candidateDigest']==digest and view['mappingDigest']==codec.digest(view['mapping'])
        assert view['profile']=='das-python-native-reference-view/v1'
        assert not view['authority'] and not view['qualification']
        root = Path(view['viewPath'])
        assert root.parent==store.root and root.name.startswith('.reference-')
        assert (root/'run.py').read_bytes()==content['run.py'][0]
        assert (root/'.das-external-materials/dependency').read_bytes()==b'pinned bytes'
        assert stat.S_IMODE((root/'run.py').stat().st_mode)==0o444
        assert stat.S_IMODE((root/'nested/data').stat().st_mode)==0o555
        assert stat.S_IMODE(root.stat().st_mode)==0o555
        assert store.verify(digest)==values[0]
        assert stat.S_IMODE((store.root/digest[7:] / 'tree/run.py').stat().st_mode)==0o400


@pytest.mark.parametrize('content', [{'other.py':(b'not the fixed entrypoint',False)},
    {'run.py':(b'print(1)',False),'.DAS-EXTERNAL-MATERIALS/file':(b'conflict',False)}])
def test_reference_view_refuses_missing_entrypoint_and_material_mapping_collision(tmp_path,content):
    values = fixture(tmp_path,content=content)
    with new_store(tmp_path) as store:
        digest = receive(store,values)['candidateDigest']
        with pytest.raises(CandidateError): store.prepare_reference_view(digest)
        assert store.verify(digest)==values[0]


def test_candidate_publication_rereads_final_name_before_reporting_success(tmp_path, monkeypatch):
    values = fixture(tmp_path)
    rename = implementation._rename_absent
    with new_store(tmp_path) as store:
        def change_published_file(directory, source, target):
            published = rename(directory, source, target)
            edited = store.root / target / 'tree/README.md'
            edited.chmod(0o600)
            edited.write_bytes(b'preserve concurrent edit')
            edited.chmod(0o400)
            return published
        monkeypatch.setattr(implementation, '_rename_absent', change_published_file)
        with pytest.raises(CandidateError, match='content or mode'):
            receive(store, values)
        digest = sha(codec.canonical(values[0]))
        assert (store.root / digest[7:] / 'tree/README.md').read_bytes() == b'preserve concurrent edit'


def test_reference_view_rejects_undeclared_empty_directory(tmp_path, monkeypatch):
    values = fixture(tmp_path, content={'run.py': (b'print(1)', False)})
    write = implementation._write_tree
    with new_store(tmp_path) as store:
        digest = receive(store, values)['candidateDigest']
        def add_empty_directory(directory, inventory, content, deadline, readable=False):
            write(directory, inventory, content, deadline, readable)
            os.fchmod(directory, 0o755)
            os.mkdir('undeclared', 0o755, dir_fd=directory)
            child = os.open('undeclared', implementation.DIRECTORY_FLAGS, dir_fd=directory)
            try:
                os.fchmod(child, 0o555)
            finally:
                os.close(child)
            os.fchmod(directory, 0o555)
        monkeypatch.setattr(implementation, '_write_tree', add_empty_directory)
        with pytest.raises(CandidateError, match='directory'):
            store.prepare_reference_view(digest)
        assert not any(path.name.startswith('.reference-') and not path.name.startswith('.reference-pending-')
                       for path in store.root.iterdir())
        assert store.verify(digest) == values[0]


@pytest.mark.parametrize('member', ['file', 'directory'])
def test_reference_view_rejects_path_replacement_during_actual_readback(tmp_path, monkeypatch, member):
    values = fixture(tmp_path, content={'run.py': (b'print(1)', False), 'nested/data': (b'expected', False)})
    write, read = implementation._write_tree, os.read
    selected = {}
    with new_store(tmp_path) as store:
        digest = receive(store, values)['candidateDigest']
        def select_readback_file(directory, inventory, content, deadline, readable=False):
            write(directory, inventory, content, deadline, readable)
            selected['root'] = Path(os.readlink('/proc/self/fd/' + str(directory)))
            selected['inode'] = (selected['root'] / 'nested/data').stat().st_ino
        def replace_readback_path(descriptor, count):
            raw = read(descriptor, count)
            if raw and os.fstat(descriptor).st_ino == selected.get('inode'):
                root = selected['root']
                selected['inode'] = None
                if member == 'file':
                    parent = root / 'nested'
                    parent.chmod(0o755)
                    (parent / 'data').rename(parent / 'retained-data')
                    (parent / 'data').write_bytes(b'preserve concurrent edit')
                    (parent / 'data').chmod(0o444)
                    parent.chmod(0o555)
                else:
                    root.chmod(0o755)
                    (root / 'nested').rename(root / 'retained-nested')
                    (root / 'nested').mkdir(mode=0o755)
                    (root / 'nested/data').write_bytes(b'preserve concurrent edit')
                    (root / 'nested/data').chmod(0o444)
                    (root / 'nested').chmod(0o555)
                    root.chmod(0o555)
            return raw
        monkeypatch.setattr(implementation, '_write_tree', select_readback_file)
        monkeypatch.setattr(os, 'read', replace_readback_path)
        with pytest.raises(CandidateError, match='changed|replaced'):
            store.prepare_reference_view(digest)
        assert (selected['root'] / 'nested/data').read_bytes() == b'preserve concurrent edit'
        assert store.verify(digest) == values[0]


def test_reference_view_rereads_published_path_before_returning_it(tmp_path, monkeypatch):
    values = fixture(tmp_path, content={'run.py': (b'print(1)', False)})
    rename = implementation._rename_absent
    with new_store(tmp_path) as store:
        digest = receive(store, values)['candidateDigest']
        def change_published_view(directory, source, target):
            published = rename(directory, source, target)
            edited = store.root / target / 'run.py'
            edited.chmod(0o644)
            edited.write_bytes(b'preserve concurrent edit')
            edited.chmod(0o444)
            return published
        monkeypatch.setattr(implementation, '_rename_absent', change_published_view)
        with pytest.raises(CandidateError, match='execution-view'):
            store.prepare_reference_view(digest)
        assert store.verify(digest) == values[0]
        published = [path for path in store.root.iterdir()
                     if path.name.startswith('.reference-') and not path.name.startswith('.reference-pending-')]
        assert len(published) == 1
        assert (published[0] / 'run.py').read_bytes() == b'preserve concurrent edit'


@pytest.mark.parametrize('mutation', ['tree-replaced', 'materials-replaced', 'tree-extra', 'materials-extra'])
def test_candidate_readback_detects_directory_changes_after_inventory_read(tmp_path, monkeypatch, mutation):
    values = fixture(tmp_path, materials={'dependency': b'pinned'})
    read = os.read
    with new_store(tmp_path) as store:
        digest = receive(store, values, external_materials={'dependency': b'pinned'})['candidateDigest']
        root = store.root / digest[7:]
        kind = mutation.split('-')[0]
        directory = root / kind
        file = directory / ('README.md' if kind == 'tree' else 'dependency')
        selected_inode = file.stat().st_ino
        changed = []
        def mutate_readback_directory(descriptor, count):
            raw = read(descriptor, count)
            if raw and not changed and os.fstat(descriptor).st_ino == selected_inode:
                if mutation.endswith('replaced'):
                    root.chmod(0o700)
                    directory.rename(root / ('retained-' + kind))
                    directory.mkdir(mode=0o700)
                    edited = directory / 'user-edit'
                    edited.write_bytes(b'preserve concurrent edit')
                    edited.chmod(0o400)
                    directory.chmod(0o500)
                    root.chmod(0o500)
                else:
                    directory.chmod(0o700)
                    edited = directory / 'user-edit'
                    edited.write_bytes(b'preserve concurrent edit')
                    edited.chmod(0o400)
                    directory.chmod(0o500)
                changed.append(edited)
            return raw
        monkeypatch.setattr(os, 'read', mutate_readback_directory)
        with pytest.raises(CandidateError, match='changed|replaced'):
            store.verify(digest)
        assert changed[0].read_bytes() == b'preserve concurrent edit'
