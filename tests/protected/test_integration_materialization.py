"""Independent Git/byte observations of the fixed whole-file composition path."""
import os
import subprocess

import pytest

from dasops.protected.candidates import CandidateError
from tests.protected.test_candidate_store import fixture, receive, new_store, D


@pytest.fixture
def inputs(tmp_path):
    before = tmp_path / 'B'; before.mkdir()
    source = tmp_path / 'C'; source.mkdir()
    base = fixture(before, content={'keep.txt': (b'from target B', False),
        'change.txt': (b'old content', False), 'delete.txt': (b'retired', False)},
        materials={'dependency': b'old material'})
    candidate = fixture(source, content={'change.txt': (b'from source C', True),
        'new.txt': (b'new source file', False)}, materials={'dependency': b'new material'})
    with new_store(tmp_path) as store:
        b = receive(store, base, external_materials={'dependency': b'old material'})['candidateDigest']
        c = receive(store, candidate, external_materials={'dependency': b'new material'})['candidateDigest']
        yield store, b, c, base, candidate


def compose(inputs, **overrides):
    store, b, c, *_ = inputs
    options = dict(source_paths=['materials/dependency', 'tree/change.txt', 'tree/new.txt'],
        deleted_paths=['tree/delete.txt'], tool_digest=D)
    options.update(overrides)
    return store.compose_integration(b, c, **options)


def test_actual_i_combines_b_c_files_modes_materials_and_independent_git_identity(inputs, tmp_path):
    store, b, c, base, source = inputs
    result = compose(inputs); i = result['candidateDigest']
    binding = store.verify(i)
    assert i not in (b, c)
    tree = store.root / i[7:] / 'tree'
    assert sorted(p.name for p in tree.iterdir()) == ['change.txt', 'keep.txt', 'new.txt']
    assert (tree / 'keep.txt').read_bytes() == b'from target B'
    assert (tree / 'change.txt').read_bytes() == b'from source C'
    assert os.stat(tree / 'change.txt').st_mode & 0o777 == 0o500
    assert (store.root / i[7:] / 'materials/dependency').read_bytes() == b'new material'
    # Independent native Git computes the object ID from the produced commit.
    raw = (store.root / i[7:] / 'commit.bin').read_bytes()
    checked = subprocess.run(['/usr/bin/git', 'hash-object', '-t', 'commit', '--stdin'],
        input=raw, capture_output=True, check=True, cwd=tmp_path,
        env={'PATH':'/usr/bin:/bin', 'HOME':'/nonexistent', 'GIT_CONFIG_NOSYSTEM':'1', 'GIT_CONFIG_GLOBAL':'/dev/null'})
    assert checked.stdout.decode().strip() == binding['source']['commitOid']
    assert raw.splitlines()[1:3] == [('parent '+base[0]['source']['commitOid']).encode(),
        ('parent '+source[0]['source']['commitOid']).encode()]
    assert result['lineage'] == store.integration_lineage(b, c, i, tool_digest=D)
    replay = compose(inputs)
    assert replay['candidateDigest'] == i and replay['lineage'] == result['lineage']
    assert replay['outcome'] == 'already_present'
    assert not result['authority'] and not result['qualification']


@pytest.mark.parametrize('fault',['unknown', 'unsorted', 'duplicate', 'overlap', 'missing-delete', 'all-delete'])
def test_invalid_selection_never_publishes_or_changes_input_trees(inputs, fault):
    store, b, c, *_ = inputs
    names = sorted(p.name for p in store.root.iterdir())
    options = {}
    if fault == 'unknown': options['source_paths'] = ['tree/absent.txt']
    elif fault == 'unsorted': options['source_paths'] = ['tree/new.txt', 'tree/change.txt']
    elif fault == 'duplicate': options['source_paths'] = ['tree/change.txt', 'tree/change.txt']
    elif fault == 'overlap': options['deleted_paths'] = ['tree/change.txt']
    elif fault == 'missing-delete': options['deleted_paths'] = ['tree/absent.txt']
    else:
        options.update(source_paths=[], deleted_paths=['materials/dependency','tree/change.txt','tree/delete.txt','tree/keep.txt'])
    with pytest.raises(CandidateError): compose(inputs, **options)
    assert sorted(p.name for p in store.root.iterdir()) == names
    assert store.verify(b) and store.verify(c)


def test_unrelated_valid_complete_i_cannot_claim_b_c_materialization(inputs, tmp_path):
    store, b, c, *_ = inputs
    unrelated = tmp_path / 'unrelated'; unrelated.mkdir()
    i = receive(store, fixture(unrelated, content={'change.txt':(b'unrelated bytes',False)}))['candidateDigest']
    with pytest.raises(CandidateError): store.integration_lineage(b, c, i, tool_digest=D)
    assert store.verify(i) and store.verify(b) and store.verify(c)
