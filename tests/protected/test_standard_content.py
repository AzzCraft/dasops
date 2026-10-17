"""Physical content boundaries; no release/migration/activation approval."""
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import time
import zipfile

import pytest

from dasops.protected.bundle import BundleError, NativeBundleResolver, _standard_content, _standard_references


@pytest.mark.parametrize('templates,paths', [
    ({'tree/UI.md':'ui_spec'}, ['tree/../UI.md']),
    ({'tree/UI.md':'ui_spec'}, ['tree/UI.md','tree/UI.md']),
    ({'tree/UI.md':'ui_spec'}, [['tree/UI.md']]),
    ({'tree/UI.md':'ui_spec'}, ['materials/UI.md']),
    ({'tree/UI.md':'ui_spec'}, ['tree/OTHER.md']),
    ({'tree/PACK.json':'context_pack'}, ['tree/PACK.json']),
    ({}, ['tree/UI.md']),
])
def test_adoption_installed_mapping_rejects_escapes_ambiguous_selection_and_pack_cycles(templates,paths):
    from dasops.adopt import GovernedAdoption
    from dasops.protected.candidates import CandidateError
    # Constructor-only test, no native approval or resolved content claimed.
    resolver=object.__new__(NativeBundleResolver)
    with pytest.raises(CandidateError):
        GovernedAdoption(resolver,templates=templates,source_paths=paths)


def test_adoption_mapping_is_copied_from_installer_and_cannot_be_edited_by_request():
    from dasops.adopt import GovernedAdoption
    templates={'tree/UI.md':'ui_spec'};paths=['tree/UI.md']
    prepared=GovernedAdoption(object.__new__(NativeBundleResolver),templates=templates,source_paths=paths)
    templates['tree/UI.md']='context_pack';paths[0]='tree/OTHER.md'
    assert dict(prepared.templates)=={'tree/UI.md':'ui_spec'}
    assert prepared.source_paths==('tree/UI.md',)
    with pytest.raises(TypeError):prepared.templates['tree/UI.md']='context_pack'


def test_adoption_selection_can_pin_supporting_material_without_making_it_a_template():
    from dasops.adopt import GovernedAdoption
    paths=['materials/dependency','tree/UI.md']
    prepared=GovernedAdoption(object.__new__(NativeBundleResolver),
        templates={'tree/UI.md':'ui_spec'},source_paths=paths)
    paths[0]='materials/other'
    assert prepared.source_paths==('materials/dependency','tree/UI.md')


@pytest.mark.parametrize('path',['materials/../dependency','materials/nested/dependency',
    'materials/','materials/.hidden','materials/with.dot','materials/CON','materials/'+'x'*65,
    'materials/dependency\n','other/dependency'])
def test_adoption_material_selection_requires_one_exact_portable_material_id(path):
    from dasops.adopt import GovernedAdoption
    from dasops.protected.candidates import CandidateError
    with pytest.raises(CandidateError):
        GovernedAdoption(object.__new__(NativeBundleResolver),templates={'tree/UI.md':'ui_spec'},
            source_paths=sorted([path,'tree/UI.md']))


def test_adoption_material_cannot_replace_a_pinned_standard_template_destination():
    from dasops.adopt import GovernedAdoption
    from dasops.protected.candidates import CandidateError
    with pytest.raises(CandidateError):
        GovernedAdoption(object.__new__(NativeBundleResolver),
            templates={'materials/dependency':'ui_spec'},source_paths=['materials/dependency'])


SECTION_AUTHOR = dict(templateKind='minimal_governed',sectionAnchor='appendix-m-prd-template')
SECTION_SOURCE = b'''# Shared appendix
## Appendix M PRD Template
### Document Control
- **Doc ID:** <id>
- **Owner:** <owner>
- **Status:** draft
### Goals
<goals>
## Appendix M Runbook Template
Do not copy this sibling.
'''


FULL_AUTHOR = dict(templateKind='canonical_full')
FULL_SOURCE = b'''# Canonical document
<a id="document"></a>
## Document Control
- **Doc ID**: `{{DOC_ID}}`
- **Owner**: `{{OWNER}}`
- **Status**: `{{STATUS}}`
## Project
- **Success is**: {{BODY}}
[[LOCAL_LINK]]
```text
{{OWNER}} [[LOCAL_LINK]] <Type>
``` trailing text does not close this example
{{OWNER}}
````
backend <-> db
'''


def test_canonical_template_fills_literal_project_fields_and_preserves_examples():
    from dasops.adopt import render_full_template
    values=dict(DOC_ID='MASTER-7', OWNER='existing-project-owner', STATUS='draft',
        BODY='Existing <Widget> API.\n```text\n{{OWNER}} is literal project code.\n```',
        LOCAL_LINK='docs/local.md')
    actual=render_full_template(FULL_AUTHOR,FULL_SOURCE,values)
    assert b'- **Doc ID**: `MASTER-7`' in actual
    assert b'- **Owner**: `existing-project-owner`' in actual
    assert values['BODY'].encode() in actual
    assert b'```text\n{{OWNER}} [[LOCAL_LINK]] <Type>\n``` trailing text does not close this example\n{{OWNER}}\n````' in actual
    assert b'<a id="document"></a>' in actual and b'backend <-> db' in actual


@pytest.mark.parametrize('fault', ['unknown','empty','nul','unresolved','metadata-line',
    'active-unfilled','status-whitespace','oversized','wrong-kind','invalid-utf8'])
def test_canonical_template_refuses_invalid_fields_and_false_placeholder_readiness(fault):
    from dasops.adopt import render_full_template
    from dasops.protected.candidates import CandidateError
    author=dict(FULL_AUTHOR);source=FULL_SOURCE;values={'OWNER':'owner','STATUS':'draft'}
    if fault=='unknown':values['not a field']='data'
    elif fault=='empty':values['OWNER']=' '
    elif fault=='nul':values['OWNER']='bad\x00text'
    elif fault=='unresolved':values['OWNER']='{{OWNER}}'
    elif fault=='metadata-line':values['OWNER']='owner\n- **Status**: active'
    elif fault=='active-unfilled':values['STATUS']='active'
    elif fault=='status-whitespace':values['STATUS']=' active '
    elif fault=='oversized':values['BODY']='x'*65536
    elif fault=='wrong-kind':author['templateKind']='minimal_governed'
    elif fault=='invalid-utf8':source=b'\xff'
    with pytest.raises(CandidateError):render_full_template(author,source,values)


def test_canonical_template_all_required_fields_can_be_filled_without_expanding_code():
    from dasops.adopt import render_full_template
    values=dict(DOC_ID='MASTER-7',OWNER='owner',STATUS='active',BODY='Approved project prose.')
    actual=render_full_template(FULL_AUTHOR,FULL_SOURCE,values)
    assert b'- **Status**: `active`' in actual
    assert b'[[LOCAL_LINK]]' in actual  # Optional prose may remain; examples always do.
    assert b'{{OWNER}}' in actual


@pytest.mark.parametrize('kind', ['master_doc','ui_spec'])
def test_real_canonical_authors_accept_explicit_draft_project_fields(kind):
    from dasops.adopt import render_full_template
    standard=Path(__file__).resolve().parents[3]/'das-standard'
    author=next(row for row in json.loads((standard/'template_catalog.json').read_bytes())['templates'] if row['docType']==kind)
    raw=(standard/author['artifactPath']).read_bytes()
    values={'DOC_ID':'PROJECT-7','OWNER':'actual-owner','STATUS':'draft'}
    values['USER_OUTCOME' if kind=='master_doc' else 'WHAT_USER_IS_DOING_HERE']='Approved local outcome.\nSecond line stays.'
    actual=render_full_template(author,raw,values)
    assert b'- **Doc ID**: `PROJECT-7`' in actual
    assert b'- **Owner**: `actual-owner`' in actual
    assert b'- **Status**: `draft`' in actual
    assert b'Approved local outcome.\nSecond line stays.' in actual
    assert len(actual)>len(raw)//2  # Retain the full author, not Appendix M extraction.


def test_section_template_extracts_one_author_and_preserves_literal_local_content():
    from dasops.adopt import render_section_template, GovernedAdoption
    values={'id':'PRD-1','owner':'actual-owner','goals':'Existing local requirement.\nSecond line stays.'}
    rendered=render_section_template(SECTION_AUTHOR,SECTION_SOURCE,values)
    assert rendered==b'''## Appendix M PRD Template
### Document Control
- **Doc ID:** PRD-1
- **Owner:** actual-owner
- **Status:** draft
### Goals
Existing local requirement.
Second line stays.
'''
    mapping={'tree/PRD.md':dict(values)}
    adoption=GovernedAdoption(object.__new__(NativeBundleResolver),templates={'tree/PRD.md':'prd'},
        source_paths=['tree/PRD.md'],template_values=mapping)
    mapping['tree/PRD.md']['owner']='changed'
    assert adoption.template_values['tree/PRD.md']['owner']=='actual-owner'
    with pytest.raises(TypeError):adoption.template_values['tree/PRD.md']['owner']='changed'


def test_section_template_preserves_explicit_local_code_and_markup_as_literal_data():
    from dasops.adopt import render_section_template
    local='Keep the approved <Widget> API.\n```text\n<owner> is a code example.\n```\n本地目标和验收要求保持。'
    values={'id':'PROJECT-PRD-7','owner':'项目负责人','goals':local}
    rendered=render_section_template(SECTION_AUTHOR,SECTION_SOURCE,values)
    assert local.encode() in rendered
    assert b'- **Doc ID:** PROJECT-PRD-7\n' in rendered
    assert '- **Owner:** 项目负责人\n'.encode() in rendered
    assert b'Runbook Template' not in rendered


@pytest.mark.parametrize('fault',['missing','extra','unresolved','empty','metadata-line','missing-anchor',
    'duplicate-anchor','fenced-anchor','whole-appendix','oversized'])
def test_section_template_rejects_ambiguous_authors_or_incomplete_instantiation(fault):
    from dasops.adopt import render_section_template
    from dasops.protected.candidates import CandidateError
    source=SECTION_SOURCE;author=dict(SECTION_AUTHOR);values={'id':'PRD-1','owner':'owner','goals':'local text'}
    if fault=='missing':values.pop('owner')
    elif fault=='extra':values['unapproved']='text'
    elif fault=='unresolved':values['goals']='<another-placeholder>'
    elif fault=='empty':values['owner']=' '
    elif fault=='metadata-line':values['owner']='owner\n- **Status:** approved'
    elif fault=='missing-anchor':author['sectionAnchor']='absent'
    elif fault=='duplicate-anchor':source+=b'\n## Appendix M PRD Template\n'
    elif fault=='fenced-anchor':source=b'```md\n'+source+b'```\n'
    elif fault=='whole-appendix':author['templateKind']='canonical_full'
    else:values['goals']='x'*65536
    with pytest.raises(CandidateError):render_section_template(author,source,values)


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _package(root):
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    names = ['SPECIFICATION.md', 'VERSION', 'standard_manifest.json',
             'standard_modules.json', 'standard_requirements.json']
    members = {'SPECIFICATION.md': b'TEST normative source\n', 'VERSION': b'1.5.0-beta.1\n',
        'standard_manifest.json': json.dumps(dict(standardVersion='1.5.0-beta.1',
            requiredArtifacts=[*names, 'release_snapshot_manifest.json'])).encode(),
        'standard_modules.json': b'{}', 'standard_requirements.json': b'{}'}
    for name, raw in members.items():
        (root/name).write_bytes(raw); (root/name).chmod(0o644)
    snapshot = dict(schemaVersion='1.0.0', standardVersion='1.5.0-beta.1',
        standardManifestVersion='1.5.0-beta.1', snapshotKind='standard_content_bundle',
        createdAt='2026-10-07T00:00:00Z', buildRef='TEST-content',
        sourceRepoRef=dict(kind='custom', uri='content-manifest://TEST',
            pinType='version', pinValue='1.5.0-beta.1', floating=False),
        bundleDigestAlgorithm='sha256', bundleDigest='',
        artifacts=[dict(path=name, sha256=_hash(members[name]), artifactClass='normative', required=True)
                   for name in sorted(names)],
        mirrorRules=dict(localMirrorAllowed=True, requireSnapshotRefForMirror=True, allowLocalModifications=False))
    return snapshot


def _pin(root, snapshot):
    joined='\n'.join(f"{row['path']}:{row['sha256']}" for row in snapshot['artifacts']).encode()
    snapshot['bundleDigest'] = _hash(joined)
    raw = json.dumps(snapshot).encode()
    (root/'release_snapshot_manifest.json').write_bytes(raw)
    (root/'release_snapshot_manifest.json').chmod(0o644)
    return 'sha256:' + _hash(raw)


def test_actual_closed_content_returns_both_original_digest_domains(tmp_path):
    root=tmp_path/'installed'; snapshot=_package(root); pin=_pin(root,snapshot)
    ref, members=_standard_content(root,pin,'1.5.0-beta.1',time.clock_gettime(time.CLOCK_BOOTTIME)+5)
    assert ref == dict(snapshotDigest=pin, contentDigest='sha256:'+snapshot['bundleDigest'])
    assert members['VERSION'] == b'1.5.0-beta.1\n'


def _distribution(root, archive, *, compression=zipfile.ZIP_DEFLATED, fault=None):
    members={p.name:p.read_bytes() for p in root.iterdir()}
    if fault=='changed-member':members['SPECIFICATION.md']=b'TEST other content\n'
    elif fault=='changed-snapshot':members['release_snapshot_manifest.json']+=b'\n'
    elif fault=='missing':members.pop('VERSION')
    elif fault=='extra':members['unexpected.txt']=b'not declared'
    elif fault=='escape':members['../unexpected.txt']=b'outside'
    elif fault=='oversized':members['SPECIFICATION.md']=b'x'*(4*1024*1024+1)
    with zipfile.ZipFile(archive,'w',compression=compression) as zipped:
        for name,raw in members.items():
            entry=zipfile.ZipInfo(name);entry.compress_type=compression
            entry.external_attr=(stat.S_IFLNK|0o777)<<16 if fault=='link' and name=='VERSION' else (stat.S_IFREG|0o644)<<16
            zipped.writestr(entry,raw)
        if fault=='duplicate':
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter('ignore',UserWarning);zipped.writestr('VERSION',members['VERSION'])
        if fault=='directory':zipped.writestr('extra/',b'')
    archive.chmod(0o600)
    return 'sha256:'+_hash(archive.read_bytes())


@pytest.mark.parametrize('compression',[zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED])
def test_distribution_pin_binds_exact_archive_to_verified_installed_content(tmp_path,compression):
    from dasops.protected.bundle import _standard_distribution
    root=tmp_path/'installed';snapshot=_package(root);pin=_pin(root,snapshot)
    ref,members=_standard_content(root,pin,'1.5.0-beta.1',time.clock_gettime(time.CLOCK_BOOTTIME)+5)
    archive=tmp_path/'standard.zip';artifact_pin=_distribution(root,archive,compression=compression)
    assert artifact_pin!=ref['snapshotDigest']
    assert _standard_distribution(archive,artifact_pin,members,time.clock_gettime(time.CLOCK_BOOTTIME)+5)==artifact_pin


@pytest.mark.parametrize('distribution', [dict(standard_archive='/not-read/standard.zip'),
    dict(standard_archive_sha256='sha256:'+'1'*64),
    dict(standard_archive='relative.zip',standard_archive_sha256='sha256:'+'1'*64),
    dict(standard_archive='/not-read/standard.zip',standard_archive_sha256='sha256:'+'1'*64+'\n')])
def test_distribution_configuration_rejects_unbound_or_ambiguous_pins_before_native_work(distribution):
    with pytest.raises(BundleError,match='distribution'):
        NativeBundleResolver(binary='/not-read/cadence',binary_sha256='sha256:'+'1'*64,
            release_version='1.2.0-beta.1',load_control=lambda *args:None,
            authorize=lambda *args:True,**distribution)


@pytest.mark.parametrize('fault',['changed-member','changed-snapshot','missing','extra','escape',
    'oversized','duplicate','directory','link','compression','changed-pin','symlink','hardlink',
    'writable','expired','invalid-zip','corrupt-stream'])
def test_installer_pinned_archive_still_requires_exact_safe_content_closure(tmp_path,fault):
    from dasops.protected.bundle import _standard_distribution
    root=tmp_path/'installed';snapshot=_package(root);pin=_pin(root,snapshot)
    _,members=_standard_content(root,pin,'1.5.0-beta.1',time.clock_gettime(time.CLOCK_BOOTTIME)+5)
    archive=tmp_path/'standard.zip';artifact_pin=_distribution(root,archive,
        compression=zipfile.ZIP_BZIP2 if fault=='compression' else zipfile.ZIP_DEFLATED,fault=fault)
    deadline=time.clock_gettime(time.CLOCK_BOOTTIME)+5
    if fault=='changed-pin':artifact_pin='sha256:'+'0'*64
    elif fault=='symlink':
        retained=tmp_path/'retained.zip';archive.rename(retained);archive.symlink_to(retained)
    elif fault=='hardlink':os.link(archive,tmp_path/'shared.zip')
    elif fault=='writable':archive.chmod(0o666)
    elif fault=='expired':deadline=time.clock_gettime(time.CLOCK_BOOTTIME)-1
    elif fault=='invalid-zip':archive.write_bytes(b'not a ZIP');artifact_pin='sha256:'+_hash(archive.read_bytes())
    elif fault=='corrupt-stream':
        with zipfile.ZipFile(archive) as zipped:entry=zipped.getinfo('SPECIFICATION.md')
        raw=bytearray(archive.read_bytes());offset=entry.header_offset+30+len(entry.filename.encode())+len(entry.extra)
        raw[offset]^=0xff;archive.write_bytes(raw);artifact_pin='sha256:'+_hash(raw)
    with pytest.raises((BundleError,OSError)):
        _standard_distribution(archive,artifact_pin,members,deadline)


def test_physical_fragment_check_uses_unicode_columns_and_original_text_hash_domain():
    raw = '甲🙂\r\nMUST retain original scope\r\n'.encode()
    text = '甲🙂\nMUST'
    ref = dict(path='author.md',startLine=1,endLine=2,startColumn=0,endColumn=len(text),
               textSha256=_hash(text.encode()))
    _standard_references({'author.md':raw}, [ref,dict(ref)], time.clock_gettime(time.CLOCK_BOOTTIME)+5)
    # The old textual hash is independent of physical CRLF byte spelling.
    assert ref['textSha256'] != _hash(raw[:len(text)])


@pytest.mark.parametrize('fault', ['missing','changed','wrong-hash','bad-unicode','boolean-line',
    'zero-line','outside-line','negative-column','outside-column','empty-span','expired'])
def test_physical_fragment_check_rejects_bad_source_or_span(fault):
    sources={'author.md':b'MUST preserve scope\n'}
    ref=dict(path='author.md',startLine=1,endLine=1,startColumn=0,endColumn=4,
             textSha256=_hash(b'MUST'))
    deadline=time.clock_gettime(time.CLOCK_BOOTTIME)+5
    if fault=='missing':sources.clear()
    elif fault=='changed':sources['author.md']=b'MAY  preserve scope\n'
    elif fault=='wrong-hash':ref['textSha256']='0'*64
    elif fault=='bad-unicode':sources['author.md']=b'\xff'
    elif fault=='boolean-line':ref['startLine']=True
    elif fault=='zero-line':ref['startLine']=0
    elif fault=='outside-line':ref['endLine']=2
    elif fault=='negative-column':ref['startColumn']=-1
    elif fault=='outside-column':ref['endColumn']=100
    elif fault=='empty-span':ref['endColumn']=0
    elif fault=='expired':deadline=time.clock_gettime(time.CLOCK_BOOTTIME)-1
    with pytest.raises((BundleError,UnicodeError)):
        _standard_references(sources,[ref],deadline)


@pytest.mark.parametrize('fault', ['changed-body','changed-pin','duplicate','unsorted','unsafe-path',
    'wrong-edition','lost-required','optional-member','digest-newline','symlink','hardlink',
    'writable-root','writable-file','fifo','oversized','expired'])
def test_even_installer_pinned_content_rejects_invalid_member_boundary(tmp_path, fault):
    root=tmp_path/'installed'; snapshot=_package(root); pin=_pin(root,snapshot)
    deadline=time.clock_gettime(time.CLOCK_BOOTTIME)+5
    if fault=='changed-body': (root/'SPECIFICATION.md').write_bytes(b'TEST tamper')
    elif fault=='changed-pin': pin+='\n'
    elif fault=='duplicate': snapshot['artifacts'].append(dict(snapshot['artifacts'][0]))
    elif fault=='unsorted': snapshot['artifacts'].reverse()
    elif fault=='unsafe-path': snapshot['artifacts'][0]['path']='../SPECIFICATION.md'
    elif fault=='wrong-edition': snapshot['standardVersion']='1.4.0'
    elif fault=='lost-required': snapshot['artifacts'].pop(0)
    elif fault=='optional-member': snapshot['artifacts'][0]['required']=False
    elif fault=='digest-newline': snapshot['artifacts'][0]['sha256']+='\n'
    elif fault=='symlink':
        body=root/'SPECIFICATION.md'; raw=body.read_bytes(); body.unlink()
        outside=tmp_path/'outside'; outside.write_bytes(raw); body.symlink_to(outside)
    elif fault=='hardlink': os.link(root/'SPECIFICATION.md',tmp_path/'shared')
    elif fault=='writable-root': root.chmod(0o777)
    elif fault=='writable-file': (root/'SPECIFICATION.md').chmod(0o666)
    elif fault=='fifo': (root/'SPECIFICATION.md').unlink(); os.mkfifo(root/'SPECIFICATION.md')
    elif fault=='oversized':
        with (root/'SPECIFICATION.md').open('wb') as stream: stream.truncate(4*1024*1024+1)
    elif fault=='expired': deadline=time.clock_gettime(time.CLOCK_BOOTTIME)-1
    if fault in ('duplicate','unsorted','unsafe-path','wrong-edition','lost-required','optional-member','digest-newline'):
        pin=_pin(root,snapshot)
    with pytest.raises((BundleError, ValueError, OSError)):
        _standard_content(root,pin,'1.5.0-beta.1',deadline)
