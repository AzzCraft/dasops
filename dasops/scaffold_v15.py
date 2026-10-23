"""Finite 1.5 scaffold, local Suite inputs and installed-runtime checks.

This file is also copied into generated products. It has no protected-state or
service dependency. Native execution remains Cadence's responsibility.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry

EDITION = '1.5.0-beta.1'
STATE = '.dasops-scaffold.json'
SUITE_FILES = ('suite_lock.json', 'suite.tooling_lock.json', 'suite_version_closure.json')
SCHEMAS = {'suite_lock.json': 'suite_lock.schema.json',
           'suite.tooling_lock.json': 'tooling_lock.schema.json',
           'suite_version_closure.json': 'suite_version_closure.schema.json',
           'tooling_lock.json': 'tooling_lock.schema.json',
           'local_extension_manifest.json': 'local_extension_manifest.schema.json'}
VENDOR = 'vendor/cadence/cadence-oss'


class PublicationRecoveryRequired(RuntimeError):
    """A concurrent filesystem conflict left data requiring explicit recovery."""



def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def read(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'regular input file required: {path.name}')
    return path.read_bytes()


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError(f'duplicate JSON key: {key}')
        result[key] = value
    return result


def load(path):
    return json.loads(read(path), object_pairs_hook=_pairs)


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def local(root, ref):
    """Resolve only product-local references; never fetch a remote schema/ref."""
    uri = ref.get('uri') if isinstance(ref, dict) else ref
    if not isinstance(uri, str) or not uri or Path(uri).is_absolute() or '..' in Path(uri).parts:
        raise ValueError('relative local path required')
    path = Path(root) / uri
    if not path.resolve().is_relative_to(Path(root).resolve()):
        raise ValueError('local reference escapes its root')
    if any(p.is_symlink() for p in (path, *path.parents) if p.is_relative_to(Path(root))):
        raise ValueError('linked local reference is unsupported')
    return path


def schema_check(value, schema_path):
    schema = load(schema_path)
    Draft202012Validator.check_schema(schema)
    errors = list(Draft202012Validator(schema, registry=Registry(), format_checker=FormatChecker()).iter_errors(value))
    if errors: raise ValueError(schema_path.name + ': ' + errors[0].message)


def file_ref(path):
    return dict(kind='file', uri=path, pinType='manifest', pinValue=path, floating=False)


def git(root, *args):
    proc = subprocess.run(['git', '-C', str(root), *args], capture_output=True, text=True, timeout=30)
    if proc.returncode:
        raise ValueError('Git input check failed: ' + proc.stderr.strip())
    return proc.stdout.strip()


def suite_inputs(suite):
    suite = Path(suite).expanduser().resolve()
    if git(suite, 'status', '--porcelain'):
        raise ValueError('Suite workspace must be clean')
    # Select Suite code explicitly, retain this interpreter's declared dependencies.
    program = ('import sys,json;sys.path[0]=sys.argv[1];'
               'from pathlib import Path;from dassuite.report import generate_report;'
               'print(json.dumps(generate_report(Path(sys.argv[1]),enforce_workspace=True)))')
    environment=dict(os.environ);environment.pop('PYTHONPATH',None)
    proc = subprocess.run([sys.executable, '-B', '-c', program, str(suite)],
                          cwd=suite,env=environment,capture_output=True, text=True, timeout=60)
    if proc.returncode:
        raise ValueError('Suite report failed: ' + proc.stderr.strip())
    report = json.loads(proc.stdout)
    if report['issues']:
        raise ValueError('Suite workspace: ' + '; '.join(report['issues']))
    if git(suite, 'status', '--porcelain'):
        raise ValueError('Suite workspace must be clean')
    modules = {m['id']: m for m in report['modules']}
    if set(modules) != {'das-standard', 'dasops', 'cadence-oss'}:
        raise ValueError('expected the three public OSS modules')
    for m in modules.values():
        if m['state'] != 'present_locked_match' or m['currentHead'] != m['expectedPinValue']:
            raise ValueError('Suite module is not fixed: ' + m['id'])
    return suite, {k: Path(v['resolvedPath']) for k, v in modules.items()}, report


def code_identity(factory, resources):
    """Bind loaded code AND templates to the fixed Suite factory, including wheels."""
    actual = Path(__file__).resolve().parent
    expected = factory / 'dasops'
    observed = {}
    for base, installed in ((expected, actual), (factory / 'templates', resources / 'templates')):
        files = [p for p in base.rglob('*') if p.is_file() and '__pycache__' not in p.parts
                 and (base.name == 'templates' or p.suffix in ('.py', '.json', '.sql'))]
        for path in files:
            rel = path.relative_to(base)
            target = installed / rel
            if read(target) != read(path):
                raise ValueError('executing factory code/resources differ from Suite: ' + str(rel))
            observed[str(path.relative_to(factory))] = digest(read(target))
    return digest(json.dumps(observed, sort_keys=True).encode())


def metadata(text):
    result = {}
    fence = None
    control_level = None
    for line in text.splitlines():
        mark = re.match(r'^\s*(`{3,}|~{3,})', line)
        if mark:
            if fence is None: fence = mark[1][0]
            elif fence == mark[1][0]: fence = None
            continue
        if fence is not None: continue
        heading = re.match(r'^(#{1,6})\s+(.+)', line)
        if heading:
            if 'document control' in heading[2].lower(): control_level = len(heading[1])
            elif control_level is not None and len(heading[1]) <= control_level: break
        if control_level is None: continue
        match = re.match(r'^\s*-\s+\*\*([^*]+)\*\*:?\s*(.+)', line)
        if match:
            key = re.sub(r'\s*\([^)]*\)', '', match[1].rstrip(':')).strip()
            value = re.sub(r'^\([^)]*\):\s*', '', match[2].strip())
            value = value.split('`')[1] if value.startswith('`') else value
            if key in result and result[key] != value:
                raise ValueError('ambiguous document metadata: ' + key)
            result[key] = value
    return result


def headings(text):
    result = []; fence = None
    for line in text.splitlines():
        mark = re.match(r'^\s*(`{3,}|~{3,})', line)
        if mark:
            if fence is None: fence = mark[1][0]
            elif fence == mark[1][0]: fence = None
            continue
        if fence is None and re.match(r'^#{1,6}\s+', line): result.append(line.strip())
    return result


def author_section(entry, source):
    text = source.decode('utf-8')
    if entry['templateKind'] == 'canonical_full': return text
    rows = text.splitlines(keepends=True); selected = []; level = None
    for line in rows:
        h = re.match(r'^(#{1,6})\s+(.+)', line)
        if h:
            slug = re.sub(r'[^\w\- ]', '', h[2].strip().lower()).replace(' ', '-')
            if level is not None and len(h[1]) <= level: break
            if slug == entry['sectionAnchor']: level = len(h[1])
        if level is not None: selected.append(line)
    if not selected: raise ValueError('template section not found')
    return ''.join(selected)


def document_prose(text):
    """Exclude fenced examples and comments from document-reference decisions."""
    rows=[];fence=None
    for line in re.sub(r'<!--.*?-->','',text,flags=re.S).splitlines():
        mark=re.match(r'^ {0,3}(`{3,}|~{3,})(.*)$',line)
        if mark:
            if fence is None:fence=mark[1]
            elif mark[1][0]==fence[0] and len(mark[1])>=len(fence) and not mark[2].strip():fence=None
            continue
        if fence is None:rows.append(line)
    return '\n'.join(rows)


def document_check(kind, data, authors, *, project=None, master_profile=None, manifest=None):
    text = data.decode('utf-8'); fields = metadata(text)
    required = manifest['requiredDocMetadata'][kind] if manifest is not None else ('Doc ID', 'Owner', 'Status', 'Governing standard')
    for key in required:
        if not fields.get(key) or re.search(r'\{\{|\[\[|<[^>]+>', fields[key]):
            raise ValueError(f'{kind}: complete metadata required: {key}')
    if 'Last updated' in fields:
        try:
            if not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}', fields['Last updated']):raise ValueError('date format')
            datetime.strptime(fields['Last updated'], '%Y-%m-%d')
        except ValueError: raise ValueError(kind + ': Last updated must be YYYY-MM-DD')
    if fields['Status'] not in ('draft', 'active', 'frozen', 'deprecated'):
        raise ValueError(kind + ': invalid Status')
    if EDITION not in fields['Governing standard']:
        raise ValueError(kind + ': Governing standard must name ' + EDITION)
    if kind == 'master_doc':
        if fields.get('Doc family role') != 'canonical_entrypoint': raise ValueError('Master must be canonical_entrypoint')
        project = fields.get('Project slug', '')
        if not re.fullmatch(r'[a-z][a-z0-9-]{1,62}[a-z0-9]', project): raise ValueError('invalid Project slug')
        if fields.get('Canonical doc path') != 'docs/master_doc.md': raise ValueError('Master DOC_PATH must be docs/master_doc.md')
        if fields.get('Conformance profile') not in ('L0', 'L1', 'L2'): raise ValueError('invalid Conformance profile')
        if fields.get('Interaction profile') not in ('headless', 'standard_ui'):
            raise ValueError('supported Interaction profile: headless or standard_ui; HFVI is not supported')
    elif 'Parent Master Doc' in fields and fields['Parent Master Doc'] != 'docs/master_doc.md':
        raise ValueError(kind + ': Parent Master Doc must be docs/master_doc.md')
    if kind == 'headless_surface_note' and fields.get('Interaction profile') != 'headless':
        raise ValueError('Headless Surface Note must declare headless')
    if kind == 'ui_spec' and fields.get('Interaction profile', master_profile) != 'standard_ui':
        raise ValueError('UI Spec must declare standard_ui')
    if project is not None and fields.get('Project slug', project) != project:
        raise ValueError(kind + ': Project slug differs from Master')
    if kind == 'ui_spec' and fields.get('Canonical doc path', 'docs/ui_spec.md') != 'docs/ui_spec.md':
        raise ValueError('UI Spec DOC_PATH must be docs/ui_spec.md')
    author = authors[kind]
    if kind in ('headless_surface_note', 'context_pack'):
        markers=set(re.findall(r'<([^<>\n]+)>', author))
        if any(line.strip() in {'<'+marker+'>' for marker in markers} for line in text.splitlines()):
            raise ValueError(kind + ': Appendix M still contains unfilled required values')
    actual_headings=headings(text)
    marker=r'(\{\{[^{}\n]+\}\}|\[\[[^\[\]\n]+\]\])'
    def matches_heading(template):
        pattern=''.join('.+' if re.fullmatch(marker,part) else re.escape(part)
                        for part in re.split(marker,template))
        return any(re.fullmatch(pattern,actual) for actual in actual_headings)
    missing = [h for h in headings(author) if not matches_heading(h)]
    if missing: raise ValueError(kind + ': missing template section: ' + missing[0])
    # Fenced examples and syntax descriptions do not become unfinished project fields.
    prose=[]; fence=None
    for line in text.splitlines():
        if re.match(r'^\s*(`{3,}|~{3,})', line): fence = None if fence else line.lstrip()[0];continue
        if fence is None and not any(x in line for x in ('REQUIRED_PLACEHOLDER', 'OPTIONAL_PLACEHOLDER')): prose.append(line)
    pending = sorted(set(re.findall(r'\{\{([^{}\n]+)\}\}', '\n'.join(prose))))
    if fields['Status'] != 'draft' and pending: raise ValueError(kind + ': active/frozen document has unfilled required fields')
    return fields, pending


def resource_manifest(cadence):
    registry = load(cadence / 'cadence-registry/registry.json')
    if not registry.get('registryId') or not isinstance(registry.get('entries'), list): raise ValueError('native registry required')
    resources = {'cadence-registry/registry.json': digest(read(cadence / 'cadence-registry/registry.json'))}
    for entry in registry['entries']:
        path = (cadence / 'cadence-registry' / entry['ref']).resolve()
        if not path.is_relative_to(cadence.resolve()): raise ValueError('registry target escapes Cadence')
        if digest(read(path)) != entry['digest']: raise ValueError('registry target digest differs: ' + entry['id'])
        resources[str(path.relative_to(cadence.resolve()))] = entry['digest']
    return resources


def _publish(staged, destination, empty_inode=None):
    """Linux no-replace publish; an existing empty directory is exchanged atomically."""
    if sys.platform != 'linux': raise ValueError('1.5 scaffold publication currently supports Linux')
    libc = ctypes.CDLL(None, use_errno=True)
    if not hasattr(libc, 'renameat2'):raise ValueError('atomic 1.5 publication requires Linux renameat2')
    rename = libc.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    flag = 1
    if empty_inode is not None:
        st = destination.lstat()
        if (st.st_dev, st.st_ino) != empty_inode or destination.is_symlink() or any(destination.iterdir()):
            raise ValueError('destination changed during creation')
        flag = 2
    if rename(-100, os.fsencode(staged), -100, os.fsencode(destination), flag):
        raise OSError(ctypes.get_errno(), 'destination publication refused')
    if flag == 2:
        # The exchanged directory must be the exact empty destination checked above.
        st = staged.lstat()
        if (st.st_dev, st.st_ino) != empty_inode or any(staged.iterdir()):
            if rename(-100, os.fsencode(staged), -100, os.fsencode(destination), 2):
                raise PublicationRecoveryRequired('publication conflict; recover the preserved directory at '+str(staged.parent))
            raise ValueError('destination was occupied during publication')
        staged.rmdir()


def create(*, factory_root, dest_dir, master_doc_path, ui_spec_path=None,
           from_suite=None, headless_note_path=None, context_pack_path=None,
           extension_manifest_path=None, change_id=None, intent='', init_git=True,
           overwrite=False, change_empty=False):
    from .repo_factory import maybe_git_init, finalize_bootstrap_provenance, new_change, ensure_product_repo_permissions
    if not from_suite: raise ValueError('1.5 create requires --from-suite with a fixed synced workspace')
    if not init_git: raise ValueError('first 1.5 scaffold supports Git bootstrap only')
    if sys.platform != 'linux': raise ValueError('1.5 scaffold currently supports Linux')
    destination = Path(dest_dir).expanduser().absolute()
    if destination.is_symlink() or (destination.exists() and (not destination.is_dir() or any(destination.iterdir()))):
        raise ValueError('1.5 create requires a new or empty real directory; overwrite is unsupported')
    empty_inode = None
    if destination.exists():
        st = destination.stat();empty_inode = (st.st_dev, st.st_ino)
    suite, modules, report = suite_inputs(from_suite)
    for source in (suite, *modules.values(), Path(factory_root).resolve()):
        if source == destination or source.is_relative_to(destination) or destination.is_relative_to(source):
            raise ValueError('destination must be separate from source resources')
    identity = code_identity(modules['dasops'], Path(factory_root))
    standard = modules['das-standard']; cadence = modules['cadence-oss']
    if read(standard / 'VERSION').decode().strip() != EDITION: raise ValueError('Suite does not select Standard ' + EDITION)
    manifest = load(standard / 'standard_manifest.json');catalog = load(standard / 'template_catalog.json')
    if manifest.get('standardVersion') != EDITION or catalog.get('standardVersion') != EDITION: raise ValueError('Standard catalog/manifest edition mismatch')
    entries = {e['docType']: e for e in catalog['templates']}
    authors = {kind: author_section(e, read(local(standard, e['artifactPath']))) for kind,e in entries.items()}
    master = read(master_doc_path); fields, _ = document_check('master_doc', master, authors, manifest=manifest)
    master_refs=document_prose(master.decode())
    profile = fields['Interaction profile']; documents = {'master_doc': ('docs/master_doc.md', master)}
    inputs = {'ui_spec': ui_spec_path, 'headless_surface_note': headless_note_path, 'context_pack': context_pack_path}
    required = {'headless_surface_note'} if profile == 'headless' else {'ui_spec'}
    if fields['Conformance profile'] == 'L2': required.add('context_pack')
    # Mixed surfaces are explicit Master references; never infer facts from absent files.
    for kind in ('headless_surface_note', 'ui_spec'):
        if 'docs/' + kind + '.md' in master_refs: required.add(kind)
    for kind, source in inputs.items():
        if kind in required and source is None: raise ValueError('required document: ' + kind)
        if source is not None:
            path = 'docs/' + kind + '.md'
            if path not in master_refs: raise ValueError('Master must reference ' + path)
            data = read(source); document_check(kind, data, authors, project=fields['Project slug'], master_profile=profile, manifest=manifest)
            documents[kind] = (path, data)
    extension = read(extension_manifest_path) if extension_manifest_path else None
    if extension is None and 'local_extension_manifest.json' in master_refs:
        raise ValueError('Master references a missing extension manifest')
    if extension is not None:
        extension_value=json.loads(extension)
        if extension_value.get('standardManifestVersion')!=EDITION:raise ValueError('extension manifest edition differs')
        schema_check(extension_value, standard / 'local_extension_manifest.schema.json')
        if 'local_extension_manifest.json' not in master_refs: raise ValueError('Master must reference supplied extension manifest')
        if b'org.example.project' in extension: raise ValueError('example extension is not a project fact')
    upstream = {name: read(suite / name) for name in SUITE_FILES}
    closure = json.loads(upstream['suite_version_closure.json']);tooling = json.loads(upstream['suite.tooling_lock.json'])
    if closure['standardVersion'] != EDITION or closure['standardManifestVersion'] != EDITION: raise ValueError('Suite closure edition differs')
    resources = resource_manifest(cadence)
    prefix = 'tooling/das/suite/'
    derived = json.loads(json.dumps(closure));derived['$schema'] = 'standard/suite_version_closure.schema.json'
    derived['suiteLockRef'] = file_ref(prefix+'suite_lock.json')
    derived['lockRefs'] = dict(suiteToolingLock=file_ref(prefix+'suite.tooling_lock.json'), repoToolingLock=file_ref('tooling_lock.json'))
    lock = dict(schemaVersion='1.0.0', standardManifestVersion=EDITION,
                sourceOfTruth=dict(kind='git', uri='.', pinType='commit', pinValue='0'*40, floating=False),
                verifyRuntime=closure['refs']['verifyRuntime'], suiteVersionClosureRef=file_ref('tooling/das/suite_version_closure.json'),
                suiteLockRef=derived['suiteLockRef'], verifyRegistryRef=file_ref(VENDOR+'/cadence-registry/registry.json'),
                toolchain=[dict(name='python3', version='>=3.10'), dict(name='git', version='>=2.30')])
    lock['mirrors']=[dict(kind='standard_local_copy',path='tooling/das/standard',
                          sourceOfTruth=closure['refs']['standard']['uri'],
                          mirrorPurpose='Selected pinned templates and schemas for offline scaffold checks',
                          localModificationsAllowed=False,snapshotRef=closure['refs']['standard'])]
    registry = load(cadence / 'cadence-registry/registry.json')
    policies = [e['id'] for e in registry['entries'] if e['kind']=='policyPack' and e['id']=='scaffold-v15']
    if not policies: raise ValueError('selected Cadence does not include scaffold-v15 metadata for its existing core checks')
    native = dict(projectId=fields['Project slug'], mode='strict_offline', closureRef='tooling/das/suite_version_closure.json',
                  toolingLock='tooling_lock.json', runtimeRef=VENDOR+'/cadence-sandbox/runtime_profile.json',
                  registryRef=VENDOR+'/cadence-registry/registry.json', sandboxRef=VENDOR+'/cadence-sandbox/sandbox_profile.json',
                  policies=policies, ui=dict(enabled=False))
    selected = dict(suiteCommit=git(suite, 'rev-parse', 'HEAD'), factoryCodeDigest=identity,
                    runtime=closure['refs']['verifyRuntime'], suiteFiles={k:digest(v) for k,v in upstream.items()})
    destination.parent.mkdir(parents=True, exist_ok=True)
    directory=tempfile.mkdtemp(prefix='.dasops-create-', dir=destination.parent)
    preserve=False
    try:
        staged = Path(directory) / 'repo';shutil.copytree(Path(factory_root)/'templates/das-product', staged)
        # Adapt only factory-owned guidance, before importing user documents.
        if profile == 'headless' and 'ui_spec' not in documents:
            for guidance in staged.rglob('*.md'):
                guidance.write_text(guidance.read_text().replace('docs/ui_spec.md','docs/headless_surface_note.md'))
        (staged / 'docs/ui_spec.md').unlink(missing_ok=True)
        (staged / 'local_extension_manifest.json').unlink(missing_ok=True)
        for path,data in documents.values(): (staged / path).write_bytes(data)
        if extension is not None: (staged/'local_extension_manifest.json').write_bytes(extension)
        for name,data in upstream.items():
            target = staged/prefix/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
        shutil.copytree(suite/'schemas', staged/prefix/'schemas')
        standard_dir=staged/'tooling/das/standard';standard_dir.mkdir(parents=True)
        standard_files=set(SCHEMAS.values()) | {'standard_manifest.json','template_catalog.json','standard_manifest.schema.json','template_catalog.schema.json'} | {e['artifactPath'] for e in entries.values()}
        standard_digests={}
        for name in sorted(standard_files):
            data=read(local(standard,name));target=standard_dir/name
            target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
            standard_digests[name]=digest(data)
        write_json(staged/'tooling/das/suite_version_closure.json', derived)
        write_json(staged/'tooling_lock.json', lock)
        (staged/'cadence.yaml').write_text(yaml.safe_dump(native,sort_keys=False))
        (staged/'tooling/das/native-config.schema.json').write_bytes(read(cadence/'cadence-core/internal/config/config.schema.json'))
        (staged/'VERIFY_REQUIREMENTS.md').write_text('# Product verification scope\n\n`./scripts/verify --scope scaffold` checks generated structure, documents and fixed sources.\n`./scripts/verify` also requires completed documents, an installed fixed runtime and applicable product checks.\nThe current core scanner does not execute UI tests or certify complete DAS conformance.\n')
        (staged/'README.md').write_text('# DAS '+EDITION+' product scaffold\n\nCanonical documents:\n'+''.join('- '+path+'\n' for path,_ in documents.values())+'\nRun `./scripts/verify --scope scaffold` before runtime installation.\nInstall from the selected fixed Suite with `./scripts/install_cadence_vendor.sh --from-suite /path/to/suite`.\nThen run `./cadencew doctor` and `./cadencew verify --profile dev`.\nDefault `./scripts/verify` fails when documents, the runtime or an applicable UI runner are unfinished.\nCreation does not grant approval or certify full DAS conformance.\n')
        manual=staged/'docs/USER_MANUAL.md'
        manual.write_text(manual.read_text().replace('The default Factory seed retains its legacy 1.4 configuration.', 'This generated product uses an explicit 1.5 configuration and fixed Suite sources.'))
        (staged/'STANDARD_REF.md').write_text('# Governing Standard\n\nDAS '+EDITION+'\n\n'+json.dumps(closure['refs']['standard'],sort_keys=True)+'\n')
        state=dict(standardRelease=EDITION, projectId=fields['Project slug'], interactionProfile=profile,
                   documents={kind:path for kind,(path,_) in documents.items()}, selectedSources=selected,
                   standardFileDigests=standard_digests,
                   nativeSchemaDigest=digest(read(cadence/'cadence-core/internal/config/config.schema.json')),
                   resourceDigests=resources, documentAuthors={kind:digest(author.encode()) for kind,author in authors.items()})
        write_json(staged/STATE,state)
        shutil.copyfile(Path(__file__), staged/'scripts/das_scaffold.py')
        for name,command in [('verify','verify'),('install_cadence_vendor.sh','install')]:
            (staged/'scripts'/name).write_text('#!/usr/bin/env bash\nset -euo pipefail\nROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"\nexec "${PYTHON:-python3}" -B "$ROOT/scripts/das_scaffold.py" '+command+' --repo-root "$ROOT" "$@"\n')
        (staged/'scripts/verify-frontend').write_text('#!/usr/bin/env bash\nset -euo pipefail\necho "Implement the product UI tests in scripts/verify-frontend; core checks and evidence-file presence do not execute UI tests." >&2\nexit 1\n')
        (staged/'cadencew').write_text('#!/usr/bin/env bash\nset -euo pipefail\nROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"\nexec "${PYTHON:-python3}" -B "$ROOT/scripts/das_scaffold.py" run --repo-root "$ROOT" -- "$@"\n')
        doc_lines='\n'.join('    - '+path for path,_ in documents.values())
        for p in [staged/'openspec/config.yaml', staged/'openspec/schemas/das-standard/schema.yaml',
                  *(staged/'openspec/schemas/das-standard/templates').glob('*.md')]:
            text=p.read_text();text=text.replace('    - docs/master_doc.md\n    - docs/ui_spec.md',doc_lines)
            text=text.replace('        - docs/master_doc.md\n        - docs/ui_spec.md',doc_lines.replace('    -','        -'))
            text=text.replace('docs/ui_spec.md','docs/headless_surface_note.md') if profile=='headless' and 'ui_spec' not in documents else text
            p.write_text(text)
        (staged/'.dasops_product_repo').write_text('DAS 1.5 product scaffold\n')
        with (staged/'.gitignore').open('a') as stream: stream.write('\n# Local runtime builds and execution evidence\n.cadence/bin/\n.cadence/out/\n.cadence/tmp/\nvendor/cadence/\n')
        ensure_product_repo_permissions(staged)
        if change_id: new_change(staged,change_id,intent,empty=change_empty)
        maybe_git_init(staged);finalize_bootstrap_provenance(staged)
        result=verify(staged,scope='scaffold')
        if not result['ok']: raise ValueError('; '.join(result['problems']))
        try: _publish(staged,destination,empty_inode)
        except PublicationRecoveryRequired:
            preserve=True
            raise
    finally:
        if not preserve: shutil.rmtree(directory)
    return destination


def verify(root, scope='scaffold'):
    root=Path(root).resolve();problems=[];pending=[];checks=[]
    try:
        state=load(root/STATE)
        if state['standardRelease']!=EDITION: raise ValueError('unsupported scaffold edition')
        base=root/'tooling/das/standard'
        for name,expected in state['standardFileDigests'].items():
            if digest(read(local(base,name)))!=expected:raise ValueError('Standard mirror changed: '+name)
        catalog=load(base/'template_catalog.json')
        authors={e['docType']:author_section(e,read(local(base,e['artifactPath']))) for e in catalog['templates']}
        for kind,author in authors.items():
            if digest(author.encode())!=state['documentAuthors'][kind]:raise ValueError('template author changed: '+kind)
        manifest=load(base/'standard_manifest.json')
        docs=state['documents'];master=read(local(root,docs['master_doc']));fields,_=document_check('master_doc',master,authors,manifest=manifest)
        master_refs=document_prose(master.decode())
        required={'headless_surface_note'} if fields['Interaction profile']=='headless' else {'ui_spec'}
        if fields['Conformance profile']=='L2':required.add('context_pack')
        if not required<=set(docs):raise ValueError('missing conditional documents')
        if fields['Interaction profile']!=state['interactionProfile'] or fields['Project slug']!=state['projectId']:
            raise ValueError('document identity differs from scaffold configuration')
        identifiers=set()
        for kind,path in docs.items():
            if kind!='master_doc' and path not in master_refs:raise ValueError('Master does not reference '+path)
            doc_fields,items=document_check(kind,read(local(root,path)),authors,project=state['projectId'],master_profile=state['interactionProfile'],manifest=manifest)
            if doc_fields['Doc ID'] in identifiers:raise ValueError('duplicate document identity')
            identifiers.add(doc_fields['Doc ID'])
            pending.extend(kind+': '+item for item in items)
        if (root/'local_extension_manifest.json').exists():
            extension_value=load(root/'local_extension_manifest.json')
            if extension_value.get('standardManifestVersion')!=EDITION:raise ValueError('extension manifest edition differs')
            schema_check(extension_value,base/'local_extension_manifest.schema.json')
            if 'local_extension_manifest.json' not in master_refs:raise ValueError('extension manifest is not referenced')
        elif 'local_extension_manifest.json' in master_refs:raise ValueError('referenced extension manifest missing')
        upstream=root/'tooling/das/suite'
        for name in SUITE_FILES:
            if digest(read(upstream/name))!=state['selectedSources']['suiteFiles'][name]:raise ValueError('Suite original changed: '+name)
            schema_check(load(upstream/name),upstream/'schemas/das-standard'/SCHEMAS[name])
        original=load(upstream/'suite_version_closure.json');derived=load(root/'tooling/das/suite_version_closure.json');lock=load(root/'tooling_lock.json')
        schema_check(derived,base/'suite_version_closure.schema.json');schema_check(lock,base/'tooling_lock.schema.json')
        for name in ('refs','standardVersion','standardManifestVersion','suiteVersion','factoryVersion','verifyRuntimeVersion'):
            if derived[name]!=original[name]:raise ValueError('derived closure identity changed: '+name)
        expected={'suiteToolingLock':'tooling/das/suite/suite.tooling_lock.json','repoToolingLock':'tooling_lock.json'}
        if derived['lockRefs']!={key:file_ref(value) for key,value in expected.items()}:raise ValueError('invalid product lock alignment')
        if lock['suiteLockRef']!=derived['suiteLockRef'] or lock['suiteVersionClosureRef']!=file_ref('tooling/das/suite_version_closure.json'):
            raise ValueError('product closure paths differ')
        for value in [derived['suiteLockRef'],*derived['lockRefs'].values(),lock['suiteVersionClosureRef']]:read(local(root,value))
        mirrors=lock.get('mirrors',[])
        if len(mirrors)!=1 or mirrors[0].get('snapshotRef')!=original['refs']['standard'] or mirrors[0].get('localModificationsAllowed') is not False or mirrors[0].get('path')!='tooling/das/standard':raise ValueError('Standard mirror source declaration differs')
        if lock['standardManifestVersion']!=derived['standardManifestVersion']:raise ValueError('product lock edition differs')
        if lock['verifyRuntime']!=derived['refs']['verifyRuntime']:raise ValueError('runtime identity differs')
        source=lock['sourceOfTruth']
        if source.get('uri')!='.' or source.get('kind')!='git' or source.get('pinType')!='commit':raise ValueError('unsupported product provenance')
        git(root,'merge-base','--is-ancestor',source['pinValue'],'HEAD')
        if digest(read(root/'tooling/das/native-config.schema.json'))!=state['nativeSchemaDigest']:raise ValueError('native schema identity differs')
        cfg=yaml.safe_load(read(root/'cadence.yaml'))
        schema_check(cfg,root/'tooling/das/native-config.schema.json')
        expected_config=dict(projectId=state['projectId'],mode='strict_offline',closureRef='tooling/das/suite_version_closure.json',toolingLock='tooling_lock.json',runtimeRef=VENDOR+'/cadence-sandbox/runtime_profile.json',registryRef=VENDOR+'/cadence-registry/registry.json',sandboxRef=VENDOR+'/cadence-sandbox/sandbox_profile.json',policies=['scaffold-v15'],ui=dict(enabled=False))
        if cfg!=expected_config:raise ValueError('native configuration differs from the supported scaffold profile')
        if lock['verifyRegistryRef']!=file_ref(cfg['registryRef']):raise ValueError('registry reference differs')
        runtime_installed=(root/VENDOR/'.dasops-install.json').is_file()
        if runtime_installed: installed(root)
        else: pending.append('runtime: not installed')
        if scope=='full':
            if pending:raise ValueError('full verification requires completed documents and installed runtime')
            if 'ui_spec' in docs:
                run_frontend(root)
                checks.append(dict(name='product-frontend-command',status='passed',command='scripts/verify-frontend'))
            result=subprocess.run([str(installed(root)),'verify','--profile','dev'],cwd=root,capture_output=True,text=True,check=False)
            if result.returncode:raise ValueError('native core verification failed: '+result.stderr.strip())
            checks.append(dict(name='native-core',status='passed',policyMetadataOnly=True))
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError,yaml.YAMLError) as exc:problems.append(str(exc))
    return dict(ok=not problems,scope=scope,problems=problems,pendingItems=pending,checks=checks,
                qualification=False,coverage='scaffold structure'+(' and existing native core checks' if scope=='full' else ''))


def run_frontend(root):
    command=local(root,'scripts/verify-frontend')
    read(command)
    if not os.access(command,os.X_OK):raise ValueError('product frontend command is not executable')
    result=subprocess.run([str(command)],cwd=root,capture_output=True,text=True,timeout=300,check=False)
    if result.returncode:raise ValueError('product frontend checks failed: '+result.stderr.strip())


def installed(root):
    state=load(root/STATE);base=root/VENDOR;record=load(base/'.dasops-install.json')
    if record['runtime']!=state['selectedSources']['runtime']:raise ValueError('installed runtime source differs')
    for path,expected in state['resourceDigests'].items():
        if digest(read(local(base,path)))!=expected:raise ValueError('installed resource changed: '+path)
    binary=local(base,record['binaryPath'])
    if digest(read(binary))!=record['binaryDigest']:raise ValueError('installed binary differs')
    proc=subprocess.run([str(binary),'version','--json'],capture_output=True,text=True,timeout=10)
    if proc.returncode:raise ValueError('installed version check failed')
    identity=json.loads(proc.stdout)
    if identity['binarySha256']!=record['binaryDigest'] or identity['releaseVersion']!=record['releaseVersion'] or identity['sourceModified'] or identity['sourceRevision']!=record['runtime']['pinValue']:
        raise ValueError('native binary/source identity differs')
    return binary


def run_native(root,args):
    return subprocess.run([str(installed(root)),*args],cwd=root,check=False).returncode


def install(root, suite, force=False):
    import fcntl
    root=Path(root).resolve()
    guard_dir=local(root,'.cadence/tmp');guard_dir.mkdir(parents=True,exist_ok=True)
    descriptor=os.open(guard_dir/'install.guard',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'r+b') as guard:
        fcntl.flock(guard.fileno(),fcntl.LOCK_EX)
        return _install_locked(root,suite,force)


def _install_locked(root, suite, force=False):
    root=Path(root).resolve();_,modules,_=suite_inputs(suite);source=modules['cadence-oss'];state=load(root/STATE)
    if git(source,'rev-parse','HEAD')!=state['selectedSources']['runtime']['pinValue']:raise ValueError('install source differs from selected runtime')
    if resource_manifest(source)!=state['resourceDigests']:raise ValueError('install resources differ from planned runtime')
    target=root/VENDOR
    if target.exists() and not force:raise ValueError('runtime already installed; use --force explicitly')
    if target.is_symlink() or (root/'vendor').is_symlink() or (root/'vendor/cadence').is_symlink():raise ValueError('linked vendor target refused')
    target.parent.mkdir(parents=True,exist_ok=True)
    temp=tempfile.mkdtemp(prefix='.cadence-install-',dir=target.parent)
    preserve=False
    try:
        staged=Path(temp)/'new';staged.mkdir()
        # Copy only files belonging to the pinned commit, not Git databases or caches.
        for name in [*state['resourceDigests'], 'VERSION', 'LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md']:
            data=read(local(source,name));dest=staged/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data)
        binary=staged/'.cadence/bin/cadence';binary.parent.mkdir(parents=True)
        # Build in the fixed Git checkout so Go can bind the actual source revision.
        proc=subprocess.run(['go','build','-buildvcs=true','-trimpath','-o',str(binary),'./cmd/cadence'],cwd=source/'cadence-core',check=False)
        if proc.returncode:raise ValueError('Cadence build failed; previous install retained')
        release=read(source/'VERSION').decode().strip()
        record=dict(runtime=state['selectedSources']['runtime'],releaseVersion=release,binaryPath='.cadence/bin/cadence',binaryDigest=digest(read(binary)))
        for path,expected in state['resourceDigests'].items():
            if digest(read(staged/path))!=expected:raise ValueError('staged resource changed')
        identity=json.loads(subprocess.check_output([str(binary),'version','--json'],text=True,timeout=10))
        if identity['sourceModified'] or identity['sourceRevision']!=record['runtime']['pinValue'] or identity['releaseVersion']!=release or identity['binarySha256']!=record['binaryDigest']:
            raise ValueError('built runtime identity differs; previous install retained')
        record['platform'] = {key:identity[key] for key in ('goos','goarch','goVersion')}
        write_json(staged/'.dasops-install.json',record)
        previous=Path(temp)/'previous'
        if target.exists():target.rename(previous)
        try:staged.rename(target)
        except OSError:
            if previous.exists():
                try: previous.rename(target)
                except OSError as exc:
                    preserve=True
                    raise PublicationRecoveryRequired('restore the preserved previous installation at '+str(previous)) from exc
            raise
    finally:
        if not preserve: shutil.rmtree(temp)
    return record


def main(argv=None):
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['verify','install','run']);parser.add_argument('--repo-root',required=True)
    parser.add_argument('--scope',choices=['scaffold','full'],default='full');parser.add_argument('--from-suite');parser.add_argument('--force',action='store_true');parser.add_argument('--tier',choices=['oss'],default='oss')
    args,rest=parser.parse_known_args(argv);root=Path(args.repo_root).resolve()
    try:
        if args.action=='run':return run_native(root,rest[1:] if rest[:1]==['--'] else rest)
        if rest:parser.error('unexpected arguments')
        if args.action=='install':
            if not args.from_suite:raise ValueError('install requires the selected --from-suite workspace')
            print(json.dumps(install(root,args.from_suite,args.force),indent=2));return 0
        result=verify(root,args.scope);print(json.dumps(result,indent=2));return 0 if result['ok'] else 1
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError) as exc:
        print('DAS scaffold: '+str(exc),file=sys.stderr);return 2


if __name__=='__main__':raise SystemExit(main())
