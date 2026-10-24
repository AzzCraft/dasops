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
import platform
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
CHANGE_TEMPLATES = ('master_doc_delta.md', 'contracts_plan.md', 'verification_plan.md', 'tasks.md')
ENTRY_FILES = ('STANDARD_REF.md', '.dasops_product_repo', 'openspec/config.yaml',
               'openspec/schemas/das-standard/schema.yaml', 'scripts/das_scaffold.py',
               'scripts/verify', 'scripts/install_cadence_vendor.sh', 'cadencew')


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


def schema_check(value, schema_path, schema=None):
    if schema is None: schema = load(schema_path)
    Draft202012Validator.check_schema(schema)
    errors = list(Draft202012Validator(schema, registry=Registry(), format_checker=FormatChecker()).iter_errors(value))
    if errors: raise ValueError(schema_path.name + ': ' + errors[0].message)


def file_ref(path):
    return dict(kind='file', uri=path, pinType='manifest', pinValue=path, floating=False)


def check_extension_manifest(data, schema_path, schema=None):
    value = json.loads(data, object_pairs_hook=_pairs)
    if not isinstance(value, dict) or value.get('standardManifestVersion') != EDITION:
        raise ValueError('extension manifest edition differs')
    schema_check(value, schema_path, schema)
    if any(identifier == 'org.example.project' or identifier.startswith('org.example.project.')
           for item in value['extensions'] for identifier in (item['name'], item['namespace'])):
        raise ValueError('example extension is not a project fact')


def product_manual(template, document_paths, has_extensions):
    """Keep shared workflow guidance, with this product's paths and 1.5 commands."""
    before, marker, rest = template.partition('- System truth\n')
    _, change_marker, rest = rest.partition('- Change truth\n')
    shared, cadence_marker, _ = rest.partition('Section 5. Cadence integration\n')
    if not (marker and change_marker and cadence_marker):
        raise ValueError('product manual template sections are missing')
    paths = [*document_paths, 'STANDARD_REF.md', 'tooling_lock.json']
    if has_extensions:
        paths.append('local_extension_manifest.json')
    return (before + marker + ''.join('  - `' + path + '`\n' for path in paths)
            + change_marker + shared + '''Section 5. Cadence integration

This product uses DAS Standard 1.5.0-beta.1 and fixed Suite sources.
The document list above reflects this project's actual inputs. Headless and
mixed surfaces require their Surface Note; L2 requires its Context Pack.
An extension manifest is present only when real local extensions were supplied.

Check the generated structure before installation, from the product root:

```bash
./scripts/verify --scope scaffold
```

A successful scaffold check may still report pending document fields, toolchain
differences or an uninstalled runtime. It is not full verification or approval.

Install the fixed Cadence runtime:

```bash
./scripts/install_cadence_vendor.sh --from-suite /path/to/validated-suite-workspace
```

Use the same selected Suite combination, with clean, locked modules synchronized
under its workspace. Installation reads Suite report's resolvedPath for the
selected module; it does not assume a sibling release directory or clone a tip.
The supported runtime path is Linux source building and requires Go, Git and
the declared Python dependencies. Source SHA, binary digest, version and resource
digests are checked. This installs the binary and selected resources, not a full
Cadence source checkout with its development verification scripts.

To replace an existing installation explicitly, add --force to the same command.
A failed build or replacement retains the prior installation; if automatic
restoration fails, the error identifies the preserved directory to recover.
The created project remains available when installation fails.

Inspect and run the installed binary:

```bash
./cadencew version --json
./cadencew doctor
./cadencew verify --profile dev
```

The wrapper checks the fixed binary and resources on each invocation and never
falls back to another cadence on PATH. Doctor may create .cadence/tmp. Native
verification writes evidence under .cadence/out; a core pass covers only its
implemented checks, not full DAS conformance.

Run the product's complete configured checks:

```bash
./scripts/verify
```

The default full scope requires completed documents, matching locked toolchain
versions and the installed runtime. UI and mixed products also require a working
scripts/verify-frontend supplied by the product author. The generated frontend
script exits 1 until real product tests replace it; it does not perform visual
comparisons or accept screenshot files as proof. Full selects this command from
the actual UI document set, independently of the native ui.enabled setting.
Headless products do not require that UI command. Failed or unexecuted required
checks cannot produce an overall full pass. Creation and verification never
grant adoption approval or reference qualification.
''')


def git(root, *args):
    proc = subprocess.run(['git', '-C', str(root), *args], capture_output=True, text=True, timeout=30)
    if proc.returncode:
        raise ValueError('Git input check failed: ' + proc.stderr.strip())
    return proc.stdout.strip()


def observe_toolchain():
    """Observe the tools this interpreter and the scaffold actually invoke."""
    if sys.version_info < (3, 10):
        raise ValueError('scaffold requires Python 3.10 or later')
    try:
        result = subprocess.run(['git', '--version'], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError('cannot observe Git version') from exc
    # Normalize known packaging suffixes, retaining release-candidate identity.
    match = re.fullmatch(r'git version (\d+\.\d+\.\d+(?:\.rc\d+)?)(?:\.windows\.\d+| \(Apple Git-[\w.]+\))?', result.stdout.strip())
    if result.returncode or not match:
        raise ValueError('cannot parse Git version')
    version = match[1]
    if tuple(map(int, version.split('.')[:3])) < (2, 30, 0):
        raise ValueError('scaffold requires Git 2.30 or later')
    return [dict(name='python3', version=platform.python_version()), dict(name='git', version=version)]


def check_toolchain(expected):
    result = dict(expected=expected, observed=[], problems=[])
    try:
        result['observed'] = observe_toolchain()
        if (not isinstance(expected, list) or len(expected) != 2
                or not all(isinstance(item, dict) for item in expected)
                or {item.get('name') for item in expected} != {'python3', 'git'}):
            raise ValueError('product toolchain must pin Python and Git exactly once')
        pins = {item['name']: item.get('version') for item in expected}
        for item in result['observed']:
            if pins[item['name']] != item['version']:
                result['problems'].append('toolchain '+item['name']+': expected '+str(pins[item['name']])+', observed '+item['version'])
    except ValueError as exc:
        result['problems'].append(str(exc))
    return result


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


def source_snapshot(root, paths, revision):
    """Read selected Git files once and bind those bytes to the selected commit."""
    result = {}
    tree = git(root, 'ls-tree', '-r', '-z', revision, '--', *paths)
    for row in tree.split('\0'):
        if not row: continue
        info, name = row.split('\t', 1)
        mode, kind, expected = info.split()
        if kind != 'blob' or mode not in ('100644', '100755'):
            raise ValueError('regular source file required: ' + name)
        data = read(local(root, name))
        # This is Git's object identifier, not a cryptographic trust decision.
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data, usedforsecurity=False).hexdigest()
        if blob != expected: raise ValueError('source changed from selected commit: ' + name)
        result[name] = (data, int(mode, 8) & 0o777)
    if not result: raise ValueError('selected source files missing')
    return result


def write_snapshot(root, files):
    for name, (data, mode) in files.items():
        target = local(root, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(mode)


def code_identity(factory, resources, revision):
    """Bind loaded code AND templates to the fixed Suite factory, including wheels."""
    actual = Path(__file__).resolve().parent
    observed = {}; templates = {}
    files = source_snapshot(factory, ['dasops', 'templates'], revision)
    for name, (data, mode) in files.items():
        path = Path(name)
        if path.parts[0] == 'templates':
            target = local(resources, name)
            if path.parts[:2] == ('templates', 'das-product'):
                templates[str(path.relative_to('templates/das-product'))] = (data, mode)
        elif path.suffix in ('.py', '.json', '.sql'):
            target = local(actual, str(path.relative_to('dasops')))
        else: continue
        if read(target) != data:
            raise ValueError('executing factory code/resources differ from Suite: ' + name)
        observed[name] = digest(data)
    return digest(json.dumps(observed, sort_keys=True).encode()), templates, files['dasops/scaffold_v15.py'][0]


def metadata(text):
    result = {}
    control_level = None
    for line in document_prose(text).splitlines():
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
    return [line.strip() for line in document_prose(text).splitlines() if re.match(r'^#{1,6}\s+', line)]


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
    """Visible Markdown for metadata, headings, pending fields and references."""
    rows=[];fence=None
    text = re.sub(r'<!--.*?(?:-->|\Z)', lambda m: '\n' * m[0].count('\n'), text, flags=re.S)
    for line in text.splitlines():
        mark=re.match(r'^ {0,3}(`{3,}|~{3,})(.*)$',line)
        if mark:
            if fence is None:fence=mark[1]
            elif mark[1][0]==fence[0] and len(mark[1])>=len(fence) and not mark[2].strip():fence=None
            continue
        if fence is None:rows.append(line)
    return '\n'.join(rows)


def document_references(text):
    """Read whole local paths from prose/code spans and Markdown link targets."""
    text = document_prose(text)
    paths = []
    def link(match):
        # Labels do not establish a reference to a different link destination.
        target = match[1].strip()
        if target: paths.append(target.split()[0].strip('<>'))
        return ' '
    text = re.sub(r'!?\[[^\]\n]*\]\(([^)\n]*)\)', link, text)
    paths.extend(re.findall(r'''(?<![\w./%+~:-])(?:docs/[^\s`<>()\[\]"',;*]+|local_extension_manifest\.json[^\s`<>()\[\]"',;*]*)''', text))
    return {path.rstrip('.:!').split('#', 1)[0] for path in paths}


def document_check(kind, data, authors, *, project=None, master_profile=None, manifest=None):
    text = document_prose(data.decode('utf-8')); fields = metadata(text)
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
    if not re.search(r'\bv?' + re.escape(EDITION) + r'(?![\w+-]|\.\w)', fields['Governing standard']):
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
        # Appendix M's standalone fields need visible values, not just headings.
        required_sections = {}
        section = None
        for line in document_prose(author).splitlines():
            if re.match(r'^#{1,6}\s+', line): section = line.lstrip('# ').strip()
            elif section is not None and re.fullmatch(r'\s*<[^<>\n]+>\s*', line):
                required_sections[section] = False
        section = 'Document Control'
        active_section = None
        active_level = 0
        for line in text.splitlines():
            heading = re.match(r'^(#{1,6})\s+', line)
            if heading:
                section = line.lstrip('# ').strip()
                if section in required_sections:
                    active_section, active_level = section, len(heading[1])
                elif len(heading[1]) <= active_level:
                    active_section = None
                continue
            value = re.sub(r'^\s*(?:[-+*]|\d+[.)])\s+(?:\[[ xX]\]\s+)?', '', line).strip().strip('`*_~').strip()
            marker = re.fullmatch(r'<([^<>\n]+)>', value)
            if marker and marker[1] in markers:
                raise ValueError(kind + ': Appendix M still contains unfilled required values in ' + section + ': ' + value)
            if active_section is not None and value:
                required_sections[active_section] = True
        for section, supplied in required_sections.items():
            if not supplied:
                raise ValueError(kind + ': Appendix M requires visible content in ' + section)
    actual_headings=headings(text)
    marker=r'(\{\{[^{}\n]+\}\}|\[\[[^\[\]\n]+\]\])'
    def matches_heading(template):
        pattern=''.join('.+' if re.fullmatch(marker,part) else re.escape(part)
                        for part in re.split(marker,template))
        return any(re.fullmatch(pattern,actual) for actual in actual_headings)
    missing = [h for h in headings(author) if not matches_heading(h)]
    if missing: raise ValueError(kind + ': missing template section: ' + missing[0])
    # Fenced examples and syntax descriptions do not become unfinished project fields.
    prose=[line for line in text.splitlines() if not any(x in line for x in ('REQUIRED_PLACEHOLDER', 'OPTIONAL_PLACEHOLDER'))]
    pending = sorted(set(re.findall(r'\{\{([^{}\n]+)\}\}', '\n'.join(prose))))
    if fields['Status'] != 'draft' and pending: raise ValueError(kind + ': active/frozen document has unfilled required fields')
    return fields, pending


def resource_manifest(cadence, snapshot=None):
    def content(name): return read(local(cadence, name)) if snapshot is None else snapshot[name][0]
    registry_data = content('cadence-registry/registry.json')
    registry = json.loads(registry_data)
    if not registry.get('registryId') or not isinstance(registry.get('entries'), list): raise ValueError('native registry required')
    resources = {'cadence-registry/registry.json': digest(registry_data)}
    for entry in registry['entries']:
        path = (cadence / 'cadence-registry' / entry['ref']).resolve()
        if not path.is_relative_to(cadence.resolve()): raise ValueError('registry target escapes Cadence')
        name = str(path.relative_to(cadence.resolve()))
        if digest(content(name)) != entry['digest']: raise ValueError('registry target digest differs: ' + entry['id'])
        resources[name] = entry['digest']
    return resources


def required_documents(fields, master_refs):
    required = {'headless_surface_note'} if fields['Interaction profile'] == 'headless' else {'ui_spec'}
    if fields['Conformance profile'] == 'L2': required.add('context_pack')
    for kind in ('headless_surface_note', 'ui_spec', 'context_pack'):
        if 'docs/' + kind + '.md' in master_refs: required.add(kind)
    return required


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
    resolved_destination = destination.resolve()
    for source in (suite, *modules.values(), Path(factory_root).resolve()):
        if source == resolved_destination or source.is_relative_to(resolved_destination) or resolved_destination.is_relative_to(source):
            raise ValueError('destination must be separate from source resources')
    pins = {row['id']: row['expectedPinValue'] for row in report['modules']}
    identity, templates, helper = code_identity(modules['dasops'], Path(factory_root), pins['dasops'])
    standard = modules['das-standard']; cadence = modules['cadence-oss']
    standard_data = source_snapshot(standard, ['VERSION', 'standard_manifest.json', 'template_catalog.json'], pins['das-standard'])
    if standard_data['VERSION'][0].decode().strip() != EDITION: raise ValueError('Suite does not select Standard ' + EDITION)
    manifest = json.loads(standard_data['standard_manifest.json'][0]);catalog = json.loads(standard_data['template_catalog.json'][0])
    if manifest.get('standardVersion') != EDITION or catalog.get('standardVersion') != EDITION: raise ValueError('Standard catalog/manifest edition mismatch')
    entries = {e['docType']: e for e in catalog['templates']}
    standard_files=set(SCHEMAS.values()) | {'standard_manifest.schema.json','template_catalog.schema.json'} | {e['artifactPath'] for e in entries.values()}
    standard_data.update(source_snapshot(standard, sorted(standard_files), pins['das-standard']))
    authors = {kind: author_section(e, standard_data[e['artifactPath']][0]) for kind,e in entries.items()}
    master = read(master_doc_path); fields, _ = document_check('master_doc', master, authors, manifest=manifest)
    master_refs=document_references(master.decode())
    profile = fields['Interaction profile']; documents = {'master_doc': ('docs/master_doc.md', master)}
    inputs = {'ui_spec': ui_spec_path, 'headless_surface_note': headless_note_path, 'context_pack': context_pack_path}
    required = required_documents(fields, master_refs)
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
        check_extension_manifest(extension, standard / 'local_extension_manifest.schema.json',
                                 json.loads(standard_data['local_extension_manifest.schema.json'][0]))
        if 'local_extension_manifest.json' not in master_refs: raise ValueError('Master must reference supplied extension manifest')
    suite_commit = git(suite, 'rev-parse', 'HEAD')
    suite_data = source_snapshot(suite, [*SUITE_FILES, 'schemas'], suite_commit)
    upstream = {name: suite_data[name][0] for name in SUITE_FILES}
    closure = json.loads(upstream['suite_version_closure.json']);tooling = json.loads(upstream['suite.tooling_lock.json'])
    if closure['standardVersion'] != EDITION or closure['standardManifestVersion'] != EDITION: raise ValueError('Suite closure edition differs')
    for key, name in [('standard','das-standard'), ('factory','dasops'), ('verifyRuntime','cadence-oss')]:
        if closure['refs'][key]['pinValue'] != pins[name]: raise ValueError('Suite selection changed during creation')
    native_data = source_snapshot(cadence, ['cadence-registry/registry.json', 'cadence-core/internal/config/config.schema.json'], pins['cadence-oss'])
    registry = json.loads(native_data['cadence-registry/registry.json'][0])
    targets = []
    for entry in registry['entries']:
        target = (cadence / 'cadence-registry' / entry['ref']).resolve()
        if not target.is_relative_to(cadence.resolve()): raise ValueError('registry target escapes Cadence')
        targets.append(str(target.relative_to(cadence.resolve())))
    native_data.update(source_snapshot(cadence, targets, pins['cadence-oss']))
    resources = resource_manifest(cadence, native_data)
    prefix = 'tooling/das/suite/'
    derived = json.loads(json.dumps(closure));derived['$schema'] = 'standard/suite_version_closure.schema.json'
    derived['suiteLockRef'] = file_ref(prefix+'suite_lock.json')
    derived['lockRefs'] = dict(suiteToolingLock=file_ref(prefix+'suite.tooling_lock.json'), repoToolingLock=file_ref('tooling_lock.json'))
    lock = dict(schemaVersion='1.0.0', standardManifestVersion=EDITION,
                sourceOfTruth=dict(kind='git', uri='.', pinType='commit', pinValue='0'*40, floating=False),
                verifyRuntime=closure['refs']['verifyRuntime'], suiteVersionClosureRef=file_ref('tooling/das/suite_version_closure.json'),
                suiteLockRef=derived['suiteLockRef'], verifyRegistryRef=file_ref(VENDOR+'/cadence-registry/registry.json'),
                toolchain=observe_toolchain())
    lock['mirrors']=[dict(kind='standard_local_copy',path='tooling/das/standard',
                          sourceOfTruth=closure['refs']['standard']['uri'],
                          mirrorPurpose='Selected pinned templates and schemas for offline scaffold checks',
                          localModificationsAllowed=False,snapshotRef=closure['refs']['standard'])]
    policies = [e['id'] for e in registry['entries'] if e['kind']=='policyPack' and e['id']=='scaffold-v15']
    if not policies: raise ValueError('selected Cadence does not include scaffold-v15 metadata for its existing core checks')
    native = dict(projectId=fields['Project slug'], mode='strict_offline', closureRef='tooling/das/suite_version_closure.json',
                  toolingLock='tooling_lock.json', runtimeRef=VENDOR+'/cadence-sandbox/runtime_profile.json',
                  registryRef=VENDOR+'/cadence-registry/registry.json', sandboxRef=VENDOR+'/cadence-sandbox/sandbox_profile.json',
                  policies=policies, ui=dict(enabled=False))
    selected = dict(suiteCommit=suite_commit, factoryCodeDigest=identity,
                    runtime=closure['refs']['verifyRuntime'], suiteFiles={k:digest(v) for k,v in upstream.items()})
    destination.parent.mkdir(parents=True, exist_ok=True)
    directory=tempfile.mkdtemp(prefix='.dasops-create-', dir=destination.parent)
    preserve=False
    try:
        staged = Path(directory) / 'repo';staged.mkdir();write_snapshot(staged, templates)
        # Adapt only factory-owned guidance, before importing user documents.
        if profile == 'headless' and 'ui_spec' not in documents:
            for guidance in staged.rglob('*.md'):
                guidance.write_text(guidance.read_text().replace('docs/ui_spec.md','docs/headless_surface_note.md'))
        delta=staged/'openspec/schemas/das-standard/templates/master_doc_delta.md'
        delta.write_text(delta.read_text().replace('./scripts/verify --mode backend','./scripts/verify'))
        (staged / 'docs/ui_spec.md').unlink(missing_ok=True)
        (staged / 'local_extension_manifest.json').unlink(missing_ok=True)
        for path,data in documents.values(): (staged / path).write_bytes(data)
        if extension is not None: (staged/'local_extension_manifest.json').write_bytes(extension)
        for name,data in upstream.items():
            target = staged/prefix/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
        write_snapshot(staged/prefix, {name:value for name,value in suite_data.items() if name.startswith('schemas/')})
        standard_dir=staged/'tooling/das/standard';standard_dir.mkdir(parents=True)
        write_snapshot(standard_dir, standard_data)
        standard_digests={name:digest(value[0]) for name,value in standard_data.items()}
        write_json(staged/'tooling/das/suite_version_closure.json', derived)
        write_json(staged/'tooling_lock.json', lock)
        (staged/'cadence.yaml').write_text(yaml.safe_dump(native,sort_keys=False))
        native_schema=native_data['cadence-core/internal/config/config.schema.json'][0]
        (staged/'tooling/das/native-config.schema.json').write_bytes(native_schema)
        (staged/'VERIFY_REQUIREMENTS.md').write_text('# Product verification scope\n\n`./scripts/verify --scope scaffold` checks generated structure, documents and fixed sources.\n`./scripts/verify` also requires completed documents, an installed fixed runtime and applicable product checks.\nThe current core scanner does not execute UI tests or certify complete DAS conformance.\n')
        (staged/'README.md').write_text('# DAS '+EDITION+' product scaffold\n\nCanonical documents:\n'+''.join('- '+path+'\n' for path,_ in documents.values())+'\nRun `./scripts/verify --scope scaffold` before runtime installation.\nInstall from the selected fixed Suite with `./scripts/install_cadence_vendor.sh --from-suite /path/to/suite`.\nThen run `./cadencew doctor` and `./cadencew verify --profile dev`.\nDefault `./scripts/verify` fails when documents, the runtime or an applicable UI runner are unfinished.\nCreation does not grant approval or certify full DAS conformance.\n')
        manual=staged/'docs/USER_MANUAL.md'
        manual.write_text(product_manual(manual.read_text(),
                          [path for path,_ in documents.values()],
                          (staged/'local_extension_manifest.json').is_file()))
        (staged/'STANDARD_REF.md').write_text('# Governing Standard\n\nDAS '+EDITION+'\n\n'+json.dumps(closure['refs']['standard'],sort_keys=True)+'\n')
        state=dict(standardRelease=EDITION, projectId=fields['Project slug'], interactionProfile=profile,
                   documents={kind:path for kind,(path,_) in documents.items()}, selectedSources=selected,
                   standardFileDigests=standard_digests,
                   nativeSchemaDigest=digest(native_schema),
                   resourceDigests=resources, documentAuthors={kind:digest(author.encode()) for kind,author in authors.items()})
        write_json(staged/STATE,state)
        (staged/'scripts/das_scaffold.py').write_bytes(helper)
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


def check_entry_files(root, documents):
    required = [*ENTRY_FILES, *('openspec/schemas/das-standard/templates/'+name for name in CHANGE_TEMPLATES)]
    executable = ['scripts/verify', 'scripts/install_cadence_vendor.sh', 'cadencew']
    if 'ui_spec' in documents:
        required.append('scripts/verify-frontend');executable.append('scripts/verify-frontend')
    for name in required:
        try: read(local(root, name))
        except (OSError,ValueError) as exc: raise ValueError('required scaffold file missing or unreadable: '+name) from exc
    for name in executable:
        if not os.access(local(root, name), os.X_OK): raise ValueError('scaffold entry is not executable: '+name)
    config=yaml.safe_load(read(root/'openspec/config.yaml'))
    schema=yaml.safe_load(read(root/'openspec/schemas/das-standard/schema.yaml'))
    if not isinstance(config,dict) or config.get('schema')!='das-standard' or not isinstance(config.get('context'),str):
        raise ValueError('invalid OpenSpec config')
    if not isinstance(schema,dict) or schema.get('name')!='das-standard' or schema.get('version')!=1:
        raise ValueError('invalid OpenSpec schema')
    artifacts=schema.get('artifacts',[])
    if (not isinstance(artifacts,list) or not all(isinstance(item,dict) for item in artifacts)
            or len(artifacts)!=len(CHANGE_TEMPLATES) or {item.get('template') for item in artifacts}!=set(CHANGE_TEMPLATES)):
        raise ValueError('OpenSpec change templates differ')
    instruction=next((item.get('instruction','') for item in artifacts if item.get('id')=='master-doc-delta'),'')
    for text in (config['context'],instruction):
        if not isinstance(text,str) or set(re.findall(r'^\s*-\s+(docs/\S+)\s*$',text,re.M))!=set(documents.values()):
            raise ValueError('OpenSpec document context differs from actual documents')


def verify(root, scope='scaffold'):
    root=Path(root).resolve();problems=[];pending=[];checks=[]
    toolchain=dict(expected=[],observed=[],problems=[])
    try:
        state=load(root/STATE)
        if state['standardRelease']!=EDITION: raise ValueError('unsupported scaffold edition')
        check_entry_files(root, state['documents'])
        base=root/'tooling/das/standard'
        for name,expected in state['standardFileDigests'].items():
            if digest(read(local(base,name)))!=expected:raise ValueError('Standard mirror changed: '+name)
        catalog=load(base/'template_catalog.json')
        authors={e['docType']:author_section(e,read(local(base,e['artifactPath']))) for e in catalog['templates']}
        for kind,author in authors.items():
            if digest(author.encode())!=state['documentAuthors'][kind]:raise ValueError('template author changed: '+kind)
        manifest=load(base/'standard_manifest.json')
        docs=state['documents'];master=read(local(root,docs['master_doc']));fields,_=document_check('master_doc',master,authors,manifest=manifest)
        master_refs=document_references(master.decode())
        required=required_documents(fields, master_refs)
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
            check_extension_manifest(read(root/'local_extension_manifest.json'),base/'local_extension_manifest.schema.json')
            if 'local_extension_manifest.json' not in master_refs:raise ValueError('extension manifest is not referenced')
        elif 'local_extension_manifest.json' in master_refs:raise ValueError('referenced extension manifest missing')
        upstream=root/'tooling/das/suite'
        for name in SUITE_FILES:
            if digest(read(upstream/name))!=state['selectedSources']['suiteFiles'][name]:raise ValueError('Suite original changed: '+name)
            schema_check(load(upstream/name),upstream/'schemas/das-standard'/SCHEMAS[name])
        original=load(upstream/'suite_version_closure.json');derived=load(root/'tooling/das/suite_version_closure.json');lock=load(root/'tooling_lock.json')
        schema_check(derived,base/'suite_version_closure.schema.json');schema_check(lock,base/'tooling_lock.schema.json')
        toolchain=check_toolchain(lock['toolchain'])
        pending.extend(toolchain['problems'])
        for name in ('refs','standardVersion','standardManifestVersion','suiteVersion','factoryVersion','verifyRuntimeVersion'):
            if derived[name]!=original[name]:raise ValueError('derived closure identity changed: '+name)
        expected={'suiteToolingLock':'tooling/das/suite/suite.tooling_lock.json','repoToolingLock':'tooling_lock.json'}
        if derived['lockRefs']!={key:file_ref(value) for key,value in expected.items()}:raise ValueError('invalid product lock alignment')
        if derived['suiteLockRef']!=file_ref('tooling/das/suite/suite_lock.json') or lock['suiteLockRef']!=derived['suiteLockRef'] or lock['suiteVersionClosureRef']!=file_ref('tooling/das/suite_version_closure.json'):
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
            if pending:raise ValueError('full verification requires completed documents, matching toolchain and installed runtime')
            if 'ui_spec' in docs:
                run_frontend(root)
                checks.append(dict(name='product-frontend-command',status='passed',command='scripts/verify-frontend'))
            result=subprocess.run([str(installed(root)),'verify','--profile','dev'],cwd=root,capture_output=True,text=True,check=False)
            if result.returncode:raise ValueError('native core verification failed: '+result.stderr.strip())
            checks.append(dict(name='native-core',status='passed',policyMetadataOnly=True))
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError,yaml.YAMLError) as exc:problems.append(str(exc))
    return dict(ok=not problems,scope=scope,problems=problems,pendingItems=pending,checks=checks,toolchain=toolchain,
                qualification=False,coverage='scaffold structure'+(' and existing native core checks' if scope=='full' else ''))


def run_frontend(root):
    command=local(root,'scripts/verify-frontend')
    read(command)
    if not os.access(command,os.X_OK):raise ValueError('product frontend command is not executable')
    result=subprocess.run([str(command)],cwd=root,capture_output=True,text=True,timeout=300,check=False)
    if result.returncode:raise ValueError('product frontend checks failed: '+result.stderr.strip())


def installed(root):
    state=load(root/STATE);base=root/VENDOR;record=load(base/'.dasops-install.json')
    if record['runtime']!=state['selectedSources']['runtime']:
        raise ValueError('installed runtime source differs: expected '+json.dumps(state['selectedSources']['runtime'],sort_keys=True)+', observed '+json.dumps(record['runtime'],sort_keys=True))
    for path,expected in state['resourceDigests'].items():
        observed=digest(read(local(base,path)))
        if observed!=expected:raise ValueError(f'installed resource changed: {path}: expected {expected}, observed {observed}')
    binary=local(base,record['binaryPath'])
    observed=digest(read(binary))
    if observed!=record['binaryDigest']:raise ValueError(f"installed binary differs: expected {record['binaryDigest']}, observed {observed}")
    proc=subprocess.run([str(binary),'version','--json'],capture_output=True,text=True,timeout=10)
    if proc.returncode:raise ValueError('installed version check failed')
    identity=json.loads(proc.stdout)
    expected=dict(binarySha256=record['binaryDigest'],releaseVersion=record['releaseVersion'],sourceModified=False,sourceRevision=record['runtime']['pinValue'])
    observed={key:identity.get(key) for key in expected}
    if observed!=expected:
        raise ValueError('native binary/source identity differs: expected '+json.dumps(expected,sort_keys=True)+', observed '+json.dumps(observed,sort_keys=True))
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
