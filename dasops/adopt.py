from __future__ import annotations

import importlib.util
import hashlib
import sys
import re
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
import time


TASK_ID = "OPS-002"


def governed_adoption_inputs(database, resolver, *, actor, epoch, scope, target,
                             expected_bundle_digest, retain_preparation=True):
    """Current approved reading/adoption input; never normalize legacy files.

    The installed service supplies resolver and the actual candidate/baseline.
    An edited Bundle file, preview or Context Pack cannot replace recomputation.
    The installed preparation consumer can use retain_preparation=False to
    preserve the action's exact native preparation while recomputing reading
    inputs. It does not change the current approval or authorize a write.
    Actual file replacement still goes through the existing protected candidate
    and resource manager, with its separate current action authorization.
    """
    from .protected.bundle import BundleError, NativeBundleResolver, context_pack

    if not isinstance(resolver, NativeBundleResolver):
        raise BundleError('installed current Bundle resolver required')
    bundle, requirements = resolver.resolve(database, actor=actor, epoch=epoch, scope=scope,
        target=target, retain_preparation=retain_preparation)
    if bundle['bundleDigest'] != expected_bundle_digest:
        raise BundleError('current Bundle differs from the approved adoption input')
    if bundle['status'] != 'resolved' or bundle['resolution']['leafMigrationComplete'] is not True:
        raise BundleError('complete leaf migration and determined applicability required for adoption')
    return bundle, context_pack(bundle, requirements)


def render_section_template(author, source, values):
    """Instantiate one pinned Appendix M section with explicit literal values.

    This is data preparation, not a template language or an approval. Callers
    must bind the author bytes to their installed Standard before using it.
    Every placeholder needs a value; no project facts or defaults are invented.
    """
    from .protected.candidates.store import CandidateError
    if author.get('templateKind') != 'minimal_governed' or type(values) is not dict:
        raise CandidateError('section template requires explicit installed values')
    try:
        text = source.decode('utf-8')
    except (UnicodeError, AttributeError) as exc:
        raise CandidateError('section template requires UTF-8 author bytes') from exc
    # The fixed catalog points at ATX sections in the normative Appendix M.
    # Ignore fenced examples; require one exact heading and stop at its sibling.
    headings = []; fence = None
    for match in re.finditer(r'^.*(?:\n|$)', text, re.M):
        line = match.group().rstrip('\r\n')
        fenced = re.match(r'^\s{0,3}(`{3,}|~{3,})', line)
        if fenced:
            mark = fenced.group(1)
            if fence is None: fence = mark
            elif mark[0] == fence[0] and len(mark) >= len(fence): fence = None
            continue
        if fence is not None: continue
        heading = re.match(r'^(#{1,6})\s+(.+?)\s*#*\s*$', line)
        if heading:
            slug = re.sub(r'[^\w\- ]', '', heading.group(2).strip().lower())
            slug = re.sub(r'[\s-]+', '-', slug).strip('-')
            headings.append((match.start(), len(heading.group(1)), slug))
    selected = [row for row in headings if row[2] == author.get('sectionAnchor')]
    if len(selected) != 1:
        raise CandidateError('section template author anchor missing or ambiguous')
    start, level, _ = selected[0]
    end = next((offset for offset, depth, _ in headings if offset > start and depth <= level), len(text))
    section = text[start:end].rstrip() + '\n'
    markers = set(re.findall(r'<([^<>\n]+)>', section))
    if (set(values) != markers or any(type(value) is not str or not value.strip()
            or '\x00' in value or re.fullmatch(r'\s*<[^<>\n]+>\s*', value)
            for value in values.values())):
        raise CandidateError('section template needs exactly all nonempty literal placeholder values')
    for line in section.splitlines():
        if re.match(r'^-\s+\*\*[^*]+:\*\*', line):
            if any('\n' in values[key] or '\r' in values[key]
                   for key in re.findall(r'<([^<>\n]+)>', line)):
                raise CandidateError('document metadata values must occupy one line')
    # One substitution over the pinned author only. Explicit project prose/code
    # is literal data; an embedded <Type> or example <owner> is not a second
    # template pass. A whole unresolved placeholder value still rejects above.
    rendered = re.sub(r'<([^<>\n]+)>', lambda match: values[match.group(1)], section).encode('utf-8')
    if len(rendered) > 65536:
        raise CandidateError('section template exceeds the bounded reference profile')
    return rendered


def render_full_template(author, source, values):
    """Fill explicit literal prose fields in a pinned canonical author.

    Drafts may retain unfilled fields. An active label requires every required
    prose field filled; it never asserts human approval or the other readiness
    obligations. Fenced examples and inserted project data are never expanded.
    """
    from .protected.candidates.store import CandidateError
    if author.get('templateKind') != 'canonical_full' or type(values) is not dict:
        raise CandidateError('canonical template requires explicit installed values')
    try:
        text = source.decode('utf-8')
    except (UnicodeError, AttributeError) as exc:
        raise CandidateError('canonical template requires UTF-8 author bytes') from exc
    pattern = r'\{\{([^{}\n]+)\}\}|\[\[([^\[\]\n]+)\]\]'
    lines=[]; fence=None; fields=set(); required=set()
    for line in text.splitlines(keepends=True):
        mark=re.match(r'^ {0,3}(`{3,}|~{3,})(.*?)(?:\r?\n)?$',line)
        if fence is not None:
            lines.append((line,False))
            if mark and mark[1][0]==fence[0] and len(mark[1])>=len(fence) and not mark[2].strip():
                fence=None
            continue
        if mark:
            fence=mark[1];lines.append((line,False));continue
        lines.append((line,True))
        for match in re.finditer(pattern,line):
            key=match[1] or match[2]
            # These describe the syntax in the Master author, not project fields.
            if key in ('REQUIRED_PLACEHOLDER','OPTIONAL_PLACEHOLDER'):continue
            fields.add(key)
            if match[1] is not None:required.add(key)
    if (not values or not set(values)<=fields
            or any(type(value) is not str or not value.strip() or '\x00' in value
                or re.fullmatch(r'\s*(?:\{\{[^{}\n]+\}\}|\[\[[^\[\]\n]+\]\])\s*',value)
                for value in values.values())):
        raise CandidateError('canonical template needs known nonempty literal placeholder values')
    control_level=None
    for line,prose in lines:
        if not prose:continue
        heading=re.match(r'^(#{1,6})\s+(.+)',line)
        if heading:
            if 'document control' in heading[2].lower():control_level=len(heading[1])
            elif control_level is not None and len(heading[1])<=control_level:control_level=None
        # A bold project outcome bullet is prose, not document metadata.
        if control_level is not None and re.match(r'^-\s+\*\*[^*]+\*\*:',line):
            if any('\n' in values[key] or '\r' in values[key]
                    for match in re.finditer(pattern,line)
                    for key in [match[1] or match[2]] if key in values):
                raise CandidateError('document metadata values must occupy one line')
    if 'STATUS' in values and values['STATUS'] not in ('draft','active','frozen','deprecated'):
        raise CandidateError('canonical document status must be an exact supported value')
    if values.get('STATUS')=='active' and not required<=set(values):
        raise CandidateError('active canonical document still has unfilled required prose fields')
    rendered=''.join(re.sub(pattern,lambda match:values.get(match[1] or match[2],match[0]),line)
        if prose else line for line,prose in lines).encode('utf-8')
    if len(rendered)>65536:
        raise CandidateError('canonical template exceeds the bounded reference profile')
    return rendered


class GovernedAdoption:
    """Installed template preparation for the existing govern plan.

    The installer fixes template destinations and the permitted C -> I selection.
    Candidate preparation never switches a target, registers a plan or completes
    a task. The ordinary authenticated submit/plan/integrate/complete path owns
    those effects. Context Packs remain outside the candidates they reference.
    """
    def __init__(self, resolver, *, templates, source_paths, template_values=None):
        from .protected.bundle import NativeBundleResolver
        from .protected.candidates.store import CandidateError, CandidateLimits, _path
        if not isinstance(resolver, NativeBundleResolver):
            raise CandidateError('installed native adoption resolver required')
        if (type(templates) is not dict or not templates or len(templates)>64
                or not isinstance(source_paths, (list, tuple))
                or not source_paths or len(source_paths)>CandidateLimits().max_files
                or any(not isinstance(path,str) for path in source_paths)
                or list(source_paths)!=sorted(set(source_paths))):
            raise CandidateError('installed exact template mapping and sorted selection required')
        paths=tuple(source_paths)
        for name in paths:
            if name.startswith('tree/'):
                _path(name[5:],CandidateLimits())
            elif name.startswith('materials/') and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}',name[10:]):
                _path(name[10:],CandidateLimits())
            else:
                raise CandidateError('adoption selects exact candidate files or flat material IDs only')
        for name,kind in templates.items():
            if (name not in paths or not name.startswith('tree/') or not isinstance(kind,str) or not kind
                    or kind=='context_pack'):
                raise CandidateError('template destination must be selected; Pack stays outside candidate')
        self.resolver=resolver
        self.templates=MappingProxyType(dict(templates))
        self.source_paths=paths
        values={} if template_values is None else template_values
        if (type(values) is not dict or not set(values) <= set(templates)
                or any(type(row) is not dict or len(row)>256
                    or any(type(key) is not str or len(key)>256 or type(value) is not str or len(value.encode('utf-8'))>65536
                           for key,value in row.items()) for row in values.values())):
            raise CandidateError('bounded installed section template values required')
        if any(sum(len(value.encode('utf-8')) for value in row.values())>65536 for row in values.values()):
            raise CandidateError('section template values exceed the bounded reference profile')
        self.template_values=MappingProxyType({name:MappingProxyType(dict(row)) for name,row in values.items()})

    def prepare(self, manager, *, actor, epoch, scope, resource, instance,
                generation, source, expected_bundle_digest, authorize, integrated=None):
        """Build immutable I from current B and received C, checking real templates.

        C is committed material received through CandidateStore, never a caller
        pathname or executable template. Unselected local B files are retained.
        Returned Bundle/Pack are reading inputs, not authority or a completed plan.
        """
        from .protected.bundle import BundleError
        from .protected.candidates.versions import VersionTreeManager
        from .protected.candidates.store import CandidateError
        from .protected.candidates.qualification import NativeQualification
        from .protected.sqlite.store import _integer
        from .standards_contracts import exact_json as codec
        if not isinstance(manager,VersionTreeManager):
            raise CandidateError('installed adoption version manager required')
        qualification=manager.check_qualification
        if (not isinstance(qualification,NativeQualification)
                or qualification.bundle_resolver is not self.resolver
                or qualification.adoption_bundle is None
                or qualification.adoption_bundle['scope'] != scope or not callable(authorize)):
            raise CandidateError('adoption must use the installed qualification resolver and scope')
        epoch=_integer(epoch); generation=_integer(generation,1)
        def current():
            with manager.database.read_snapshot() as connection:
                meta=connection.execute('SELECT authority_epoch FROM metadata WHERE singleton=1').fetchone()
                if (meta['authority_epoch']!=epoch
                        or authorize(connection,'govern_plan',actor,epoch) is not True):
                    raise CandidateError('current adoption preparation authorization denied')
                target=manager._target(connection,resource,instance)
                if target['generation']!=generation:
                    raise CandidateError('adoption target generation changed')
                binding=manager.candidates.verify(source)
                manager._current_task(connection,binding)
                return target,binding
        before,binding=current()
        # A selected template must be the exact registered artifact from the
        # independently pinned Standard snapshot. No text execution or repair.
        deadline=time.clock_gettime(time.CLOCK_BOOTTIME)+self.resolver.timeout
        edition=qualification.adoption_bundle['standardVersion']
        _,members=self.resolver._content(edition,deadline,retain_sources={'template_catalog.json',
            'appendices/appendix-m-doc-family-governance-and-module-doc-templates.md',
            'appendices/appendix-c-project-master-doc-template.md',
            'appendices/appendix-d-ui-spec-appendix-template.md'})
        catalog=codec.parse(members['sourceBytes']['template_catalog.json'])
        codec.closed_object(catalog,['schemaVersion','standardVersion','templates'],['$schema'])
        if catalog['schemaVersion']!='1.0.0' or catalog['standardVersion']!=edition:
            raise CandidateError('installed template catalog edition differs')
        rows=catalog['templates']
        if not isinstance(rows,list) or not rows or len(rows)>64:
            raise CandidateError('bounded installed template catalog required')
        authors={}
        for row in rows:
            codec.closed_object(row,['docType','artifactPath','sectionAnchor','templateKind','notes'])
            if row['docType'] in authors:
                raise CandidateError('template catalog has duplicate document authors')
            authors[row['docType']]=row
        inventory={f['path']:f for f in binding['files']}
        for name,kind in self.templates.items():
            author=authors.get(kind)
            if author is None or author['artifactPath'] not in members['memberDigests']:
                raise CandidateError('requested document has no pinned template author')
            expected=members['memberDigests'][author['artifactPath']]
            if author['templateKind']=='minimal_governed':
                if name not in self.template_values:
                    raise CandidateError('section template requires explicit installed values')
                raw=members['sourceBytes'].get(author['artifactPath'])
                rendered=render_section_template(author,raw,dict(self.template_values[name]))
                expected=hashlib.sha256(rendered).hexdigest()
            elif author['templateKind']=='canonical_full':
                if name in self.template_values:
                    rendered=render_full_template(author,members['sourceBytes'].get(author['artifactPath']),
                        dict(self.template_values[name]))
                    expected=hashlib.sha256(rendered).hexdigest()
            else:
                raise CandidateError('unsupported installed template kind')
            item=inventory.get(name[5:])
            if item is None or item['mode']!='100644' or item['contentSha256']!='sha256:'+expected:
                raise CandidateError('candidate template differs from the installed Standard author')
        if integrated is None:
            prepared=manager.candidates.compose_integration(before['candidate_digest'],source,
                source_paths=list(self.source_paths),deleted_paths=[],tool_digest=manager.tool_digest)
        else:
            # Authenticated plan preflight is read-only, before the existing
            # grant/budget outbox. Verify received I rather than publishing one.
            lineage=manager.candidates.integration_lineage(before['candidate_digest'],source,integrated,
                tool_digest=manager.tool_digest)
            if lineage['sourcePaths']!=list(self.source_paths) or lineage['deletedPaths']:
                raise CandidateError('adoption candidate differs from installed source selection')
            prepared=dict(candidateDigest=integrated,lineage=lineage,lineageDigest=codec.digest(lineage))
        if current()!=(before,binding):
            raise CandidateError('adoption target or source changed during composition')
        target=dict(candidateDigest=prepared['candidateDigest'],deploymentBaselineDigest=before['candidate_digest'])
        try:
            bundle,pack=governed_adoption_inputs(manager.database,self.resolver,actor=actor,epoch=epoch,
                scope=scope,target=target,expected_bundle_digest=expected_bundle_digest,
                retain_preparation=False)
        except BundleError as exc:
            raise CandidateError('current complete adoption inputs required') from exc
        if current()!=(before,binding):
            raise CandidateError('adoption target or source changed during preparation')
        return dict(candidate=prepared,bundle=bundle,contextPack=pack,
                    expectedGeneration=generation,beforeCandidateDigest=before['candidate_digest'])

    def check_plan(self, manager, intent, *, actor, epoch, authorize):
        """Recompute the prepared I at the existing authenticated plan boundary."""
        from .protected.candidates.store import CandidateError
        plan=intent['parameters']['plan']
        if plan['contractIdentity']=='das-version-tree-plan/v1' and plan['rollbackOf'] is not None:
            # Compensation restores the retained snapshot, not a fresh template.
            # It still needs a new current Bundle and purpose-specific native
            # verification/grants in the ordinary version manager transaction.
            from .protected.candidates.qualification import NativeQualification
            native=manager.check_qualification
            if (not isinstance(native,NativeQualification) or native.bundle_resolver is not self.resolver
                    or native.adoption_bundle is None):
                raise CandidateError('installed current adoption compensation qualification required')
            def current():
                with manager.database.read_snapshot() as connection:
                    metadata=connection.execute('SELECT authority_epoch FROM metadata WHERE singleton=1').fetchone()
                    if metadata['authority_epoch']!=epoch or authorize(connection,'govern_plan',actor,epoch) is not True:
                        raise CandidateError('current compensation preparation authorization denied')
                    target=manager._target(connection,plan['resourceId'],plan['resourceInstance'])
                    if (target['generation'],target['candidate_digest'])!=(plan['expectedGeneration'],plan['beforeCandidateDigest']):
                        raise CandidateError('compensation target changed before planning')
                    manager._rollback_receipt(connection,plan['resourceId'],plan['resourceInstance'],
                        plan['expectedGeneration'],plan['rollbackOf'],plan['afterCandidateDigest'])
                    return target
            before=current()
            from .protected.bundle import BundleError
            try:
                governed_adoption_inputs(manager.database,self.resolver,actor=actor,epoch=epoch,
                    scope=native.adoption_bundle['scope'],target=dict(candidateDigest=plan['afterCandidateDigest'],
                        deploymentBaselineDigest=plan['beforeCandidateDigest']),
                    expected_bundle_digest=native.adoption_bundle['bundleDigest'],retain_preparation=False)
            except BundleError as exc:
                raise CandidateError('current complete compensation inputs required') from exc
            if current()!=before:
                raise CandidateError('compensation target changed during current preparation')
            return
        if plan['contractIdentity']!='das-integration-plan/v1':
            raise CandidateError('template adoption requires an integration plan')
        bundle=manager.check_qualification.adoption_bundle
        prepared=self.prepare(manager,actor=actor,epoch=epoch,scope=bundle['scope'],
            resource=plan['resourceId'],instance=plan['resourceInstance'],generation=plan['expectedGeneration'],
            source=plan['sourceCandidateDigest'],expected_bundle_digest=bundle['bundleDigest'],authorize=authorize,
            integrated=plan['afterCandidateDigest'])
        if (prepared['candidate']['candidateDigest']!=plan['afterCandidateDigest']
                or prepared['beforeCandidateDigest']!=plan['beforeCandidateDigest']):
            raise CandidateError('adoption plan differs from the prepared current candidate')


def _get_repair_tree():
    try:
        from .repair_doc_links import repair_tree
        return repair_tree
    except ImportError:
        module_name = "dasops_adopt_repair_doc_links"
        module = sys.modules.get(module_name)
        if module is None:
            spec = importlib.util.spec_from_file_location(module_name, Path(__file__).with_name("repair_doc_links.py"))
            if spec is None or spec.loader is None:
                raise ImportError("unable to load repair_doc_links.py")
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
        return module.repair_tree


@dataclass(frozen=True)
class AuditResult:
    repo_root: Path
    findings: list[str]
    repaired: list[str] = field(default_factory=list)


# Required paths for a DAS-compliant repository.
REQUIRED_PATHS: dict[str, str] = {
    "docs/master_doc.md": "file",
    "docs/ui_spec.md": "file",
    "openspec/changes": "dir",
    "VERSION": "file",
    "CHANGELOG.md": "file",
    "README.md": "file",
    "scripts/verify": "file",
    "BUILD_REQUIREMENTS.md": "file",
    "VERIFY_REQUIREMENTS.md": "file",
    "NOTICE": "file",
    "LICENSE": "file",
}


def audit_repo(repo_root: Path) -> AuditResult:
    """Check a repo for DAS compliance.  Returns an AuditResult with findings."""
    findings: list[str] = []
    for rel, expected_kind in REQUIRED_PATHS.items():
        target = repo_root / rel
        if not target.exists():
            findings.append(f"missing {rel}")
            continue
        if expected_kind == "dir" and not target.is_dir():
            findings.append(f"{rel} must be a directory")
        if expected_kind == "file" and not target.is_file():
            findings.append(f"{rel} must be a file")
    # Check for cadence config
    if not (repo_root / "cadence.yaml").exists() and not (repo_root / "cadence.yml").exists():
        findings.append("missing cadence.yaml or cadence.yml")
    return AuditResult(repo_root=repo_root, findings=findings)


def _normalization_conflicts(repo_root: Path) -> list[str]:
    conflicts: set[str] = set()
    for rel, kind in {**REQUIRED_PATHS, "cadence.yaml": "file", ".dasops": "dir",
                      ".dasops/adoption_evidence.json": "file"}.items():
        target = repo_root / rel
        for parent in target.parents:
            if parent == repo_root:
                break
            if parent.is_symlink() or (parent.exists() and not parent.is_dir()):
                conflicts.add(f"{parent.relative_to(repo_root)} must be a real directory")
        if target.is_symlink() or (target.exists() and (target.is_dir() if kind == "dir" else target.is_file()) is False):
            conflicts.add(f"{rel} must be a real {kind}")
    return sorted(conflicts)


def normalize_repo(repo_root: Path) -> AuditResult:
    """Audit and automatically create missing governance baseline files."""
    conflicts = _normalization_conflicts(repo_root)
    if conflicts:
        return AuditResult(repo_root=repo_root, findings=conflicts)
    result = audit_repo(repo_root)
    repaired: list[str] = []
    for finding in result.findings:
        if finding == "missing cadence.yaml or cadence.yml":
            target = repo_root / "cadence.yaml"
            if not target.exists():
                target.write_text("version: 1\nprofile: adopted\n", encoding="utf-8")
                repaired.append("created cadence.yaml")
        elif finding.startswith("missing "):
            rel = finding[len("missing "):]
            target = repo_root / rel
            if not target.exists():
                expected_kind = REQUIRED_PATHS.get(rel)
                if expected_kind == "dir":
                    target.mkdir(parents=True, exist_ok=True)
                    repaired.append(f"created {rel}")
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.name == "verify":
                    target.write_text("#!/usr/bin/env bash\nset -euo pipefail\necho \"verify: not_configured; replace this placeholder with the project verification gate\" >&2\nexit 2\n", encoding="utf-8")
                    target.chmod(0o755)
                elif target.suffix in (".md", ".txt", ""):
                    target.write_text(
                        f"# {target.stem}\n\nCreated by dasops adopt; add repository-specific details before release.\n",
                        encoding="utf-8",
                    )
                else:
                    target.write_text("", encoding="utf-8")
                repaired.append(f"created {rel}")
    return AuditResult(repo_root=repo_root, findings=result.findings, repaired=repaired)


def _missing_artifacts(findings: list[str]) -> list[str]:
    artifacts: list[str] = []
    for finding in findings:
        if finding.startswith("missing "):
            artifacts.append(finding[len("missing "):])
        elif finding == "missing cadence.yaml or cadence.yml":
            artifacts.append("cadence.yaml")
    return artifacts


def audit_report(repo_root: Path) -> dict[str, object]:
    result = audit_repo(repo_root)
    return {
        "schemaVersion": 1,
        "task": TASK_ID,
        "command": "audit-repo",
        "ok": not result.findings,
        "repoRoot": str(repo_root),
        "missingArtifacts": _missing_artifacts(result.findings),
        "findings": result.findings,
    }


def adopt_report(repo_root: Path) -> dict[str, object]:
    result = normalize_repo(repo_root)
    conflicts = _normalization_conflicts(repo_root) or audit_repo(repo_root).findings
    if conflicts:
        return {"schemaVersion": 1, "task": TASK_ID, "command": "adopt-repo",
                "ok": False, "repoRoot": str(repo_root), "findings": conflicts,
                "repairedArtifacts": [], "docLinkRepairs": [], "docLinkFilesChanged": []}

    evidence_dir = repo_root / ".dasops"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence = evidence_dir / "adoption_evidence.json"
    evidence.write_text('{"task":"OPS-002","status":"adopted"}\n', encoding="utf-8")
    return {
        "schemaVersion": 1,
        "task": TASK_ID,
        "command": "adopt-repo",
        "ok": True,
        "repoRoot": str(repo_root),
        "repairedArtifacts": result.repaired,
        "evidencePath": ".dasops/adoption_evidence.json",
    }


def normalize_report(repo_root: Path) -> dict[str, object]:
    result = normalize_repo(repo_root)
    conflicts = _normalization_conflicts(repo_root) or audit_repo(repo_root).findings
    if conflicts:
        return {"schemaVersion": 1, "task": TASK_ID, "command": "normalize-repo",
                "ok": False, "repoRoot": str(repo_root), "findings": conflicts,
                "repairedArtifacts": [], "docLinkRepairs": [], "docLinkFilesChanged": []}

    repair = _get_repair_tree()(repo_root)
    return {
        "schemaVersion": 1,
        "task": TASK_ID,
        "command": "normalize-repo",
        "ok": True,
        "repoRoot": str(repo_root),
        "repairedArtifacts": result.repaired,
        "docLinkRepairs": repair.rewrites,
        "docLinkFilesChanged": repair.files_changed,
    }


def trace_report(repo_root: Path) -> dict[str, object]:
    audit = audit_repo(repo_root)
    trace_issues = trace_check(repo_root)
    problems = [{"artifact": "layout", "message": f"{TASK_ID} trace-check: {finding}"}
                for finding in audit.findings]
    problems.extend(
        {"artifact": "trace", "message": f"{TASK_ID} trace-check: {issue}"}
        for issue in trace_issues
    )
    ok = not problems
    kinds = ["layout", "version-changelog"] if ok else []
    return {
        "schemaVersion": 1,
        "task": TASK_ID,
        "command": "trace-check",
        "ok": ok,
        "repoRoot": str(repo_root),
        "kinds": kinds,
        "scope": "layout-and-version-only",
        "relations": [],
        "problems": problems,
    }


def repair_doc_links(repo_root: Path) -> list[str]:
    """Scan markdown files for broken internal links and report them."""
    broken: list[str] = []
    docs_dir = repo_root / "docs"
    if not docs_dir.is_dir():
        return broken
    for md in docs_dir.rglob("*.md"):
        if not md.is_file() or md.is_symlink():
            continue
        content = md.read_text(errors="replace")
        # Simple bracket-link scanner: [text](target)
        import re
        for m in re.finditer(r"\[([^\]]*)\]\(([^)]+)\)", content):
            target = m.group(2)
            if target.startswith("http://") or target.startswith("https://"):
                continue
            # Strip anchors
            target_path = target.split("#")[0]
            if not target_path:
                continue
            resolved = (md.parent / target_path).resolve()
            if not resolved.exists():
                rel_md = md.relative_to(repo_root)
                broken.append(f"{rel_md}: broken link to {target_path}")
    return broken


def trace_check(repo_root: Path) -> list[str]:
    """Verify that key artifacts trace back to the standard."""
    issues: list[str] = []
    version_file = repo_root / "VERSION"
    if version_file.is_file():
        version = version_file.read_text().strip()
        if not version:
            issues.append("VERSION file is empty")
    else:
        issues.append("VERSION file missing")
    changelog = repo_root / "CHANGELOG.md"
    if changelog.is_file():
        content = changelog.read_text(errors="replace")
        if version_file.is_file():
            ver = version_file.read_text().strip()
            if ver and re.search(r"(?<![\w.+-])" + re.escape(ver) + r"(?![\w.+-])", content) is None:
                issues.append(f"CHANGELOG.md does not mention current version {ver}")
    return issues
