from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass, field
from pathlib import Path


TASK_ID = "OPS-002"


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
    repo_root = repo_root.expanduser().resolve()
    if not repo_root.is_dir():
        return AuditResult(repo_root=repo_root, findings=["repository root is not a directory"])
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


def normalize_repo(repo_root: Path) -> AuditResult:
    """Perform only non-deceptive structural normalization.

    A missing policy, document or verifier cannot be honestly synthesized from a
    generic template.  In particular, never create a verifier that prints a
    success message and then report the repository as adopted.
    """
    result = audit_repo(repo_root)
    repaired: list[str] = []
    for finding in result.findings:
        if finding == "missing openspec/changes":
            target = repo_root / "openspec" / "changes"
            target.mkdir(parents=True, exist_ok=True)
            repaired.append("created openspec/changes directory")
        elif finding.endswith("must be a directory"):
            # Do not delete a user file in order to make an audit pass.
            continue
        elif finding.startswith("missing "):
            rel = finding[len("missing "):]
            if rel in REQUIRED_PATHS and REQUIRED_PATHS[rel] == "dir":
                target = repo_root / rel
                target.mkdir(parents=True, exist_ok=True)
                repaired.append(f"created {rel} directory")
    after = audit_repo(repo_root)
    return AuditResult(repo_root=repo_root, findings=after.findings, repaired=repaired)


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
    evidence_dir = repo_root / ".dasops"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence = evidence_dir / "adoption_evidence.json"
    outcome = "adopted" if not result.findings else "incomplete"
    evidence.write_text(
        '{"task":"OPS-002","status":"' + outcome + '","remainingFindings":' + str(len(result.findings)) + '}\n',
        encoding="utf-8",
    )
    return {
        "schemaVersion": 1,
        "task": TASK_ID,
        "command": "adopt-repo",
        "ok": not result.findings,
        "repoRoot": str(repo_root),
        "repairedArtifacts": result.repaired,
        "remainingFindings": result.findings,
        "evidencePath": ".dasops/adoption_evidence.json",
    }


def normalize_report(repo_root: Path) -> dict[str, object]:
    result = normalize_repo(repo_root)
    repair = _get_repair_tree()(repo_root)
    return {
        "schemaVersion": 1,
        "task": TASK_ID,
        "command": "normalize-repo",
        "ok": not result.findings,
        "repoRoot": str(repo_root),
        "repairedArtifacts": result.repaired,
        "remainingFindings": result.findings,
        "docLinkRepairs": repair.rewrites,
        "docLinkFilesChanged": repair.files_changed,
    }


def trace_report(repo_root: Path) -> dict[str, object]:
    audit = audit_repo(repo_root)
    trace_issues = trace_check(repo_root)
    problems = [
        {
            "artifact": artifact,
            "message": f"{TASK_ID} trace-check missing artifact: {artifact}",
        }
        for artifact in _missing_artifacts(audit.findings)
    ]
    problems.extend(
        {"artifact": "trace", "message": f"{TASK_ID} trace-check: {issue}"}
        for issue in trace_issues
    )
    ok = not problems
    kinds = ["requirements", "tasks", "verify", "evidence"] if ok else []
    return {
        "schemaVersion": 1,
        "task": TASK_ID,
        "command": "trace-check",
        "ok": ok,
        "repoRoot": str(repo_root),
        "kinds": kinds,
        "relations": [
            {"from": "requirements", "to": "tasks"},
            {"from": "tasks", "to": "verify"},
            {"from": "verify", "to": "evidence"},
        ] if ok else [],
        "problems": problems,
    }


def repair_doc_links(repo_root: Path) -> list[str]:
    """Scan markdown files for broken internal links and report them."""
    broken: list[str] = []
    docs_dir = repo_root / "docs"
    if not docs_dir.is_dir():
        return broken
    for md in docs_dir.rglob("*.md"):
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
    if version_file.exists():
        version = version_file.read_text().strip()
        if not version:
            issues.append("VERSION file is empty")
    else:
        issues.append("VERSION file missing")
    changelog = repo_root / "CHANGELOG.md"
    if changelog.exists():
        content = changelog.read_text(errors="replace")
        if version_file.exists():
            ver = version_file.read_text().strip()
            if ver and ver not in content:
                issues.append(f"CHANGELOG.md does not mention current version {ver}")
    return issues
