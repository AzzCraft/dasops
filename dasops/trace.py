"""dasops.trace — Version / CHANGELOG traceability checks.

Provides ``check_trace`` which asserts the VERSION string appears in
CHANGELOG.md, and ``check_standard_ref`` which validates STANDARD_REF.md
references a known standard version.
"""

from __future__ import annotations

import re
from pathlib import Path


def check_trace(repo_root: Path) -> list[str]:
    """Return a list of trace-check findings (empty == pass)."""
    findings: list[str] = []
    version_path = repo_root / "VERSION"
    changelog_path = repo_root / "CHANGELOG.md"

    if not version_path.exists():
        findings.append("VERSION file missing")
        return findings

    version = version_path.read_text(encoding="utf-8").strip()
    if not version:
        findings.append("VERSION file is empty")
        return findings

    if not changelog_path.exists():
        findings.append("CHANGELOG.md missing")
        return findings

    changelog = changelog_path.read_text(encoding="utf-8")
    if version not in changelog:
        findings.append(f"VERSION {version} not found in CHANGELOG.md")

    return findings


def check_standard_ref(repo_root: Path) -> list[str]:
    """Return findings for STANDARD_REF.md traceability."""
    findings: list[str] = []
    ref_path = repo_root / "STANDARD_REF.md"
    if not ref_path.exists():
        return findings  # not required in all repos

    text = ref_path.read_text(encoding="utf-8")
    # Expect a version like DAS v1.4.0 or similar
    if not re.search(r"v?\d+\.\d+", text):
        findings.append("STANDARD_REF.md does not reference a standard version")

    return findings


__all__ = ["check_standard_ref", "check_trace"]
