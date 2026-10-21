"""DAS-03-008 idempotent doc-link repair.

Walks markdown files in a directory tree and rewrites known stale link
targets to their canonical paths. Returns a structured report. Running
the tool twice in a row must produce zero edits the second time
(idempotency contract).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlsplit

# (regex, replacement) pairs applied to link targets only.
DEFAULT_REWRITES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\.\./standard-v1\.4\.0/"), "../standard/"),
    (re.compile(r"\.\./standard-v1\.4\.4/"), "../standard/"),
    (re.compile(r"\.\./standard-v1\.4\.5/"), "../standard/"),
    (
        re.compile(r"DAS_L2_v10_[1-6]_Commercial_Implementation_Package"),
        "release-inputs/commercial/v1.0.0",
    ),
    (
        re.compile(r"DAS_L2_v10_[1-6]_Release_Package_20260427"),
        "DAS_TOOLS_v1_0_0",
    ),
    (re.compile(r"DAS_L2_v10_[1-6]_"), "DAS_TOOLS_v1_0_0_"),
]

LINK_RE = re.compile(r"(?P<prefix>[!\[]?)\[(?P<text>[^\]]*)\]\((?P<target>[^)\s]+)(?P<title>\s+\"[^\"]*\")?\)")


@dataclass
class RepairReport:
    edits: int = 0
    files_changed: list[str] = field(default_factory=list)
    rewrites: list[dict] = field(default_factory=list)


def repair_text(text: str, rewrites: list[tuple[re.Pattern, str]] | None = None) -> tuple[str, list[dict]]:
    rules = rewrites or DEFAULT_REWRITES
    edits: list[dict] = []

    def _sub(match: re.Match) -> str:
        target = match.group("target")
        new_target = target
        for pat, repl in rules:
            new_target = pat.sub(repl, new_target)
        if new_target != target:
            edits.append({"from": target, "to": new_target})
        title = match.group("title") or ""
        return f"{match.group('prefix')}[{match.group('text')}]({new_target}{title})"

    new_text = LINK_RE.sub(_sub, text)
    return new_text, edits


def repair_tree(
    root: Path,
    *,
    rewrites: list[tuple[re.Pattern, str]] | None = None,
    write: bool = True,
) -> RepairReport:
    report = RepairReport()
    if not root.is_dir():
        return report
    for md in sorted(root.rglob("*.md")):
        if not md.is_file() or md.is_symlink():
            continue
        try:
            text = md.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        edits = []
        def repair_link(match):
            original = match.group(0)
            replacement, proposed = repair_text(original, rewrites)
            if not proposed:
                return original
            old = urlsplit(proposed[0]["from"])
            new = urlsplit(proposed[0]["to"])
            if old.scheme or new.scheme or not new.path:
                return original
            # Preserve valid historical references. Never replace a missing
            # target with another missing target merely because its name matches.
            if (md.parent / unquote(old.path)).exists() or not (md.parent / unquote(new.path)).is_file():
                return original
            edits.extend(proposed)
            return replacement
        new_text = LINK_RE.sub(repair_link, text)
        if edits:
            report.edits += len(edits)
            report.files_changed.append(str(md.relative_to(root)))
            report.rewrites.extend(edits)
            if write and new_text != text:
                md.write_text(new_text, encoding="utf-8")
    return report


def is_idempotent(root: Path, **kwargs) -> bool:
    """Run repair twice; second pass must be a no-op."""
    repair_tree(root, **kwargs)
    second = repair_tree(root, **kwargs)
    return second.edits == 0
