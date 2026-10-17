from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .bundle_preview import resolve_preview, resolve_facts_preview


PACK_ROLE_ALIASES = {
    "all": "all",
    "backend": "backend",
    "frontend": "frontend",
    "architect": "architect",
    "devops": "devops",
    "qa": "qa",
    "sre": "sre",
    "tech-lead": "tech-lead",
}

RELEASE_PACKAGE_DIR_NAME = "DAS_TOOLS_v1_0_0"
RELEASE_MARKER_FILES = ("RELEASE_SHA256SUMS", "GIT_REVISION.txt")


def _has_standard_indexes(candidate: Path) -> bool:
    return (candidate / "chapter_index.json").exists() and (candidate / "clause_index.json").exists()


def _is_release_root(candidate: Path) -> bool:
    return candidate.name == RELEASE_PACKAGE_DIR_NAME and any(
        (candidate / marker).exists()
        for marker in RELEASE_MARKER_FILES
    )


def _release_root_for_repo_root(repo_root: Path) -> Path | None:
    resolved = repo_root.resolve()
    for candidate in (resolved, *resolved.parents):
        if _is_release_root(candidate):
            return candidate
    return None


def _candidate_standard_roots(repo_root: Path, override: str | None) -> list[Path]:
    if override:
        return [Path(override).expanduser().resolve()]

    environment_override = os.environ.get("DAS_STANDARD_ROOT", "").strip()
    if environment_override:
        return [Path(environment_override).expanduser().resolve()]

    release_root = _release_root_for_repo_root(repo_root)
    if release_root is not None:
        return [release_root / "das-standard"]

    package_root = Path(__file__).resolve().parents[2]
    return [
        repo_root / "das-standard",
        repo_root.parent / "das-standard",
        package_root.parent / "das-standard",
    ]


def resolve_standard_root(repo_root: Path, override: str | None = None) -> Path:
    for candidate in _candidate_standard_roots(repo_root, override):
        if _has_standard_indexes(candidate):
            return candidate
    if override:
        requested = Path(override).expanduser().resolve()
        raise SystemExit(
            "Could not locate das-standard indexes at explicit --standard-root.\n"
            f"Required files: {requested / 'chapter_index.json'} and {requested / 'clause_index.json'}."
        )
    release_root = _release_root_for_repo_root(repo_root)
    if release_root is not None:
        required = release_root / "das-standard"
        raise SystemExit(
            "Could not locate das-standard indexes in the release package.\n"
            f"Required package-local standard root: {required}\n"
            "Pass --standard-root to use an explicit DAS Standard override."
        )
    raise SystemExit(
        "Could not locate das-standard indexes.\n"
        "Set DAS_STANDARD_ROOT or pass --standard-root to point at the das-standard repo."
    )


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_indexes(repo_root: Path, standard_root: str | None = None) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    resolved = resolve_standard_root(repo_root, standard_root)
    chapters = _load_json(resolved / "chapter_index.json")
    clauses = _load_json(resolved / "clause_index.json")
    return resolved, chapters, clauses


def _norm(value: str) -> str:
    return (value or "").strip().lower()


def search_indexes(
    repo_root: Path,
    *,
    query: str,
    standard_root: str | None = None,
) -> dict[str, Any]:
    _, chapters_index, clauses_index = load_indexes(repo_root, standard_root)
    q = _norm(query)
    if not q:
        raise SystemExit("--query is required")

    results: list[dict[str, Any]] = []
    for chapter in chapters_index.get("chapters", []):
        haystack = " ".join(
            [
                chapter.get("id", ""),
                chapter.get("title", ""),
                chapter.get("summary", ""),
                " ".join(chapter.get("roles", [])),
            ]
        ).lower()
        if q in haystack:
            results.append(
                {
                    "kind": "chapter",
                    "id": chapter.get("id", ""),
                    "title": chapter.get("title", ""),
                    "file": chapter.get("file", ""),
                    "summary": chapter.get("summary", ""),
                    "roles": chapter.get("roles", []),
                }
            )

    for clause in clauses_index.get("clauses", []):
        haystack = " ".join(
            [
                clause.get("id", ""),
                clause.get("chapter", ""),
                clause.get("title", ""),
                " ".join(clause.get("keywords", [])),
                " ".join(clause.get("gateLabels", [])),
            ]
        ).lower()
        if q in haystack:
            results.append(
                {
                    "kind": "clause",
                    "id": clause.get("id", ""),
                    "chapter": clause.get("chapter", ""),
                    "title": clause.get("title", ""),
                    "keywords": clause.get("keywords", []),
                    "gateLabels": clause.get("gateLabels", []),
                }
            )

    return {"query": query, "count": len(results), "results": results}


def show_clause(
    repo_root: Path,
    *,
    clause_id: str,
    standard_root: str | None = None,
) -> dict[str, Any]:
    _, chapters_index, clauses_index = load_indexes(repo_root, standard_root)
    wanted = _norm(clause_id)
    if not wanted:
        raise SystemExit("--clause is required")

    chapters_by_id = {
        chapter.get("id", ""): chapter
        for chapter in chapters_index.get("chapters", [])
    }
    for clause in clauses_index.get("clauses", []):
        if _norm(clause.get("id", "")) != wanted:
            continue
        chapter = chapters_by_id.get(clause.get("chapter", ""), {})
        return {
            "id": clause.get("id", ""),
            "chapter": clause.get("chapter", ""),
            "chapterTitle": chapter.get("title", ""),
            "chapterFile": chapter.get("file", ""),
            "title": clause.get("title", ""),
            "keywords": clause.get("keywords", []),
            "gateLabels": clause.get("gateLabels", []),
        }

    raise SystemExit(f"Unknown clause: {clause_id}")


def build_pack(
    repo_root: Path,
    *,
    role: str,
    standard_root: str | None = None,
) -> dict[str, Any]:
    _, chapters_index, clauses_index = load_indexes(repo_root, standard_root)
    pack_role = PACK_ROLE_ALIASES.get(_norm(role))
    if not pack_role:
        valid = ", ".join(sorted(PACK_ROLE_ALIASES))
        raise SystemExit(f"Unknown pack role: {role}. Valid values: {valid}")

    selected_chapters: list[dict[str, Any]] = []
    selected_ids: set[str] = set()
    for chapter in chapters_index.get("chapters", []):
        roles = {item.lower() for item in chapter.get("roles", [])}
        if pack_role == "all" or "all" in roles or pack_role in roles:
            selected_chapters.append(
                {
                    "id": chapter.get("id", ""),
                    "title": chapter.get("title", ""),
                    "file": chapter.get("file", ""),
                    "summary": chapter.get("summary", ""),
                    "roles": chapter.get("roles", []),
                }
            )
            selected_ids.add(chapter.get("id", ""))

    selected_clauses = [
        {
            "id": clause.get("id", ""),
            "chapter": clause.get("chapter", ""),
            "title": clause.get("title", ""),
            "keywords": clause.get("keywords", []),
            "gateLabels": clause.get("gateLabels", []),
        }
        for clause in clauses_index.get("clauses", [])
        if clause.get("chapter", "") in selected_ids
    ]

    return {
        "role": pack_role,
        "chapterCount": len(selected_chapters),
        "clauseCount": len(selected_clauses),
        "chapters": selected_chapters,
        "clauses": selected_clauses,
    }
