from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml


DRAFT_MARKER = "DASOPS:DRAFT"
DRAFT_MARKER_LINE = "<!-- DASOPS:DRAFT: remove this line when complete -->"


@dataclass(frozen=True)
class Artifact:
    id: str
    generates: str
    requires: List[str]


@dataclass(frozen=True)
class TaskRow:
    task_id: str
    title: str
    owner: str
    status: str
    depends_on: str
    verify_gate: str


def read_schema(repo_root: Path) -> List[Artifact]:
    schema_path = repo_root / "openspec" / "schemas" / "das-standard" / "schema.yaml"
    if not schema_path.exists():
        schema_path = (
            Path(__file__).resolve().parents[1]
            / "templates"
            / "das-product"
            / "openspec"
            / "schemas"
            / "das-standard"
            / "schema.yaml"
        )
    data = yaml.safe_load(schema_path.read_text(encoding="utf-8"))
    artifacts: List[Artifact] = []
    for entry in data.get("artifacts", []):
        artifacts.append(
            Artifact(
                id=entry["id"],
                generates=entry["generates"],
                requires=list(entry.get("requires", [])),
            )
        )
    return artifacts


def parse_tasks_index(tasks_md: str) -> List[TaskRow]:
    lines = tasks_md.splitlines()
    header_idx = None
    for index, raw in enumerate(lines):
        stripped = raw.strip()
        if stripped.startswith("| Task ID") and "Owner" in stripped and "Status" in stripped:
            header_idx = index
            break
    if header_idx is None:
        return []

    rows: List[TaskRow] = []
    for raw in lines[header_idx + 2 :]:
        stripped = raw.strip()
        if not stripped.startswith("|"):
            break
        if re.match(r"^\|\s*-{3,}", stripped):
            continue
        parts = [part.strip() for part in stripped.strip("|").split("|")]
        while len(parts) < 6:
            parts.append("")
        task_id, title, owner, status, depends_on, verify_gate = parts[:6]
        if not task_id:
            continue
        rows.append(
            TaskRow(
                task_id=task_id,
                title=title,
                owner=owner,
                status=status,
                depends_on=depends_on,
                verify_gate=verify_gate,
            )
        )
    return rows


def find_task_section(md_lines: List[str], task_id: str) -> Optional[Tuple[int, int]]:
    start = None
    for index, line in enumerate(md_lines):
        if re.match(rf"^###\s+{re.escape(task_id)}\b", line):
            start = index
            break
    if start is None:
        return None

    end = len(md_lines)
    for index in range(start + 1, len(md_lines)):
        if re.match(r"^###\s+", md_lines[index]):
            end = index
            break
    return start, end


def extract_task_branch(tasks_md: str, task_id: str) -> str:
    lines = tasks_md.splitlines(keepends=True)
    section = find_task_section(lines, task_id)
    if section is None:
        return ""
    start, end = section
    for index in range(start + 1, end):
        stripped = lines[index].strip()
        match = re.match(r"^-\s*Branch\s*:\s*(.*)$", stripped)
        if not match:
            continue
        rest = match.group(1).strip()
        quoted = re.search(r"`([^`]+)`", rest)
        if quoted:
            return quoted.group(1).strip()
        return rest
    return ""


def extract_task_verify_cmds(tasks_md: str, task_id: str) -> List[str]:
    lines = tasks_md.splitlines(keepends=True)
    section = find_task_section(lines, task_id)
    if section is None:
        return []
    start, end = section

    verify_cmds: List[str] = []
    in_verification = False
    for index in range(start + 1, end):
        raw = lines[index]
        stripped = raw.strip()

        if re.match(r"^-\s*Verification\s*:\s*$", stripped) or re.match(
            r"^-\s*Verification\s*:\s+.*$",
            stripped,
        ):
            in_verification = True
            for command in re.findall(r"`([^`]+)`", raw):
                if "verify" in command:
                    verify_cmds.append(command.strip())
            continue

        if in_verification:
            if raw.startswith("- ") and not re.match(r"^-\s*`", raw):
                break
            for command in re.findall(r"`([^`]+)`", raw):
                if "verify" in command:
                    verify_cmds.append(command.strip())

    out: List[str] = []
    seen: set[str] = set()
    for command in verify_cmds:
        if command in seen:
            continue
        seen.add(command)
        out.append(command)
    return out


def is_unassigned_owner(value: str) -> bool:
    normalized = (value or "").strip()
    if normalized in {"", "-"}:
        return True
    if normalized.lower() in {"tbd", "unassigned", "none"}:
        return True
    return normalized.startswith("<") and normalized.endswith(">")


def extract_task_owner_status(tasks_md: str, task_id: str) -> Tuple[str, str]:
    for row in parse_tasks_index(tasks_md):
        if row.task_id == task_id:
            return row.owner, row.status

    owner = ""
    status = ""
    lines = tasks_md.splitlines(keepends=True)
    section = find_task_section(lines, task_id)
    if section is None:
        return owner, status
    start, end = section
    for index in range(start + 1, end):
        stripped = lines[index].strip()
        owner_match = re.match(r"^-\s*Owner\s*:\s*(.*)$", stripped)
        if owner_match:
            owner = owner_match.group(1).strip()
        status_match = re.match(r"^-\s*Status\s*:\s*(.*)$", stripped)
        if status_match:
            status = status_match.group(1).strip()
    return owner, status


def read_task_hints(*, repo_root: Path, change_id: str, task_id: str) -> Dict[str, object]:
    # Local imports avoid the tasks/locks import cycle. Worker startup shares
    # the same pending check and snapshot boundary as inspect/list.
    from .legacy_task_state import guard
    from .locks import _change, _snapshot

    change_dir = _change(repo_root, change_id, task_id)
    with guard(change_dir):
        tasks_md, _, _ = _snapshot(change_dir)
        return task_hints_from_text(tasks_md, change_dir / "tasks.md", task_id)


def task_hints_from_text(tasks_md: str, tasks_path: Path, task_id: str) -> Dict[str, object]:
    owner, status = extract_task_owner_status(tasks_md, task_id)
    return {
        "owner": owner,
        "status": status,
        "branch": extract_task_branch(tasks_md, task_id),
        "verify_cmds": extract_task_verify_cmds(tasks_md, task_id),
        "tasks_path": tasks_path,
    }


def update_task_index_table(md_lines: List[str], task_id: str, owner: str, status: str) -> bool:
    in_table = False
    for index, line in enumerate(md_lines):
        stripped = line.strip()
        if stripped.startswith("| Task ID") and "Owner" in stripped and "Status" in stripped:
            in_table = True
            continue
        if in_table:
            if not stripped.startswith("|") or stripped == "|":
                in_table = False
                continue
            if re.match(r"^\|\s*-{3,}", stripped):
                continue
            if re.match(rf"^\|\s*{re.escape(task_id)}\s*\|", stripped):
                parts = [part.strip() for part in stripped.strip("|").split("|")]
                while len(parts) < 6:
                    parts.append("-")
                parts[2] = owner
                parts[3] = status
                md_lines[index] = "| " + " | ".join(parts) + " |\n"
                return True
    return False


def update_task_details_section(md_lines: List[str], task_id: str, owner: str, status: str) -> bool:
    section = find_task_section(md_lines, task_id)
    if section is None:
        return False
    start, end = section

    owner_found = False
    status_found = False
    changed = False

    for index in range(start + 1, end):
        stripped = md_lines[index].lstrip()
        if re.match(r"^-\s*Owner\s*:", stripped):
            md_lines[index] = f"- Owner: {owner}\n"
            owner_found = True
            changed = True
        if re.match(r"^-\s*Status\s*:", stripped):
            md_lines[index] = f"- Status: {status}\n"
            status_found = True
            changed = True

    insert_pos = start + 1
    while insert_pos < len(md_lines) and md_lines[insert_pos].strip() == "":
        insert_pos += 1

    inserts: List[str] = []
    if not owner_found:
        inserts.append(f"- Owner: {owner}\n")
    if not status_found:
        inserts.append(f"- Status: {status}\n")
    if inserts:
        md_lines[insert_pos:insert_pos] = inserts
        changed = True
    return changed


def update_tasks_md_text(tasks_md: str, task_id: str, owner: str, status: str) -> Tuple[str, bool]:
    lines = tasks_md.splitlines(keepends=True)
    changed = update_task_index_table(lines, task_id, owner, status)
    changed |= update_task_details_section(lines, task_id, owner, status)
    return "".join(lines), changed


def split_deps(depends_on: str) -> List[str]:
    normalized = (depends_on or "").strip()
    if not normalized or normalized == "-":
        return []
    return [token.strip() for token in re.split(r"[\s,]+", normalized) if token.strip()]


def index_rows_by_id(rows: List[TaskRow]) -> Dict[str, TaskRow]:
    return {row.task_id: row for row in rows}


def list_tasks(
    *,
    repo_root: Path,
    change_id: str,
    lock_reader,
    lock_path_for,
) -> List[Dict[str, object]]:
    change_dir = repo_root / "openspec" / "changes" / change_id
    tasks_path = change_dir / "tasks.md"
    if not tasks_path.exists():
        raise SystemExit(f"tasks.md not found: {tasks_path}")

    tasks_md = tasks_path.read_text(encoding="utf-8")
    rows = parse_tasks_index(tasks_md)
    out: List[Dict[str, object]] = []
    for row in rows:
        lock_path = lock_path_for(change_dir, row.task_id)
        lock_record = lock_reader(lock_path)
        out.append(
            {
                "taskId": row.task_id,
                "title": row.title,
                "owner": row.owner,
                "status": row.status,
                "dependsOn": row.depends_on,
                "verifyGate": row.verify_gate,
                "branch": extract_task_branch(tasks_md, row.task_id),
                "verifyCmds": extract_task_verify_cmds(tasks_md, row.task_id),
                "lock": {
                    "exists": lock_record is not None,
                    "path": str(lock_path),
                    "owner": lock_record.owner if lock_record else "",
                    "status": lock_record.status if lock_record else "",
                    "claimedAt": lock_record.claimed_at if lock_record else "",
                    "updatedAt": lock_record.updated_at if lock_record else "",
                    "heartbeatAt": lock_record.heartbeat_at if lock_record else "",
                    "leaseSeconds": lock_record.lease_seconds if lock_record else 0,
                },
            }
        )
    return out


def file_is_draft(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return True

    return _text_is_draft(text)


def _text_is_draft(text: str) -> bool:
    if DRAFT_MARKER in text:
        return True
    visible_text = re.sub(r"```.*?```", "", text, flags=re.S)
    visible_text = re.sub(r"`[^`\n]*`", "", visible_text)
    return re.search(r"<[^>]+>", visible_text) is not None


def _read_status_snapshot(change_dir: Path, artifacts=()):
    # locks imports this module: keep coordination imports local.
    from . import legacy_task_state as state
    from .locks import _snapshot

    with state.guard(change_dir):
        if os.path.lexists(change_dir / "tasks.md"):
            text, by_id, _ = _snapshot(change_dir)
            rows = list(by_id.values())
        else:
            lock_dir = change_dir / "task_locks"
            if lock_dir.is_symlink() or (lock_dir.exists() and
                    (not lock_dir.is_dir() or any(lock_dir.glob("*.lock")))):
                raise state.StateError("missing_tasks_with_locks")
            text, rows = None, []
        texts = {"tasks.md": text}
        for artifact in artifacts:
            if artifact.generates not in texts:
                raw = state.read_bytes(change_dir / artifact.generates)
                texts[artifact.generates] = raw.decode("utf-8", errors="replace") if raw is not None else None
    return texts, rows


def task_index_is_complete(path: Path) -> bool:
    if path.name != "tasks.md":
        raise ValueError("task completeness requires the managed tasks.md index")
    _, rows = _read_status_snapshot(path.parent)
    return bool(rows) and all(row.status == "DONE" for row in rows)


def artifact_status(change_dir: Path, artifacts: List[Artifact]) -> Dict[str, str]:
    return _artifact_status_from_snapshot(artifacts, *_read_status_snapshot(change_dir, artifacts))


def _artifact_status_from_snapshot(artifacts, texts, rows):
    by_id = {artifact.id: artifact for artifact in artifacts}

    def is_done(artifact: Artifact) -> bool:
        text = texts[artifact.generates]
        if text is None or _text_is_draft(text):
            return False
        if artifact.generates == "tasks.md":
            return bool(rows) and all(row.status == "DONE" for row in rows)
        return True

    status: Dict[str, str] = {}
    for _ in range(10):
        changed = False
        for artifact in artifacts:
            previous = status.get(artifact.id)
            if is_done(artifact):
                current = "DONE"
            elif artifact.generates == "tasks.md" and texts[artifact.generates] is not None:
                current = "BLOCKED"
            elif all(status.get(dep) == "DONE" or is_done(by_id[dep]) for dep in artifact.requires):
                current = "READY"
            else:
                current = "BLOCKED"
            if previous != current:
                status[artifact.id] = current
                changed = True
        if not changed:
            break
    return status


def print_status(repo_root: Path, change_id: str) -> None:
    artifacts = read_schema(repo_root)
    change_dir = repo_root / "openspec" / "changes" / change_id
    if not change_dir.exists():
        raise SystemExit(f"Change folder not found: {change_dir}")

    texts, rows = _read_status_snapshot(change_dir, artifacts)
    status = _artifact_status_from_snapshot(artifacts, texts, rows)
    print(f"Change: {change_id}\n")
    for artifact in artifacts:
        text = texts[artifact.generates]
        tag = " (draft)" if text is not None and _text_is_draft(text) else ""
        print(f"- {artifact.id:16s}  {status[artifact.id]:7s}{tag}  ({artifact.generates})")
