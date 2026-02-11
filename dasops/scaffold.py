from __future__ import annotations

import getpass
import os
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Optional, Dict, List, Tuple

import yaml

# -----------------------------
# Draft marker (mechanical)
# -----------------------------

# We use a simple marker in OpenSpec artifacts that are copied as templates.
# Until the marker is removed, `dasops status` treats the artifact as DRAFT
# (i.e., not DONE), so dependency gating remains meaningful.
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


# -----------------------------
# Schema & template scaffolding
# -----------------------------


def _read_schema(repo_root: Path) -> List[Artifact]:
    """Read a repo-local OpenSpec schema (das-standard).

    NOTE: This is intended to run inside a *product* repo.
    """
    schema_path = repo_root / "openspec" / "schemas" / "das-standard" / "schema.yaml"
    data = yaml.safe_load(schema_path.read_text(encoding="utf-8"))
    artifacts: List[Artifact] = []
    for a in data.get("artifacts", []):
        artifacts.append(
            Artifact(
                id=a["id"],
                generates=a["generates"],
                requires=list(a.get("requires", [])),
            )
        )
    return artifacts


def _factory_template_dir(factory_root: Path) -> Path:
    return factory_root / "templates" / "das-product"


def _chmod_executable(path: Path) -> None:
    try:
        st = path.stat()
        os.chmod(path, st.st_mode | 0o111)
    except Exception:
        # Best-effort. On some platforms/filesystems, chmod may not apply.
        pass


def _ensure_product_repo_permissions(repo_root: Path) -> None:
    """Best-effort: make verify scripts executable."""
    scripts = repo_root / "scripts"
    if not scripts.exists():
        return
    for f in scripts.iterdir():
        if f.is_file():
            _chmod_executable(f)

    # Optional helpers
    for extra in [repo_root / "cadencew"]:
        if extra.exists() and extra.is_file():
            _chmod_executable(extra)


def create_product_repo(
    *,
    factory_root: Path,
    dest_dir: Path,
    master_doc_path: Path,
    ui_spec_path: Path,
    change_id: Optional[str] = None,
    intent: str = "",
    init_git: bool = True,
    overwrite: bool = False,
    change_empty: bool = False,
) -> Path:
    """Create a NEW product repo by copying the factory template.

    This implements the recommended "physical isolation" approach:
    - Factory repo: tooling + GUI + template
    - Product repo: generated scaffold where agents actually build your software

    Parameters
    ----------
    factory_root:
        Path to the factory repo root (must contain templates/das-product).
    dest_dir:
        Output directory for the new product repo.
    master_doc_path, ui_spec_path:
        Source docs provided by the user.
    change_id:
        Optional initial change folder to create.
    intent:
        Optional intent for the initial change.
    init_git:
        If True, run `git init` (and an initial commit) in the new repo.
    overwrite:
        If False, refuse to write into a non-empty dest dir.
    change_empty:
        If True and change_id is provided, create an empty change folder (metadata + lock dir only).
        This is recommended when you plan to use OpenSpec OPSX to generate artifacts.

    Returns
    -------
    Path to the created product repo.
    """
    template_dir = _factory_template_dir(factory_root)
    if not template_dir.exists():
        raise SystemExit(
            "Factory template not found. Expected: "
            f"{template_dir}.\n\n"
            "If you installed dasops as a package, run this command from the cloned "
            "factory repo, or pass --factory-root explicitly."
        )

    dest_dir = dest_dir.expanduser().resolve()
    if dest_dir.exists() and any(dest_dir.iterdir()):
        if not overwrite:
            raise SystemExit(
                f"Destination directory is not empty: {dest_dir}\n"
                "Refusing to overwrite. Use --overwrite if you really want this."
            )
    else:
        dest_dir.mkdir(parents=True, exist_ok=True)

    # Copy template into destination.
    shutil.copytree(template_dir, dest_dir, dirs_exist_ok=True)

    # Copy docs in.
    init_repo(repo_root=dest_dir, master_doc_path=master_doc_path, ui_spec_path=ui_spec_path)

    # Optional initial change folder.
    if change_id:
        new_change(repo_root=dest_dir, change_id=change_id, intent=intent, empty=change_empty)

    # Helpful marker so tools/agents can detect "this is a product repo".
    marker = dest_dir / ".dasops_product_repo"
    if not marker.exists():
        marker.write_text(
            "This is a DAS + OpenSpec PRODUCT repo generated by dasops.\n"
            "Work here (run verify, implement tasks, etc.).\n",
            encoding="utf-8",
        )

    _ensure_product_repo_permissions(dest_dir)

    if init_git:
        _maybe_git_init(dest_dir)

    return dest_dir


def _maybe_git_init(repo_root: Path) -> None:
    """Best-effort git init + initial commit.

    Design goals:
    - Create a repo that interns can branch from immediately (must have an initial commit).
    - Prefer 'main' as the default branch.
    - Avoid failing just because global git user.name/email is not configured.
    """
    if (repo_root / ".git").exists():
        return

    def run(cmd: List[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            cmd,
            cwd=str(repo_root),
            check=check,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

    try:
        # Prefer main branch if supported.
        try:
            run(["git", "init", "-b", "main"], check=True)
        except Exception:
            run(["git", "init"], check=True)
            # Rename default branch to main (works even before the first commit).
            subprocess.run(
                ["git", "branch", "-m", "main"],
                cwd=str(repo_root),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )

        run(["git", "add", "-A"], check=True)

        # Commit with a local identity even if global git config is missing.
        # This ensures 'main' has a real commit so feature branches can be created from it.
        run(
            [
                "git",
                "-c",
                "user.name=dasops",
                "-c",
                "user.email=dasops@local",
                "commit",
                "-m",
                "chore: bootstrap DAS + OpenSpec scaffold",
            ],
            check=False,
        )
    except FileNotFoundError:
        # git isn't installed
        return
    except Exception:
        # Any other failure is non-fatal.
        return


def init_repo(
    repo_root: Path,
    master_doc_path: Optional[Path] = None,
    ui_spec_path: Optional[Path] = None,
    master_doc_bytes: Optional[bytes] = None,
    ui_spec_bytes: Optional[bytes] = None,
    change_id: Optional[str] = None,
    change_intent: Optional[str] = None,
) -> None:
    """Initialize repo docs, optionally create a change folder.

    Either provide *_path or *_bytes.

    NOTE: This is intended to run inside a *product* repo.
    """
    docs_dir = repo_root / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)

    if master_doc_path is not None:
        master_doc_bytes = master_doc_path.read_bytes()
    if ui_spec_path is not None:
        ui_spec_bytes = ui_spec_path.read_bytes()

    assert master_doc_bytes is not None, "master_doc missing"
    assert ui_spec_bytes is not None, "ui_spec missing"

    (docs_dir / "master_doc.md").write_bytes(master_doc_bytes)
    (docs_dir / "ui_spec.md").write_bytes(ui_spec_bytes)

    if change_id:
        new_change(repo_root=repo_root, change_id=change_id, intent=change_intent or "")


def new_change(repo_root: Path, change_id: str, intent: str = "", *, empty: bool = False) -> Path:
    """Create a new change folder.

    By default, this command copies the DAS-aligned artifact templates into the change folder
    (and those templates include a DRAFT marker).

    If empty=True, only creates metadata + lock dir (recommended when using OpenSpec OPSX to
    generate artifacts via /opsx:* commands).
    """
    change_dir = repo_root / "openspec" / "changes" / change_id
    change_dir.mkdir(parents=True, exist_ok=True)

    if not empty:
        tmpl_dir = repo_root / "openspec" / "schemas" / "das-standard" / "templates"
        mapping = {
            "master_doc_delta.md": "master_doc_delta.md",
            "contracts_plan.md": "contracts_plan.md",
            "verification_plan.md": "verification_plan.md",
            "tasks.md": "tasks.md",
        }
        for src_name, dst_name in mapping.items():
            src = tmpl_dir / src_name
            dst = change_dir / dst_name
            if not dst.exists():
                dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")

    meta = change_dir / "CHANGE.md"
    if not meta.exists():
        meta.write_text(f"# Change: {change_id}\n\nIntent: {intent}\n", encoding="utf-8")

    # OpenSpec per-change metadata (optional but recommended)
    ospec_meta = change_dir / ".openspec.yaml"
    if not ospec_meta.exists():
        ospec_meta.write_text(
            f"schema: das-standard\ncreated: {date.today().isoformat()}\n",
            encoding="utf-8",
        )

    # Task claim lock directory (prevents duplicate work across workers)
    lock_dir = change_dir / "task_locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    gitkeep = lock_dir / ".gitkeep"
    if not gitkeep.exists():
        gitkeep.write_text("", encoding="utf-8")

    return change_dir


# -----------------------------
# Task parsing helpers
# -----------------------------


def _task_locks_dir(change_dir: Path) -> Path:
    return change_dir / "task_locks"


def _read_lock(lock_path: Path) -> Dict[str, object]:
    if not lock_path.exists():
        return {}
    try:
        data = yaml.safe_load(lock_path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _parse_tasks_index(tasks_md: str) -> List[TaskRow]:
    """Parse the canonical Task index table.

    Expected column order:
      Task ID | Title | Owner | Status | Depends on | Verify gate

    Returns an empty list if no table is found.
    """
    lines = tasks_md.splitlines()
    header_idx = None
    for i, raw in enumerate(lines):
        s = raw.strip()
        if s.startswith("| Task ID") and "Owner" in s and "Status" in s:
            header_idx = i
            break
    if header_idx is None:
        return []

    rows: List[TaskRow] = []
    # Skip header + separator
    for raw in lines[header_idx + 2 :]:
        s = raw.strip()
        if not s.startswith("|"):
            break
        if re.match(r"^\|\s*-{3,}", s):
            continue
        parts = [p.strip() for p in s.strip("|").split("|")]
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


def _find_task_section(md_lines: List[str], task_id: str) -> Optional[Tuple[int, int]]:
    """Return (start_idx, end_idx) of a task section headed by '### <task_id>'"""
    start = None
    for i, line in enumerate(md_lines):
        if re.match(rf"^###\s+{re.escape(task_id)}\b", line):
            start = i
            break
    if start is None:
        return None

    end = len(md_lines)
    for j in range(start + 1, len(md_lines)):
        if re.match(r"^###\s+", md_lines[j]):
            end = j
            break
    return start, end


def _extract_task_branch(tasks_md: str, task_id: str) -> str:
    """Best-effort extraction of an expected branch name from the task detail section."""
    lines = tasks_md.splitlines(keepends=True)
    sec = _find_task_section(lines, task_id)
    if sec is None:
        return ""
    start, end = sec
    for i in range(start + 1, end):
        s = lines[i].strip()
        m = re.match(r"^-\s*Branch\s*:\s*(.*)$", s)
        if not m:
            continue
        rest = m.group(1).strip()
        m2 = re.search(r"`([^`]+)`", rest)
        if m2:
            return m2.group(1).strip()
        return rest
    return ""


def _extract_task_verify_cmds(tasks_md: str, task_id: str) -> List[str]:
    """Best-effort extraction of verify commands for a task."""
    lines = tasks_md.splitlines(keepends=True)
    sec = _find_task_section(lines, task_id)
    if sec is None:
        return []
    start, end = sec

    verify_cmds: List[str] = []
    in_verification = False

    for i in range(start + 1, end):
        raw = lines[i]
        s = raw.strip()

        if re.match(r"^-\s*Verification\s*:\s*$", s) or re.match(r"^-\s*Verification\s*:\s+.*$", s):
            in_verification = True
            for cmd in re.findall(r"`([^`]+)`", raw):
                if "verify" in cmd:
                    verify_cmds.append(cmd.strip())
            continue

        if in_verification:
            if raw.startswith("- ") and not re.match(r"^-\s*`", raw):
                break
            for cmd in re.findall(r"`([^`]+)`", raw):
                if "verify" in cmd:
                    verify_cmds.append(cmd.strip())

    # De-duplicate while preserving order
    seen: set[str] = set()
    out: List[str] = []
    for c in verify_cmds:
        if c in seen:
            continue
        seen.add(c)
        out.append(c)
    return out


def _is_unassigned_owner(value: str) -> bool:
    v = (value or "").strip()
    if v == "" or v == "-" or v.lower() in {"tbd", "unassigned", "none"}:
        return True
    if v.startswith("<") and v.endswith(">"):
        return True
    return False


def _extract_task_owner_status(tasks_md: str, task_id: str) -> Tuple[str, str]:
    """Best-effort extraction of current (Owner, Status) from tasks.md."""
    owner = ""
    status = ""

    # 1) Try the Task index table
    for row in _parse_tasks_index(tasks_md):
        if row.task_id == task_id:
            return row.owner, row.status

    # 2) Try the detail section bullets
    lines = tasks_md.splitlines(keepends=True)
    sec = _find_task_section(lines, task_id)
    if sec is None:
        return owner, status
    start, end = sec
    for i in range(start + 1, end):
        s = lines[i].strip()
        m = re.match(r"^-\s*Owner\s*:\s*(.*)$", s)
        if m:
            owner = m.group(1).strip()
        m = re.match(r"^-\s*Status\s*:\s*(.*)$", s)
        if m:
            status = m.group(1).strip()

    return owner, status


def read_task_hints(*, repo_root: Path, change_id: str, task_id: str) -> Dict[str, object]:
    """Read tasks.md and extract hints for a specific task.

    Returns a dict with keys:
      owner, status, branch, verify_cmds, tasks_path

    NOTE: Best-effort. Missing fields return empty values.
    """
    change_dir = repo_root / "openspec" / "changes" / change_id
    tasks_path = change_dir / "tasks.md"
    if not tasks_path.exists():
        raise SystemExit(f"tasks.md not found: {tasks_path}")

    tasks_md = tasks_path.read_text(encoding="utf-8")
    owner, status = _extract_task_owner_status(tasks_md, task_id)
    branch = _extract_task_branch(tasks_md, task_id)
    verify_cmds = _extract_task_verify_cmds(tasks_md, task_id)

    return {
        "owner": owner,
        "status": status,
        "branch": branch,
        "verify_cmds": verify_cmds,
        "tasks_path": tasks_path,
    }


# -----------------------------
# Task mutation helpers
# -----------------------------


def _update_task_index_table(md_lines: List[str], task_id: str, owner: str, status: str) -> bool:
    """Update the 'Task index' markdown table if present."""
    in_table = False
    for i, line in enumerate(md_lines):
        s = line.strip()
        if s.startswith("| Task ID") and "Owner" in s and "Status" in s:
            in_table = True
            continue

        if in_table:
            # end of table
            if not s.startswith("|") or s == "|":
                in_table = False
                continue
            # skip separator rows
            if re.match(r"^\|\s*-{3,}", s):
                continue

            if re.match(rf"^\|\s*{re.escape(task_id)}\s*\|", s):
                parts = [p.strip() for p in s.strip("|").split("|")]
                # Expected columns: Task ID | Title | Owner | Status | Depends on | Verify gate
                while len(parts) < 6:
                    parts.append("-")
                parts[2] = owner
                parts[3] = status
                md_lines[i] = "| " + " | ".join(parts) + " |\n"
                return True

    return False


def _update_task_details_section(md_lines: List[str], task_id: str, owner: str, status: str) -> bool:
    """Update Owner/Status bullets inside the task detail section if present."""
    sec = _find_task_section(md_lines, task_id)
    if sec is None:
        return False
    start, end = sec

    owner_found = False
    status_found = False
    changed = False

    for i in range(start + 1, end):
        s = md_lines[i].lstrip()
        if re.match(r"^-\s*Owner\s*:", s):
            md_lines[i] = f"- Owner: {owner}\n"
            owner_found = True
            changed = True
        if re.match(r"^-\s*Status\s*:", s):
            md_lines[i] = f"- Status: {status}\n"
            status_found = True
            changed = True

    # Insert missing bullets right after the heading (and any blank lines)
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


def _update_tasks_md(tasks_md: str, task_id: str, owner: str, status: str) -> Tuple[str, bool]:
    """Update tasks.md with new owner/status.

    Supports both the canonical table+details template and a details-only format.
    """
    lines = tasks_md.splitlines(keepends=True)
    changed_table = _update_task_index_table(lines, task_id, owner, status)
    changed_details = _update_task_details_section(lines, task_id, owner, status)
    changed = changed_table or changed_details
    return "".join(lines), changed


def claim_task(
    *,
    repo_root: Path,
    change_id: str,
    task_id: str,
    owner: str,
    status: str = "IN_PROGRESS",
    force: bool = False,
) -> Path:
    """Claim a task by (1) updating tasks.md owner/status and (2) writing a lock file.

    Lock file location:
      openspec/changes/<change-id>/task_locks/<task-id>.lock

    The lock is intended to reduce duplicate work across multiple workers.
    """
    change_dir = repo_root / "openspec" / "changes" / change_id
    if not change_dir.exists():
        raise SystemExit(f"Change folder not found: {change_dir}")

    tasks_path = change_dir / "tasks.md"
    if not tasks_path.exists():
        raise SystemExit(f"tasks.md not found: {tasks_path}")

    lock_dir = _task_locks_dir(change_dir)
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_path = lock_dir / f"{task_id}.lock"

    tasks_md = tasks_path.read_text(encoding="utf-8")
    current_owner, _current_status = _extract_task_owner_status(tasks_md, task_id)

    # If Orchestrator already assigned an owner, workers must not override it.
    if current_owner and not _is_unassigned_owner(current_owner) and current_owner != owner and not force:
        raise SystemExit(
            f"Task {task_id} owner mismatch.\n"
            f"- tasks.md owner: '{current_owner}'\n"
            f"- you requested:  '{owner}'\n"
            "Refusing to claim. Ask Orchestrator to re-assign, or re-run with --force (Orchestrator only)."
        )

    lock_existed = lock_path.exists()
    existing_lock = _read_lock(lock_path)
    existing_lock_owner = str(existing_lock.get("owner", "")).strip() if isinstance(existing_lock, dict) else ""

    # If lock exists and is owned by someone else, refuse (unless forced).
    if lock_existed and existing_lock_owner and existing_lock_owner != owner and not force:
        raise SystemExit(
            f"Task {task_id} is already claimed by '{existing_lock_owner}'.\n"
            f"Lock file: {lock_path}\n"
            "If this is a mistake, ask the Orchestrator to re-assign, or re-run with --force."
        )

    now = datetime.now(timezone.utc).isoformat()
    claimed_at = (
        str(existing_lock.get("claimedAt")).strip()
        if isinstance(existing_lock, dict) and existing_lock.get("claimedAt")
        else now
    )

    payload = {
        "version": 1,
        "changeId": change_id,
        "taskId": task_id,
        "owner": owner,
        "status": status,
        "claimedAt": claimed_at,
        "updatedAt": now,
        "host": socket.gethostname(),
        "user": getpass.getuser(),
        "pid": os.getpid(),
    }
    lock_text = yaml.safe_dump(payload, sort_keys=False)

    created_new_lock = False

    # Acquire the lock first (atomic create) to reduce race windows.
    if not lock_existed:
        try:
            with lock_path.open("x", encoding="utf-8") as f:
                f.write(lock_text)
            created_new_lock = True
            lock_existed = True
        except FileExistsError:
            # Race: someone else created it. Re-check ownership.
            existing_lock = _read_lock(lock_path)
            existing_lock_owner = str(existing_lock.get("owner", "")).strip() if isinstance(existing_lock, dict) else ""
            if existing_lock_owner and existing_lock_owner != owner and not force:
                raise SystemExit(
                    f"Task {task_id} was claimed concurrently by '{existing_lock_owner}'.\n"
                    f"Lock file: {lock_path}"
                )
            lock_existed = True

    # Update tasks.md only after lock is acquired.
    updated, changed = _update_tasks_md(tasks_md, task_id, owner, status)
    if not changed:
        # Roll back a new lock if the task doesn't exist (best-effort).
        if created_new_lock:
            try:
                lock_path.unlink()
            except Exception:
                pass
        raise SystemExit(
            f"Task ID '{task_id}' not found in {tasks_path}.\n"
            "Refusing to claim. Orchestrator should add the task first."
        )

    tasks_path.write_text(updated, encoding="utf-8")

    # Refresh lock content (ensure it reflects latest status / timestamps).
    # Overwrite is allowed if we own it, or if --force is set.
    if lock_existed:
        if existing_lock_owner and existing_lock_owner != owner and not force:
            raise SystemExit(f"Refusing to overwrite existing lock owned by {existing_lock_owner}: {lock_path}")
        lock_path.write_text(lock_text, encoding="utf-8")

    return lock_path


def complete_task(
    *,
    repo_root: Path,
    change_id: str,
    task_id: str,
    owner: str,
    force: bool = False,
) -> Path:
    """Mark a task as DONE (updates tasks.md + lock file)."""
    return claim_task(
        repo_root=repo_root,
        change_id=change_id,
        task_id=task_id,
        owner=owner,
        status="DONE",
        force=force,
    )


def release_task(
    *,
    repo_root: Path,
    change_id: str,
    task_id: str,
    owner: str,
    status: str = "TODO",
    clear_owner: bool = False,
    force: bool = False,
) -> Path:
    """Release (unclaim) a task.

    Behavior:
    - Removes the lock file.
    - Updates tasks.md status to the provided value (default TODO).
    - Optionally clears Owner (sets to '-') if clear_owner=True.

    Safety:
    - If the lock exists and is owned by someone else, refuses unless --force.
    """
    change_dir = repo_root / "openspec" / "changes" / change_id
    if not change_dir.exists():
        raise SystemExit(f"Change folder not found: {change_dir}")

    tasks_path = change_dir / "tasks.md"
    if not tasks_path.exists():
        raise SystemExit(f"tasks.md not found: {tasks_path}")

    lock_path = _task_locks_dir(change_dir) / f"{task_id}.lock"
    if not lock_path.exists():
        raise SystemExit(f"Lock not found (task is not claimed): {lock_path}")

    existing_lock = _read_lock(lock_path)
    existing_lock_owner = str(existing_lock.get("owner", "")).strip() if isinstance(existing_lock, dict) else ""

    if existing_lock_owner and existing_lock_owner != owner and not force:
        raise SystemExit(
            f"Refusing to release {task_id}: lock is owned by '{existing_lock_owner}', not '{owner}'.\n"
            f"Lock file: {lock_path}\n"
            "Use --force only if you are the Orchestrator and you intend to re-assign."
        )

    tasks_md = tasks_path.read_text(encoding="utf-8")
    current_owner, _current_status = _extract_task_owner_status(tasks_md, task_id)

    desired_owner = "-" if clear_owner else (current_owner if current_owner else owner)

    updated, changed = _update_tasks_md(tasks_md, task_id, desired_owner, status)
    if not changed:
        raise SystemExit(f"Task ID '{task_id}' not found in {tasks_path}.")

    tasks_path.write_text(updated, encoding="utf-8")

    try:
        lock_path.unlink()
    except Exception as e:
        raise SystemExit(f"Failed to remove lock file: {lock_path}\n{e}")

    return lock_path


def list_tasks(*, repo_root: Path, change_id: str) -> List[Dict[str, object]]:
    """Return a list of tasks enriched with lock + detail hints."""
    change_dir = repo_root / "openspec" / "changes" / change_id
    tasks_path = change_dir / "tasks.md"
    if not tasks_path.exists():
        raise SystemExit(f"tasks.md not found: {tasks_path}")

    tasks_md = tasks_path.read_text(encoding="utf-8")
    rows = _parse_tasks_index(tasks_md)

    out: List[Dict[str, object]] = []
    for r in rows:
        lock_path = _task_locks_dir(change_dir) / f"{r.task_id}.lock"
        lock = _read_lock(lock_path)
        verify_cmds = _extract_task_verify_cmds(tasks_md, r.task_id)
        branch = _extract_task_branch(tasks_md, r.task_id)

        out.append(
            {
                "taskId": r.task_id,
                "title": r.title,
                "owner": r.owner,
                "status": r.status,
                "dependsOn": r.depends_on,
                "verifyGate": r.verify_gate,
                "branch": branch,
                "verifyCmds": verify_cmds,
                "lock": {
                    "exists": lock_path.exists(),
                    "path": str(lock_path),
                    "owner": str(lock.get("owner", "")) if lock else "",
                    "status": str(lock.get("status", "")) if lock else "",
                    "claimedAt": str(lock.get("claimedAt", "")) if lock else "",
                    "updatedAt": str(lock.get("updatedAt", "")) if lock else "",
                },
            }
        )

    return out


# -----------------------------
# Pull-based dispatch (workers claim ready tasks)
# -----------------------------


def _split_deps(depends_on: str) -> List[str]:
    """Parse a Depends-on cell into task IDs.

    Accepts: '-', '', comma-separated, whitespace-separated.
    """
    s = (depends_on or "").strip()
    if not s or s == "-":
        return []
    # common separators
    raw = re.split(r"[\s,]+", s)
    return [t.strip() for t in raw if t.strip()]


def _index_rows_by_id(rows: List[TaskRow]) -> Dict[str, TaskRow]:
    return {r.task_id: r for r in rows}


def claim_ready_task(
    *,
    repo_root: Path,
    change_id: str,
    owner: str,
    status: str = "IN_PROGRESS",
    allow_preassigned: bool = False,
) -> Optional[Path]:
    """Claim the next ready task (pull model).

    A task is considered "ready" if:
    - status is TODO
    - no lock exists
    - owner is unassigned (unless allow_preassigned=True)
    - all dependencies (Depends on) are DONE

    Returns the created/updated lock path, or None if nothing is ready.
    """
    change_dir = repo_root / "openspec" / "changes" / change_id
    tasks_path = change_dir / "tasks.md"
    if not tasks_path.exists():
        raise SystemExit(f"tasks.md not found: {tasks_path}")

    tasks_md = tasks_path.read_text(encoding="utf-8")
    rows = _parse_tasks_index(tasks_md)
    by_id = _index_rows_by_id(rows)

    # Iterate deterministically by task id order.
    for r in rows:
        if (r.status or "").strip().upper() != "TODO":
            continue

        if not allow_preassigned and r.owner and not _is_unassigned_owner(r.owner):
            continue

        lock_path = _task_locks_dir(change_dir) / f"{r.task_id}.lock"
        if lock_path.exists():
            continue

        deps = _split_deps(r.depends_on)
        blocked = False
        for dep in deps:
            dep_row = by_id.get(dep)
            if not dep_row:
                # Unknown dep => treat as blocked (Orchestrator typo).
                blocked = True
                break
            if (dep_row.status or "").strip().upper() != "DONE":
                blocked = True
                break
        if blocked:
            continue

        # Try to claim. If a race happens, claim_task will raise; keep scanning.
        try:
            return claim_task(
                repo_root=repo_root,
                change_id=change_id,
                task_id=r.task_id,
                owner=owner,
                status=status,
                force=False,
            )
        except SystemExit:
            continue

    return None


# -----------------------------
# Artifact status (OPSX-like)
# -----------------------------


def _file_is_draft(path: Path) -> bool:
    """Best-effort draft detection.

    Primary signal: the DRAFT marker line.

    Secondary signals (legacy/backstop): common placeholders like `<change-id>`.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return True

    if DRAFT_MARKER in text:
        return True

    # Backstop for older templates (or users who forgot to add the marker).
    if re.search(r"<[^>]+>", text):
        return True

    return False


def _artifact_status(change_dir: Path, artifacts: List[Artifact]) -> Dict[str, str]:
    """Compute BLOCKED/READY/DONE based on file existence + dependencies.

    DONE means: artifact file exists AND is not considered a DRAFT.
    """
    by_id = {a.id: a for a in artifacts}

    def is_done(a: Artifact) -> bool:
        p = change_dir / a.generates
        return p.exists() and not _file_is_draft(p)

    status: Dict[str, str] = {}

    # simple fixed-point compute
    for _ in range(10):
        changed = False
        for a in artifacts:
            prev = status.get(a.id)
            if is_done(a):
                cur = "DONE"
            else:
                deps = a.requires
                if all(status.get(d) == "DONE" or is_done(by_id[d]) for d in deps):
                    cur = "READY"
                else:
                    cur = "BLOCKED"
            if prev != cur:
                status[a.id] = cur
                changed = True
        if not changed:
            break
    return status


def print_status(repo_root: Path, change_id: str) -> None:
    artifacts = _read_schema(repo_root)
    change_dir = repo_root / "openspec" / "changes" / change_id
    if not change_dir.exists():
        raise SystemExit(f"Change folder not found: {change_dir}")

    status = _artifact_status(change_dir, artifacts)

    print(f"Change: {change_id}\n")
    for a in artifacts:
        path = change_dir / a.generates
        tag = ""
        if path.exists() and _file_is_draft(path):
            tag = " (draft)"
        print(f"- {a.id:16s}  {status[a.id]:7s}{tag}  ({a.generates})")
