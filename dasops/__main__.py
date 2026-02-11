import argparse
import json
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path

import yaml

from .scaffold import (
    claim_ready_task,
    claim_task,
    complete_task,
    create_product_repo,
    init_repo,
    list_tasks,
    new_change,
    print_status,
    read_task_hints,
    release_task,
)


def _render_prompt(template: str, mapping: dict[str, str]) -> str:
    out = template
    for k, v in mapping.items():
        out = out.replace(f"{{{{{k}}}}}", v)
    return out


def _run(cmd: list[str], cwd: Path) -> tuple[int, str]:
    """Run a command and capture combined stdout/stderr.

    Returns (returncode, output).
    """
    try:
        p = subprocess.run(
            cmd,
            cwd=str(cwd),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        return p.returncode, (p.stdout or "").strip()
    except FileNotFoundError:
        return 127, ""


def _is_git_repo(repo_root: Path) -> bool:
    rc, out = _run(["git", "rev-parse", "--is-inside-work-tree"], cwd=repo_root)
    return rc == 0 and out.strip().lower() == "true"


def _git_current_branch(repo_root: Path) -> str:
    rc, out = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_root)
    return out.strip() if rc == 0 else ""

def _resolve_repo_root(cwd: Path) -> Path:
    """Resolve a repo root for file-based commands.

    If `cwd` is inside a git worktree, this returns the git top-level folder.
    If not, it returns `cwd` unchanged.
    """
    rc, out = _run(["git", "rev-parse", "--show-toplevel"], cwd=cwd)
    if rc == 0 and out.strip():
        try:
            return Path(out.strip()).expanduser().resolve()
        except Exception:
            pass
    return cwd



def _git_has_branch(repo_root: Path, name: str) -> bool:
    rc, _out = _run(["git", "show-ref", "--verify", f"refs/heads/{name}"], cwd=repo_root)
    return rc == 0


def _git_worktree_clean(repo_root: Path) -> bool:
    rc, out = _run(["git", "status", "--porcelain"], cwd=repo_root)
    return rc == 0 and out.strip() == ""


def _normalize_owner(value: str) -> str:
    v = (value or "").strip()
    # Replace whitespace and unsafe chars with '-'
    v = re.sub(r"[^a-zA-Z0-9._-]+", "-", v)
    v = re.sub(r"-+", "-", v).strip("-")
    return v


def _default_owner(repo_root: Path) -> str:
    env = (os.getenv("DASOPS_OWNER") or "").strip()
    if env:
        return _normalize_owner(env)

    # Try git config user.name for a friendlier default.
    rc, name = _run(["git", "config", "user.name"], cwd=repo_root)
    if rc == 0 and name:
        norm = _normalize_owner(name)
        if norm:
            return norm

    # Fallback: OS username
    try:
        import getpass

        return _normalize_owner(getpass.getuser())
    except Exception:
        return "unknown"


def _is_placeholder(value: str) -> bool:
    v = (value or "").strip()
    if not v:
        return True
    if "<" in v and ">" in v:
        return True
    if "..." in v:
        return True
    if v.lower() in {"tbd", "todo", "-"}:
        return True
    return False


def _slugify(value: str) -> str:
    v = (value or "").strip().lower()
    v = re.sub(r"[^a-z0-9]+", "-", v)
    v = re.sub(r"-+", "-", v).strip("-")
    return v


def _make_change_id(intent: str) -> str:
    slug = _slugify(intent)
    slug = slug[:40] if slug else "change"
    ts = datetime.now().strftime("%Y%m%d-%H%M")
    return f"chg-{ts}-{slug}"


def _pick_base_branch(repo_root: Path) -> str:
    # Prefer main, then master, then current.
    if _git_has_branch(repo_root, "main"):
        return "main"
    if _git_has_branch(repo_root, "master"):
        return "master"
    cur = _git_current_branch(repo_root)
    return cur or "main"


def _fmt_rel(repo_root: Path, p: Path) -> str:
    try:
        return str(p.relative_to(repo_root))
    except Exception:
        return str(p)


def _print_task_table(tasks: list[dict[str, object]]) -> None:
    # Simple aligned table for terminal.
    headers = ["Task", "Owner", "Status", "Lock", "Title"]
    rows: list[list[str]] = []
    for t in tasks:
        lock = t.get("lock") or {}
        lock_owner = str(lock.get("owner", "")) if isinstance(lock, dict) else ""
        lock_exists = bool(lock.get("exists")) if isinstance(lock, dict) else False
        lock_col = lock_owner if lock_exists else "-"

        rows.append(
            [
                str(t.get("taskId", "")),
                str(t.get("owner", "")),
                str(t.get("status", "")),
                lock_col,
                str(t.get("title", "")),
            ]
        )

    widths = [len(h) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(c))

    def fmt_row(r: list[str]) -> str:
        return "  ".join(c.ljust(widths[i]) for i, c in enumerate(r))

    print(fmt_row(headers))
    print(fmt_row(["-" * w for w in widths]))
    for r in rows:
        print(fmt_row(r))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="dasops", description="DAS + OpenSpec factory tooling")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # -----------------------------------------------------------------
    # Factory command: create new product repo
    # -----------------------------------------------------------------
    p_create = sub.add_parser("create", help="Create a NEW product repo (physical isolation) from the factory template")
    p_create.add_argument("--dest", required=True, help="Destination directory for the new product repo")
    p_create.add_argument("--master-doc", required=True, help="Path to master_doc.md")
    p_create.add_argument("--ui-spec", required=True, help="Path to ui_spec.md")
    p_create.add_argument("--change-id", default=None, help="Optional initial change id, e.g. initial")
    p_create.add_argument("--intent", default="", help="Optional intent string for the initial change")
    p_create.add_argument("--factory-root", default=None, help="Factory repo root (defaults to this source tree)")
    p_create.add_argument("--no-git", action="store_true", help="Do not run 'git init' in the new repo")
    p_create.add_argument("--overwrite", action="store_true", help="Allow writing into a non-empty destination directory")
    p_create.add_argument(
        "--allow-inside-factory",
        action="store_true",
        help="Allow creating the product repo inside the factory repo (NOT recommended)",
    )
    p_create.add_argument(
        "--change-empty",
        action="store_true",
        help="If --change-id is provided: create an EMPTY change folder (OPSX generates artifacts)",
    )

    # -----------------------------------------------------------------
    # Product commands (run inside a product repo)
    # -----------------------------------------------------------------
    p_init = sub.add_parser("init", help="(Product repo) Overwrite docs/master_doc.md and docs/ui_spec.md")
    p_init.add_argument("--master-doc", required=True, help="Path to master_doc.md")
    p_init.add_argument("--ui-spec", required=True, help="Path to ui_spec.md")
    p_init.add_argument("--repo-root", default=".", help="Repo root (default: .)")

    p_new = sub.add_parser("new-change", help="(Product repo) Create a new OpenSpec change folder")
    p_new.add_argument(
        "--id",
        required=True,
        help="Change id (folder name), e.g. add-login. Use 'auto' to generate from intent.",
    )
    p_new.add_argument("--intent", default="", help="Short intent description")
    p_new.add_argument(
        "--empty",
        action="store_true",
        help="Create an empty change folder (metadata only). Recommended when using OpenSpec OPSX to generate artifacts.",
    )
    p_new.add_argument("--repo-root", default=".", help="Repo root (default: .)")

    p_status = sub.add_parser("status", help="(Product repo) Show artifact status for a change (BLOCKED/READY/DONE)")
    p_status.add_argument("--id", required=True, help="Change id (folder name)")
    p_status.add_argument("--repo-root", default=".", help="Repo root (default: .)")

    p_doctor = sub.add_parser(
        "doctor",
        help="(Product repo) Check repo health + deterministic layout (intern-friendly)",
    )
    p_doctor.add_argument("--repo-root", default=".", help="Repo root (default: .)")
    p_doctor.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings as failures (exit 2).",
    )

    p_list = sub.add_parser("list-tasks", help="(Product repo) List tasks for a change (with lock info)")
    p_list.add_argument("--change-id", required=True, help="Change id (folder name)")
    p_list.add_argument("--repo-root", default=".", help="Repo root (default: .)")
    p_list.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    p_list.add_argument("--owner", default=None, help="Filter by owner")
    p_list.add_argument("--status", default=None, help="Filter by status")

    p_claim = sub.add_parser("claim-task", help="(Product repo) Claim a task (owner+status) and create a lock file")
    p_claim.add_argument("--change-id", required=True, help="Change id (folder name), e.g. add-login")
    p_claim.add_argument("--task-id", required=True, help="Task id, e.g. T-001")
    p_claim.add_argument(
        "--owner",
        default=None,
        help="Owner/worker id. Default: $DASOPS_OWNER, else git user.name, else OS user",
    )
    p_claim.add_argument("--status", default="IN_PROGRESS", help="Status to set (default: IN_PROGRESS)")
    p_claim.add_argument("--force", action="store_true", help="Overwrite an existing lock (DANGEROUS)")
    p_claim.add_argument("--json", action="store_true", help="Machine-readable JSON output (no next-step hints)")
    p_claim.add_argument("--no-hints", action="store_true", help="Do not print next-step hints")
    p_claim.add_argument("--repo-root", default=".", help="Repo root (default: .)")

    p_claim_ready = sub.add_parser(
        "claim-ready",
        help="(Product repo) Claim the next READY task (pull model: workers claim tasks when deps are DONE)",
    )
    p_claim_ready.add_argument("--change-id", required=True, help="Change id (folder name)")
    p_claim_ready.add_argument(
        "--owner",
        default=None,
        help="Owner/worker id. Default: $DASOPS_OWNER, else git user.name, else OS user",
    )
    p_claim_ready.add_argument("--status", default="IN_PROGRESS", help="Status to set (default: IN_PROGRESS)")
    p_claim_ready.add_argument(
        "--allow-preassigned",
        action="store_true",
        help="Allow claiming tasks that already have an explicit owner in tasks.md",
    )
    p_claim_ready.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    p_claim_ready.add_argument("--repo-root", default=".", help="Repo root (default: .)")

    p_complete = sub.add_parser("complete-task", help="(Product repo) Mark a task as DONE (updates tasks.md + lock)")
    p_complete.add_argument("--change-id", required=True)
    p_complete.add_argument("--task-id", required=True)
    p_complete.add_argument("--owner", default=None)
    p_complete.add_argument("--force", action="store_true")
    p_complete.add_argument("--json", action="store_true")
    p_complete.add_argument("--repo-root", default=".")

    p_release = sub.add_parser("release-task", help="(Product repo) Release a claimed task (remove lock, set status)")
    p_release.add_argument("--change-id", required=True)
    p_release.add_argument("--task-id", required=True)
    p_release.add_argument("--owner", default=None)
    p_release.add_argument("--status", default="TODO", help="Status to set in tasks.md after release")
    p_release.add_argument("--clear-owner", action="store_true", help="Also clear Owner in tasks.md (sets '-')")
    p_release.add_argument("--force", action="store_true")
    p_release.add_argument("--json", action="store_true")
    p_release.add_argument("--repo-root", default=".")

    p_start = sub.add_parser(
        "start-task",
        help="(Product repo) Create a feature branch/worktree AND claim the task (best for interns)",
    )
    p_start.add_argument("--change-id", required=True)
    p_start.add_argument("--task-id", required=True)
    p_start.add_argument("--owner", default=None)
    p_start.add_argument("--branch", default=None, help="Override branch name")
    p_start.add_argument("--base", default=None, help="Base branch (default: main/master/current)")
    p_start.add_argument(
        "--worktree",
        default=None,
        help="Worktree directory to create (default: .worktrees/<owner>/<task-id>)",
    )
    p_start.add_argument("--no-worktree", action="store_true", help="Do not create a worktree (checkout branch in-place)")
    p_start.add_argument("--force", action="store_true", help="Dangerous overrides (reassign/overwrite locks)")
    p_start.add_argument("--json", action="store_true")
    p_start.add_argument("--repo-root", default=".")

    p_prompt = sub.add_parser(
        "prompt",
        help="(Product repo) Render a prompt template for Orchestrator/Worker",
    )
    p_prompt.add_argument(
        "--role",
        required=True,
        choices=["orchestrator", "worker"],
        help="Prompt role to render",
    )
    p_prompt.add_argument("--change-id", required=True, help="Change id (folder name)")
    p_prompt.add_argument("--task-id", default=None, help="Task id (required for worker)")
    p_prompt.add_argument(
        "--owner",
        default=None,
        help="Owner/worker id (for worker prompt). Default: $DASOPS_OWNER, else git user.name, else OS user",
    )
    p_prompt.add_argument("--repo-root", default=".")

    args = parser.parse_args(argv)

    # -----------------------------------------------------------------
    # Factory command: create
    # -----------------------------------------------------------------
    if args.cmd == "create":
        factory_root = (
            Path(args.factory_root).expanduser().resolve()
            if args.factory_root
            else Path(__file__).resolve().parents[1]
        )
        dest = Path(args.dest).expanduser().resolve()

        # Guardrail: avoid creating product repos inside the factory repo.
        try:
            inside_factory = dest == factory_root or dest.is_relative_to(factory_root)
        except Exception:
            inside_factory = False

        if inside_factory and not args.allow_inside_factory:
            raise SystemExit(
                "Refusing to create a product repo inside the factory repo.\n\n"
                f"- Factory: {factory_root}\n"
                f"- Dest:    {dest}\n\n"
                "Why: If your tooling repo and product repo share a folder, AI agents may run the factory GUI/tools\n"
                "instead of working on the product.\n\n"
                "Fix: choose a different --dest (recommended), or pass --allow-inside-factory (not recommended)."
            )

        create_product_repo(
            factory_root=factory_root,
            dest_dir=dest,
            master_doc_path=Path(args.master_doc).expanduser().resolve(),
            ui_spec_path=Path(args.ui_spec).expanduser().resolve(),
            change_id=args.change_id,
            intent=args.intent,
            init_git=not args.no_git,
            overwrite=args.overwrite,
            change_empty=args.change_empty,
        )
        print(f"Created product repo: {dest}")
        return 0

    # From here down: product repo commands
    repo_root = _resolve_repo_root(Path(getattr(args, "repo_root", ".")).expanduser().resolve())

    # -----------------------------------------------------------------
    # init
    # -----------------------------------------------------------------
    if args.cmd == "init":
        init_repo(
            repo_root=repo_root,
            master_doc_path=Path(args.master_doc).expanduser().resolve(),
            ui_spec_path=Path(args.ui_spec).expanduser().resolve(),
        )
        print("Updated docs in product repo.")
        return 0

    # -----------------------------------------------------------------
    # new-change
    # -----------------------------------------------------------------
    if args.cmd == "new-change":
        change_id = str(args.id).strip()
        if change_id.lower() == "auto":
            change_id = _make_change_id(args.intent)
        new_change(repo_root=repo_root, change_id=change_id, intent=args.intent, empty=bool(args.empty))
        print(f"Created change folder: openspec/changes/{change_id}/")
        if args.empty:
            print("Note: created empty change folder (OPSX mode). Use OpenSpec OPSX to generate artifacts.")
        return 0

    # -----------------------------------------------------------------
    # status
    # -----------------------------------------------------------------
    if args.cmd == "status":
        print_status(repo_root=repo_root, change_id=args.id)
        return 0

    # -----------------------------------------------------------------
    # doctor
    # -----------------------------------------------------------------
    if args.cmd == "doctor":
        problems: list[str] = []
        warnings: list[str] = []

        # Repo type detection
        is_product_repo = (repo_root / ".dasops_product_repo").exists()
        is_factory_repo = (repo_root / ".dasops_factory_repo").exists()

        if not is_product_repo and not is_factory_repo:
            print("dasops doctor: could not detect a DASOPS repo in this directory.")
            print("Expected one of: .dasops_product_repo or .dasops_factory_repo")
            print(f"Checked: {repo_root}")
            return 2

        print("dasops doctor")
        print(f"Repo root: {repo_root}")
        print(f"Repo type: {'product' if is_product_repo else 'factory'}")

        if is_product_repo:
            # Required stable files (external memory)
            required = [
                repo_root / "docs" / "master_doc.md",
                repo_root / "docs" / "ui_spec.md",
                repo_root / "docs" / "USER_MANUAL.md",
                repo_root / "docs" / "policies" / "AGENT_OPERATING_MODEL.md",
                repo_root / "AGENTS.override.md",
                repo_root / "CLAUDE.md",
                repo_root / "progress.txt",
                repo_root / "openspec" / "config.yaml",
            ]
            for p in required:
                if not p.exists():
                    problems.append(f"Missing required file: {p.relative_to(repo_root)}")

            # OpenSpec schema sanity check (best-effort)
            cfg_path = repo_root / "openspec" / "config.yaml"
            if cfg_path.exists():
                try:
                    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
                    schema = str(cfg.get("schema", "")).strip()
                    if schema and schema != "das-standard":
                        warnings.append(
                            f"openspec/config.yaml schema is '{schema}' (expected 'das-standard')"
                        )
                except Exception as e:
                    warnings.append(f"Could not parse openspec/config.yaml: {e}")

            # Deterministic layout checks
            if (repo_root / "docs" / "deltas").exists():
                problems.append("Found docs/deltas/. Use openspec/changes/<change-id>/ instead (deterministic).")

            stray_tasks: list[Path] = []
            for p in repo_root.rglob("tasks.md"):
                rel = p.relative_to(repo_root)
                # Allowed: openspec/changes/<change-id>/tasks.md
                ok = (
                    len(rel.parts) == 4
                    and rel.parts[0] == "openspec"
                    and rel.parts[1] == "changes"
                    and rel.parts[3] == "tasks.md"
                )
                if not ok:
                    stray_tasks.append(rel)
            if stray_tasks:
                problems.append(
                    "Found stray tasks.md outside openspec/changes/<change-id>/tasks.md:\n  - "
                    + "\n  - ".join(str(p) for p in sorted(stray_tasks))
                )

            # Friendly next steps
            print("\nNext steps (typical):")
            print("  - Read docs/USER_MANUAL.md")
            print("  - Run ./scripts/verify")
            print("  - Create a change: dasops new-change --id <change-id> --intent \"...\"")

        if is_factory_repo:
            # Factory sanity checks (minimal)
            if not (repo_root / "dasops" / "__main__.py").exists():
                problems.append("Missing dasops/__main__.py")
            if not (repo_root / "templates" / "das-product").exists():
                problems.append("Missing templates/das-product")

        if warnings:
            print("\nWarnings:")
            for w in warnings:
                print(f"- {w}")

        if problems:
            print("\nProblems:")
            for p in problems:
                print(f"- {p}")
            print("\nResult: FAIL")
            return 2

        print("\nResult: OK")
        return 0

    # -----------------------------------------------------------------
    # list-tasks
    # -----------------------------------------------------------------
    if args.cmd == "list-tasks":
        tasks = list_tasks(repo_root=repo_root, change_id=args.change_id)

        # Filtering (best-effort)
        if args.owner:
            tasks = [t for t in tasks if str(t.get("owner", "")) == str(args.owner)]
        if args.status:
            tasks = [t for t in tasks if str(t.get("status", "")) == str(args.status)]

        if args.json:
            print(json.dumps({"changeId": args.change_id, "tasks": tasks}, indent=2, ensure_ascii=False))
            return 0

        print(f"Change: {args.change_id}\n")
        if not tasks:
            print("No tasks found in the Task index table.")
            return 0

        _print_task_table(tasks)

        # Basic safety warnings
        warnings: list[str] = []
        for t in tasks:
            status = str(t.get("status", ""))
            lock = t.get("lock") or {}
            lock_exists = bool(lock.get("exists")) if isinstance(lock, dict) else False
            lock_owner = str(lock.get("owner", "")) if isinstance(lock, dict) else ""
            owner = str(t.get("owner", ""))

            if status == "IN_PROGRESS" and not lock_exists:
                warnings.append(f"- {t.get('taskId')}: IN_PROGRESS but no lock file (run dasops claim-task)")
            if lock_exists and lock_owner and owner and lock_owner != owner:
                warnings.append(
                    f"- {t.get('taskId')}: lock owner '{lock_owner}' != tasks.md owner '{owner}' (Orchestrator should resolve)"
                )

        if warnings:
            print("\nWarnings:")
            for w in warnings:
                print(w)

        return 0

    # -----------------------------------------------------------------
    # claim-task
    # -----------------------------------------------------------------
    if args.cmd == "claim-task":
        owner = _normalize_owner(args.owner) if args.owner else _default_owner(repo_root)
        if not owner:
            raise SystemExit("Owner is empty. Provide --owner or set $DASOPS_OWNER.")

        lock_path = claim_task(
            repo_root=repo_root,
            change_id=args.change_id,
            task_id=args.task_id,
            owner=owner,
            status=args.status,
            force=args.force,
        )

        hints = read_task_hints(repo_root=repo_root, change_id=args.change_id, task_id=args.task_id)
        tasks_path = hints.get("tasks_path")
        owner_from_tasks = str(hints.get("owner", "") or owner).strip()
        status_from_tasks = str(hints.get("status", "") or args.status).strip()
        expected_branch = str(hints.get("branch", "") or "").strip()
        verify_cmds = list(hints.get("verify_cmds", []) or [])

        # Paths (relative where possible)
        rel_lock = _fmt_rel(repo_root, lock_path)
        rel_tasks = _fmt_rel(repo_root, tasks_path) if isinstance(tasks_path, Path) else str(tasks_path)

        current_branch = _git_current_branch(repo_root) if _is_git_repo(repo_root) else ""

        payload = {
            "ok": True,
            "changeId": args.change_id,
            "taskId": args.task_id,
            "owner": owner_from_tasks,
            "status": status_from_tasks,
            "paths": {"tasksMd": rel_tasks, "lock": rel_lock},
            "git": {"isRepo": _is_git_repo(repo_root), "branch": current_branch},
            "hints": {"expectedBranch": expected_branch, "verify": verify_cmds},
        }

        if args.json:
            print(json.dumps(payload, indent=2, ensure_ascii=False))
            return 0

        # Human-friendly output
        print(f"Claimed {args.task_id} (change: {args.change_id})")
        print(f"- Owner:  {owner_from_tasks}")
        print(f"- Status: {status_from_tasks}")
        print(f"- Updated: {rel_tasks}")
        print(f"- Lock:   {rel_lock}")

        if verify_cmds:
            print("\nVerify gate(s) (from tasks.md):")
            for c in verify_cmds:
                print(f"- {c}")

        # Next-step coaching
        if not args.no_hints:
            if _is_git_repo(repo_root):
                add_cmd = f"git add {rel_tasks} {rel_lock}"
                commit_cmd = f'git commit -m "chore: claim {args.task_id}"'
                print("\nNext steps (recommended):")
                print(f"  {add_cmd} && {commit_cmd}")
                if current_branch:
                    print("  git push -u origin HEAD")

                suggested_branch = expected_branch
                if _is_placeholder(suggested_branch):
                    suggested_branch = f"feat/{args.change_id}/{args.task_id}"

                if current_branch in {"main", "master"}:
                    print("\nNote:")
                    print(f"- You are currently on '{current_branch}'. Workers should implement tasks on a feature branch.")
                    print(f"  Suggested: git checkout -b {suggested_branch} {current_branch}")
                elif expected_branch and not _is_placeholder(expected_branch) and current_branch and current_branch != expected_branch:
                    print("\nNote:")
                    print(f"- Current branch is '{current_branch}', but tasks.md suggests '{expected_branch}'.")
                    print("  Consider: git branch -m <new-name>  # or create a new branch")

                print("\nWorker loop (copy/paste):")
                print(
                    f"  ./scripts/run_worker_codex.sh {args.change_id} {args.task_id} {owner_from_tasks}"
                )
            else:
                print("\nNext steps:")
                print(f"- Stage and commit: {rel_tasks} and {rel_lock}")
                print(f"- Suggested commit message: chore: claim {args.task_id}")

        return 0

    # -----------------------------------------------------------------
    # claim-ready (pull-based dispatch)
    # -----------------------------------------------------------------
    if args.cmd == "claim-ready":
        owner = _normalize_owner(args.owner) if args.owner else _default_owner(repo_root)
        if not owner:
            raise SystemExit("Owner is empty. Provide --owner or set $DASOPS_OWNER.")

        lock_path = claim_ready_task(
            repo_root=repo_root,
            change_id=args.change_id,
            owner=owner,
            status=args.status,
            allow_preassigned=args.allow_preassigned,
        )

        if lock_path is None:
            if args.json:
                print(json.dumps({"ok": False, "error": "no_ready_task", "changeId": args.change_id}, indent=2))
            else:
                print("No READY tasks to claim (all blocked, already claimed, or not yet created).")
                print("Tip: run 'dasops list-tasks --change-id ...' and check Depends on / DONE status.")
            return 1

        task_id = lock_path.stem
        hints = read_task_hints(repo_root=repo_root, change_id=args.change_id, task_id=task_id)
        tasks_path = hints.get("tasks_path")
        expected_branch = str(hints.get("branch", "") or "").strip()
        verify_cmds = list(hints.get("verify_cmds", []) or [])

        rel_lock = _fmt_rel(repo_root, lock_path)
        rel_tasks = _fmt_rel(repo_root, tasks_path) if isinstance(tasks_path, Path) else str(tasks_path)
        current_branch = _git_current_branch(repo_root) if _is_git_repo(repo_root) else ""

        payload = {
            "ok": True,
            "changeId": args.change_id,
            "taskId": task_id,
            "owner": owner,
            "status": args.status,
            "paths": {"tasksMd": rel_tasks, "lock": rel_lock},
            "git": {"isRepo": _is_git_repo(repo_root), "branch": current_branch},
            "hints": {"expectedBranch": expected_branch, "verify": verify_cmds},
        }

        if args.json:
            print(json.dumps(payload, indent=2, ensure_ascii=False))
            return 0

        print(f"Claimed: {task_id}  owner={owner}  status={args.status}")
        print(f"- tasks.md: {rel_tasks}")
        print(f"- lock:     {rel_lock}")
        if expected_branch:
            print(f"- suggested branch: {expected_branch}")
        if verify_cmds:
            print("- verify:")
            for c in verify_cmds:
                print(f"    {c}")
        return 0

    # -----------------------------------------------------------------
    # complete-task
    # -----------------------------------------------------------------
    if args.cmd == "complete-task":
        owner = _normalize_owner(args.owner) if args.owner else _default_owner(repo_root)
        lock_path = complete_task(
            repo_root=repo_root,
            change_id=args.change_id,
            task_id=args.task_id,
            owner=owner,
            force=args.force,
        )

        payload = {
            "ok": True,
            "changeId": args.change_id,
            "taskId": args.task_id,
            "owner": owner,
            "status": "DONE",
            "lock": _fmt_rel(repo_root, lock_path),
        }
        if args.json:
            print(json.dumps(payload, indent=2, ensure_ascii=False))
            return 0

        print(f"Completed {args.task_id} (change: {args.change_id})")
        print(f"- Owner:  {owner}")
        print("- Status: DONE")
        print(f"- Lock:   {_fmt_rel(repo_root, lock_path)}")
        print("\nNext steps (recommended):")
        print("  ./scripts/verify")
        print(f"  git add openspec/changes/{args.change_id}/tasks.md openspec/changes/{args.change_id}/task_locks/{args.task_id}.lock")
        print(f"  git commit -m \"chore: complete {args.task_id}\"")
        print("  git push -u origin HEAD")

        return 0

    # -----------------------------------------------------------------
    # release-task
    # -----------------------------------------------------------------
    if args.cmd == "release-task":
        owner = _normalize_owner(args.owner) if args.owner else _default_owner(repo_root)
        lock_path = release_task(
            repo_root=repo_root,
            change_id=args.change_id,
            task_id=args.task_id,
            owner=owner,
            status=args.status,
            clear_owner=bool(args.clear_owner),
            force=args.force,
        )

        payload = {
            "ok": True,
            "changeId": args.change_id,
            "taskId": args.task_id,
            "owner": owner,
            "status": args.status,
            "lockRemoved": _fmt_rel(repo_root, lock_path),
        }
        if args.json:
            print(json.dumps(payload, indent=2, ensure_ascii=False))
            return 0

        print(f"Released {args.task_id} (change: {args.change_id})")
        print(f"- Owner (request): {owner}")
        print(f"- Status set to:   {args.status}")
        print(f"- Removed lock:    {_fmt_rel(repo_root, lock_path)}")
        print("\nNext steps (recommended):")
        print(f"  git add openspec/changes/{args.change_id}/tasks.md")
        print(f"  git commit -m \"chore: release {args.task_id}\"")
        print("  git push -u origin HEAD")

        return 0

    # -----------------------------------------------------------------
    # start-task
    # -----------------------------------------------------------------
    if args.cmd == "start-task":
        if not _is_git_repo(repo_root):
            raise SystemExit("start-task requires a git repo. Run inside the product repo and ensure git init is done.")

        if not _git_worktree_clean(repo_root):
            raise SystemExit(
                "Your working tree has uncommitted changes.\n"
                "For safety, commit or stash before running start-task."
            )

        owner = _normalize_owner(args.owner) if args.owner else _default_owner(repo_root)
        if not owner:
            raise SystemExit("Owner is empty. Provide --owner or set $DASOPS_OWNER.")

        hints = read_task_hints(repo_root=repo_root, change_id=args.change_id, task_id=args.task_id)
        expected_branch = str(hints.get("branch", "") or "").strip()

        # Resolve branch name
        if args.branch:
            branch = str(args.branch).strip()
        elif expected_branch and not _is_placeholder(expected_branch):
            branch = expected_branch
        else:
            # Use title to generate a stable slug.
            all_tasks = list_tasks(repo_root=repo_root, change_id=args.change_id)
            title = ""
            for t in all_tasks:
                if str(t.get("taskId")) == args.task_id:
                    title = str(t.get("title", ""))
                    break
            slug = _slugify(title) if title else "task"
            branch = f"feat/{args.change_id}/{args.task_id}-{slug}" if slug else f"feat/{args.change_id}/{args.task_id}"

        base = str(args.base).strip() if args.base else _pick_base_branch(repo_root)

        # Determine worktree dir
        if args.no_worktree:
            worktree_dir = repo_root
        else:
            if args.worktree:
                worktree_dir = Path(args.worktree).expanduser().resolve()
            else:
                worktree_dir = (repo_root / ".worktrees" / owner / args.task_id).resolve()

        payload: dict[str, object] = {
            "ok": False,
            "changeId": args.change_id,
            "taskId": args.task_id,
            "owner": owner,
            "branch": branch,
            "base": base,
            "worktree": str(worktree_dir),
            "noWorktree": bool(args.no_worktree),
        }

        # Create branch/worktree
        if args.no_worktree:
            rc, out = _run(["git", "checkout", "-b", branch, base], cwd=repo_root)
            if rc != 0:
                raise SystemExit(f"Failed to create branch: {out}")
        else:
            if worktree_dir.exists() and any(worktree_dir.iterdir()):
                raise SystemExit(f"Worktree directory already exists and is not empty: {worktree_dir}")
            worktree_dir.parent.mkdir(parents=True, exist_ok=True)
            rc, out = _run(["git", "worktree", "add", str(worktree_dir), "-b", branch, base], cwd=repo_root)
            if rc != 0:
                raise SystemExit(f"Failed to create worktree: {out}")

        # Claim the task inside the worktree (so claim artifacts are committed on that branch)
        lock_path = claim_task(
            repo_root=worktree_dir,
            change_id=args.change_id,
            task_id=args.task_id,
            owner=owner,
            status="IN_PROGRESS",
            force=args.force,
        )

        # Compose output
        rel_tasks = f"openspec/changes/{args.change_id}/tasks.md"
        rel_lock = f"openspec/changes/{args.change_id}/task_locks/{args.task_id}.lock"

        payload.update(
            {
                "ok": True,
                "paths": {"tasksMd": rel_tasks, "lock": rel_lock},
                "lockPath": _fmt_rel(worktree_dir, lock_path),
            }
        )

        if args.json:
            print(json.dumps(payload, indent=2, ensure_ascii=False))
            return 0

        print(f"Started {args.task_id} (change: {args.change_id})")
        print(f"- Owner:   {owner}")
        print(f"- Branch:  {branch}")
        if not args.no_worktree:
            print(f"- Worktree:{worktree_dir}")
        print(f"- Claimed: {rel_lock}")

        print("\nNext steps (copy/paste):")
        if not args.no_worktree:
            print(f"  cd {worktree_dir}")
        print("  ./scripts/verify")
        print(f"  git add {rel_tasks} {rel_lock}")
        print(f"  git commit -m \"chore: claim {args.task_id}\"")
        print("  git push -u origin HEAD")
        print("\nThen: run the Worker loop in this worktree:")
        print(f"  ./scripts/run_worker_codex.sh {args.change_id} {args.task_id} {owner}")
        print("\nSee docs/USER_MANUAL.md for the full workflow.")

        return 0

    # -----------------------------------------------------------------
    # prompt
    # -----------------------------------------------------------------
    if args.cmd == "prompt":
        prompts_dir = repo_root / "prompts"
        if args.role == "orchestrator":
            prompt_path = prompts_dir / "orchestrator.md"
        else:
            prompt_path = prompts_dir / "worker.md"

        if not prompt_path.exists():
            raise SystemExit(f"Prompt template not found: {prompt_path}")

        template = prompt_path.read_text(encoding="utf-8")

        mapping = {"CHANGE_ID": str(args.change_id).strip()}
        if args.role == "worker":
            if not args.task_id:
                raise SystemExit("--task-id is required for --role worker")
            owner = _normalize_owner(args.owner) if args.owner else _default_owner(repo_root)
            if not owner:
                raise SystemExit("Owner is empty. Provide --owner or set $DASOPS_OWNER.")
            mapping.update({"TASK_ID": str(args.task_id).strip(), "OWNER": owner})

        print(_render_prompt(template, mapping).rstrip() + "\n")
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
