import argparse
import json
import os
import shlex
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from .adopt import adopt_report, audit_repo, audit_report, normalize_report, trace_report
from .doctor import run_doctor
from .locks import inspect_lock, is_stale, read_lock, reclaim_lock, renew_lock, lock_path_for
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
from .standards import build_pack, search_indexes, show_clause, resolve_preview, resolve_facts_preview
from .standards_contracts import exact_json as exact_standard_json
from .template_audit import run_template_audit
from .protected_cli import add_protected_parsers, handle_protected
from .govern_cli import add_govern_parsers, handle_govern
from .bootstrap_cli import BootstrapCliError, add_bootstrap_parsers, handle_bootstrap


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


def _strip_task_command(value: str) -> str:
    match = re.search(r"`([^`]+)`", value or "")
    if match:
        return match.group(1).strip()
    return (value or "").strip()


def _final_release_task_number(task_id: str) -> int | None:
    match = re.fullmatch(r"T-(\d+)", task_id.strip())
    if match is None:
        return None
    return int(match.group(1))


def _is_final_release_task(task_id: str) -> bool:
    number = _final_release_task_number(task_id)
    return number is not None and number >= 168


def _tail(text: str, limit: int = 800) -> str:
    compact = (text or "").strip()
    if len(compact) <= limit:
        return compact
    return compact[-limit:]


def _verify_task_before_completion(repo_root: Path, change_id: str, task_id: str) -> None:
    if not _is_final_release_task(task_id):
        return

    command = ""
    for task in list_tasks(repo_root=repo_root, change_id=change_id):
        if str(task.get("taskId")) == task_id:
            command = _strip_task_command(str(task.get("verifyGate", "")))
            break

    if not command:
        raise SystemExit(f"{task_id} has no verify gate; refusing to mark DONE.")

    try:
        argv = shlex.split(command, posix=True)
    except ValueError as exc:
        raise SystemExit(f"{task_id} verify gate is not a valid command: {exc}") from exc
    if not argv or any(token in {"|", "||", "&&", ";", ">", ">>", "<"} for token in argv):
        raise SystemExit(f"{task_id} verify gate must be one executable command without shell operators.")

    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.setdefault("DAS_RELEASE_DONE_SWEEP_NESTED", "1")
    proc = subprocess.run(
        argv,
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        env=env,
        timeout=900,
    )
    if proc.returncode == 0:
        return

    detail = _tail(proc.stderr) or _tail(proc.stdout) or "no command output"
    raise SystemExit(
        f"{task_id} verify gate failed with exit {proc.returncode}; refusing to mark DONE.\n"
        f"Command: {command}\n"
        f"{detail}"
    )


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


def _default_factory_root() -> Path:
    candidates = [
        Path(__file__).resolve().parents[1],
        Path(sys.prefix),
    ]
    for candidate in candidates:
        if (candidate / "templates" / "das-product").is_dir():
            return candidate
    return candidates[0]


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

    p_standards = sub.add_parser(
        "standards",
        help="(Factory/workspace) Search and render machine-readable DAS standard indexes",
    )
    standards_sub = p_standards.add_subparsers(dest="standards_cmd", required=True)

    p_bundle_preview = standards_sub.add_parser("resolve-preview", help="Evaluate fact proposals or probe signed facts through pinned Cadence; no authority")
    p_bundle_preview.add_argument("--input", required=True, help="Exact preview request JSON")
    p_bundle_preview.add_argument("--cadence-binary", required=True, help="Absolute Cadence executable path")
    p_bundle_preview.add_argument("--cadence-sha256", required=True, help="Exact executable sha256 pin")
    p_bundle_preview.add_argument("--cadence-version", required=True, help="Exact component release version")

    p_standards_search = standards_sub.add_parser("search", help="Search standard chapters and clauses")
    p_standards_search.add_argument("--query", required=True, help="Search text, for example: closure")
    p_standards_search.add_argument("--standard-root", default=None, help="Optional path to das-standard")
    p_standards_search.add_argument("--repo-root", default=".", help="Repo root used to resolve workspace siblings")
    p_standards_search.add_argument("--json", action="store_true")

    p_standards_show = standards_sub.add_parser("show", help="Show one clause from clause_index.json")
    p_standards_show.add_argument("--clause", required=True, help="Clause id, for example: cl-2.5")
    p_standards_show.add_argument("--standard-root", default=None, help="Optional path to das-standard")
    p_standards_show.add_argument("--repo-root", default=".", help="Repo root used to resolve workspace siblings")
    p_standards_show.add_argument("--json", action="store_true")

    p_standards_pack = standards_sub.add_parser("pack", help="Build a role-oriented reading pack")
    p_standards_pack.add_argument("--for", dest="role", required=True, help="Role, for example: backend")
    p_standards_pack.add_argument("--standard-root", default=None, help="Optional path to das-standard")
    p_standards_pack.add_argument("--repo-root", default=".", help="Repo root used to resolve workspace siblings")
    p_standards_pack.add_argument("--json", action="store_true")

    p_audit = sub.add_parser(
        "audit",
        help="(Product repo) Emit a deterministic audit report for downstream consumers",
    )
    p_audit.add_argument("--repo-root", default=".", help="Repo root (default: .)")
    p_audit.add_argument("--json", action="store_true", help="Machine-readable JSON output")

    p_audit_repo = sub.add_parser("audit-repo", help="Audit a legacy repo before adoption")
    p_audit_repo.add_argument("path", help="Legacy repo path")
    p_audit_repo.add_argument("--json", action="store_true", help="Machine-readable JSON output")

    p_adopt_repo = sub.add_parser("adopt-repo", help="Seed missing DAS baseline artifacts into a legacy repo")
    p_adopt_repo.add_argument("path", help="Legacy repo path")
    p_adopt_repo.add_argument("--json", action="store_true", help="Machine-readable JSON output")

    p_normalize_repo = sub.add_parser("normalize-repo", help="Normalize a legacy repo and repair known doc links")
    p_normalize_repo.add_argument("path", help="Legacy repo path")
    p_normalize_repo.add_argument("--json", action="store_true", help="Machine-readable JSON output")

    p_trace_check = sub.add_parser("trace-check", help="Emit trace relationships for an adopted repo")
    p_trace_check.add_argument("path", help="Repo path")
    p_trace_check.add_argument("--json", action="store_true", help="Machine-readable JSON output")

    p_template_audit = sub.add_parser(
        "template-audit",
        help="(Factory repo) Audit template integrity, structured artifacts, and GUI/CLI parity",
    )
    p_template_audit.add_argument("--repo-root", default=".", help="Factory repo root (default: .)")
    p_template_audit.add_argument("--json", action="store_true", help="Machine-readable JSON output")

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

    p_lock = sub.add_parser(
        "lock-status",
        help="(Product repo) Inspect a structured task lock and optionally assert owner",
    )
    p_lock.add_argument("--change-id", required=True)
    p_lock.add_argument("--task-id", required=True)
    p_lock.add_argument("--expect-owner", default=None)
    p_lock.add_argument("--json", action="store_true")
    p_lock.add_argument("--repo-root", default=".")

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

    p_renew = sub.add_parser(
        "renew-lock",
        help="(Product repo) Renew the heartbeat of a task lock",
    )
    p_renew.add_argument("--change-id", required=True)
    p_renew.add_argument("--task-id", required=True)
    p_renew.add_argument("--owner", required=True)
    p_renew.add_argument("--lock-token", required=True, help="Lock token from the lock file")
    p_renew.add_argument("--json", action="store_true")
    p_renew.add_argument("--repo-root", default=".")

    p_reclaim = sub.add_parser(
        "reclaim-lock",
        help="(Product repo) Reclaim a stale lock for a new owner",
    )
    p_reclaim.add_argument("--change-id", required=True)
    p_reclaim.add_argument("--task-id", required=True)
    p_reclaim.add_argument("--new-owner", required=True)
    p_reclaim.add_argument("--reason", required=True, help="Reason for reclaim (audit trail)")
    p_reclaim.add_argument("--force", action="store_true", help="Reclaim even if lock is not stale")
    p_reclaim.add_argument("--json", action="store_true")
    p_reclaim.add_argument("--repo-root", default=".")

    p_check_stale = sub.add_parser(
        "check-stale",
        help="(Product repo) Check whether a task lock is stale",
    )
    p_check_stale.add_argument("--change-id", required=True)
    p_check_stale.add_argument("--task-id", required=True)
    p_check_stale.add_argument("--json", action="store_true")
    p_check_stale.add_argument("--repo-root", default=".")

    add_protected_parsers(sub)
    add_bootstrap_parsers(sub)
    add_govern_parsers(sub)

    args = parser.parse_args(argv)

    # -----------------------------------------------------------------
    # Factory command: create
    # -----------------------------------------------------------------
    if args.cmd == "create":
        factory_root = (
            Path(args.factory_root).expanduser().resolve()
            if args.factory_root
            else _default_factory_root()
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

    governed_result = handle_govern(args)
    if governed_result is not None:
        return governed_result

    # From here down: product repo commands
    raw_repo_root = Path(getattr(args, "repo_root", ".")).expanduser().resolve()
    repo_root = _resolve_repo_root(raw_repo_root)

    protected_result = handle_protected(args)
    if protected_result is not None:
        return protected_result
    try:
        bootstrap_result = handle_bootstrap(args)
    except BootstrapCliError as exc:
        print(f"bootstrap invocation rejected: {exc}", file=sys.stderr)
        return 2
    if bootstrap_result is not None:
        return bootstrap_result

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
        # Doctor uses raw_repo_root to honour the explicit --repo-root flag
        # instead of resolving to the git toplevel (which may differ when
        # the dasops directory is a subdirectory of a larger workspace).
        doctor_root = raw_repo_root
        report = run_doctor(doctor_root)
        print("dasops doctor")
        print(f"Repo root: {report.repo_root}")
        print(f"Repo type: {report.repo_type}")
        if report.repo_type == "product":
            print("\nNext steps (typical):")
            print("  - Read docs/USER_MANUAL.md")
            print("  - Run ./scripts/verify")
            print("  - Create a change: dasops new-change --id <change-id> --intent \"...\"")

        if report.warnings:
            print("\nWarnings:")
            for warning in report.warnings:
                print(f"- {warning}")

        if report.problems:
            print("\nProblems:")
            for problem in report.problems:
                print(f"- {problem}")
            print("\nResult: FAIL")
            return 2

        if args.strict and report.warnings:
            print("\nResult: FAIL (strict mode)")
            return 2

        print("\nResult: OK")
        return 0

    # -----------------------------------------------------------------
    # standards
    # -----------------------------------------------------------------
    if args.cmd == "standards":
        if args.standards_cmd == "resolve-preview":
            try:
                with Path(args.input).open("rb") as stream:
                    raw = stream.read(exact_standard_json.MAX_BYTES + 1)
                request = exact_standard_json.parse_catalog(raw)
                if not isinstance(request, dict) or request.get("contractIdentity") not in (
                        "das-bundle-preview-input/v2", "das-bundle-preview-input/v3", "das-approved-facts-preview-input/v1"):
                    request = exact_standard_json.parse(raw)
                resolver = resolve_facts_preview if isinstance(request, dict) and request.get("contractIdentity") == "das-approved-facts-preview-input/v1" else resolve_preview
                result = resolver(request, binary=args.cadence_binary, binary_sha256=args.cadence_sha256, release_version=args.cadence_version)
                print(exact_standard_json.canonical(result).decode("utf-8"))
            except (OSError, ValueError) as exc:
                raise SystemExit("Bundle preview failed; no approved governance result was produced") from exc
            return 0
        standards_root = _resolve_repo_root(Path(getattr(args, "repo_root", ".")).expanduser().resolve())
        if args.standards_cmd == "search":
            payload = search_indexes(
                standards_root,
                query=args.query,
                standard_root=args.standard_root,
            )
            if args.json:
                print(json.dumps(payload, indent=2, ensure_ascii=False))
                return 0
            print(f"query: {payload['query']}")
            print(f"matches: {payload['count']}")
            for item in payload["results"]:
                if item["kind"] == "chapter":
                    print(f"- [chapter] {item['id']} — {item['title']} ({item['file']})")
                else:
                    print(f"- [clause] {item['id']} — {item['title']} ({item['chapter']})")
            return 0

        if args.standards_cmd == "show":
            payload = show_clause(
                standards_root,
                clause_id=args.clause,
                standard_root=args.standard_root,
            )
            if args.json:
                print(json.dumps(payload, indent=2, ensure_ascii=False))
                return 0
            print(f"clause: {payload['id']}")
            print(f"title: {payload['title']}")
            print(f"chapter: {payload['chapter']} — {payload['chapterTitle']}")
            print(f"chapterFile: {payload['chapterFile']}")
            if payload["keywords"]:
                print("keywords: " + ", ".join(payload["keywords"]))
            if payload["gateLabels"]:
                print("gateLabels: " + ", ".join(payload["gateLabels"]))
            return 0

        if args.standards_cmd == "pack":
            payload = build_pack(
                standards_root,
                role=args.role,
                standard_root=args.standard_root,
            )
            if args.json:
                print(json.dumps(payload, indent=2, ensure_ascii=False))
                return 0
            print(f"role: {payload['role']}")
            print(f"chapters: {payload['chapterCount']}")
            print(f"clauses: {payload['clauseCount']}")
            for chapter in payload["chapters"]:
                print(f"- {chapter['id']} — {chapter['title']}")
            return 0

    # -----------------------------------------------------------------
    # audit
    # -----------------------------------------------------------------
    if args.cmd == "audit":
        result = audit_repo(repo_root)
        payload = {
            "schemaVersion": "1.0.0",
            "repoRoot": str(result.repo_root),
            "ok": not result.findings,
            "findings": result.findings,
        }
        if args.json:
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            print(f"repoRoot: {payload['repoRoot']}")
            print(f"ok: {payload['ok']}")
            if payload["findings"]:
                print("findings:")
                for finding in payload["findings"]:
                    print(f"- {finding}")
        return 0

    if args.cmd == "audit-repo":
        payload = audit_report(Path(args.path).expanduser().resolve())
        if args.json:
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            for finding in payload["findings"]:
                print(f"- {finding}")
        return 0 if payload["ok"] else 1

    if args.cmd == "adopt-repo":
        payload = adopt_report(Path(args.path).expanduser().resolve())
        if args.json:
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            for repaired in payload["repairedArtifacts"]:
                print(f"- {repaired}")
        return 0 if payload["ok"] else 1

    if args.cmd == "normalize-repo":
        payload = normalize_report(Path(args.path).expanduser().resolve())
        if args.json:
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            for repaired in payload["repairedArtifacts"]:
                print(f"- {repaired}")
            for rewrite in payload["docLinkRepairs"]:
                print(f"- repaired link {rewrite['from']} -> {rewrite['to']}")
        return 0 if payload["ok"] else 1

    if args.cmd == "trace-check":
        payload = trace_report(Path(args.path).expanduser().resolve())
        if args.json:
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            if payload["ok"]:
                print("OPS-002 trace-check: PASS")
            else:
                for problem in payload["problems"]:
                    print(f"- {problem['message']}")
        return 0 if payload["ok"] else 1

    # -----------------------------------------------------------------
    # template-audit
    # -----------------------------------------------------------------
    if args.cmd == "template-audit":
        # Template-audit validates the factory tree itself.  Use the explicit
        # --repo-root value rather than the git toplevel, because this repo is
        # often checked out as a subdirectory of a larger DAS workspace.
        report = run_template_audit(raw_repo_root)
        payload = report.to_payload()
        if args.json:
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            print(f"factoryRoot: {payload['factoryRoot']}")
            print(f"templateRoot: {payload['templateRoot']}")
            print(f"ok: {payload['ok']}")
            if payload["problems"]:
                print("problems:")
                for problem in payload["problems"]:
                    print(f"- {problem}")
            if payload["warnings"]:
                print("warnings:")
                for warning in payload["warnings"]:
                    print(f"- {warning}")
        return 0 if payload["ok"] else 2

    # -----------------------------------------------------------------
    # lock-status
    # -----------------------------------------------------------------
    if args.cmd == "lock-status":
        owner = _normalize_owner(args.expect_owner) if args.expect_owner else None
        payload = inspect_lock(
            repo_root=repo_root,
            change_id=args.change_id,
            task_id=args.task_id,
            expect_owner=owner,
        )
        if args.json:
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        if not payload["exists"]:
            return 1
        if owner and not payload["ownerMatches"]:
            return 2
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

        try:
            lock_path = claim_task(
                repo_root=repo_root,
                change_id=args.change_id,
                task_id=args.task_id,
                owner=owner,
                status=args.status,
                force=args.force,
            )
        except SystemExit as exc:
            if args.json:
                change_dir = repo_root / "openspec" / "changes" / args.change_id
                existing = read_lock(lock_path_for(change_dir, args.task_id))
                payload = {
                    "ok": False,
                    "task": "OPS-003",
                    "command": "claim-task",
                    "changeId": args.change_id,
                    "taskId": args.task_id,
                    "requestedOwner": owner,
                    "currentOwner": existing.owner if existing else None,
                    "message": str(exc),
                }
                print(json.dumps(payload, indent=2, ensure_ascii=False))
                return 1
            raise

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
        if not args.force:
            _verify_task_before_completion(repo_root, args.change_id, args.task_id)
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

    # -----------------------------------------------------------------
    # renew-lock
    # -----------------------------------------------------------------
    if args.cmd == "renew-lock":
        lp = renew_lock(
            repo_root=repo_root,
            change_id=args.change_id,
            task_id=args.task_id,
            owner=args.owner,
            lock_token=args.lock_token,
        )
        if getattr(args, "json", False):
            print(json.dumps({"renewed": True, "lockPath": str(lp)}))
        else:
            print(f"Lock renewed: {lp}")
        return 0

    # -----------------------------------------------------------------
    # reclaim-lock
    # -----------------------------------------------------------------
    if args.cmd == "reclaim-lock":
        change_dir = repo_root / "openspec" / "changes" / args.change_id
        lock_file = lock_path_for(change_dir, args.task_id)
        previous = read_lock(lock_file)
        lp = reclaim_lock(
            repo_root=repo_root,
            change_id=args.change_id,
            task_id=args.task_id,
            new_owner=args.new_owner,
            reason=args.reason,
            force=args.force,
        )
        if getattr(args, "json", False):
            current = read_lock(lp)
            payload = {
                "ok": True,
                "task": "OPS-003",
                "command": "reclaim-lock",
                "reclaimed": True,
                "taskId": args.task_id,
                "previousOwner": previous.owner if previous else None,
                "newOwner": current.owner if current else args.new_owner,
                "oldToken": previous.lock_token if previous else None,
                "newToken": current.lock_token if current else None,
                "lockPath": str(lp),
                "reason": args.reason,
            }
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            print(f"Lock reclaimed: {lp}")
        return 0

    # -----------------------------------------------------------------
    # check-stale
    # -----------------------------------------------------------------
    if args.cmd == "check-stale":
        change_dir = repo_root / "openspec" / "changes" / args.change_id
        lp = lock_path_for(change_dir, args.task_id)
        lock = read_lock(lp)
        if lock is None:
            result = {"taskId": args.task_id, "lockExists": False, "stale": None}
        else:
            result = {
                "taskId": args.task_id,
                "lockExists": True,
                "stale": is_stale(lock),
                "owner": lock.owner,
                "heartbeatAt": lock.heartbeat_at,
                "leaseSeconds": lock.lease_seconds,
            }
        if getattr(args, "json", False):
            print(json.dumps(result))
        else:
            if lock is None:
                print(f"No lock for task {args.task_id}")
            elif result["stale"]:
                print(f"STALE: task {args.task_id} (owner={lock.owner}, heartbeat={lock.heartbeat_at})")
            else:
                print(f"ACTIVE: task {args.task_id} (owner={lock.owner}, heartbeat={lock.heartbeat_at})")
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
