from __future__ import annotations

import json
import os
import shutil
import tempfile
import sys
import subprocess
from datetime import date
from pathlib import Path
from typing import Optional
from .identities import validate_id


def default_factory_root() -> Path:
    """Locate data_files in a source checkout, --target install, or venv."""
    candidates = [Path(__file__).resolve().parents[1], Path(sys.prefix)]
    return next((p for p in candidates if (p / "templates/das-product").is_dir()), candidates[0])


def factory_template_dir(factory_root: Path) -> Path:
    return factory_root / "templates" / "das-product"


def chmod_executable(path: Path) -> None:
    try:
        st = path.stat()
        os.chmod(path, st.st_mode | 0o111)
    except Exception:
        pass


def ensure_product_repo_permissions(repo_root: Path) -> None:
    scripts = repo_root / "scripts"
    if scripts.exists():
        for file_path in scripts.iterdir():
            if file_path.is_file():
                chmod_executable(file_path)

    cadencew = repo_root / "cadencew"
    if cadencew.exists() and cadencew.is_file():
        chmod_executable(cadencew)


def seed_machine_readable_artifacts(repo_root: Path) -> None:
    """Seed tooling_lock.json and local_extension_manifest.json into a new repo.

    These machine-readable artifacts allow the suite to verify the seeded repo
    as a closure participant from its first commit.
    """
    tooling_lock = repo_root / "tooling_lock.json"
    if not tooling_lock.exists():
        lock_content = {
            "$schema": "https://das-standard.dev/schemas/tooling_lock.schema.json",
            "schemaVersion": "1.0.0",
            "standardManifestVersion": "1.4.0",
            "sourceOfTruth": {
                "kind": "git",
                "uri": ".",
                "pinType": "commit",
                "pinState": "pending",
                "floating": False,
            },
            "verifyRuntime": {
                "kind": "package",
                "uri": "pkg://cadence-oss/core-v146-baseline",
                "pinType": "version",
                "pinValue": "2026.04",
                "floating": False,
            },
            "suiteVersionClosureRef": {
                "kind": "file",
                "uri": "./suite_version_closure.json",
                "pinType": "manifest",
                "pinValue": "suite_version_closure.json",
                "floating": False,
            },
            "suiteLockRef": {
                "kind": "file",
                "uri": "./suite_lock.json",
                "pinType": "manifest",
                "pinValue": "suite_lock.json",
                "floating": False,
            },
            "verifyRegistryRef": {
                "kind": "file",
                "uri": "./vendor/cadence/cadence-oss/cadence-registry/registry.json",
                "pinType": "manifest",
                "pinValue": "registry.json",
                "floating": False,
            },
            "generatorTemplateVersion": "2026.04.08",
            "policyPackVersion": "2026.04",
            "toolchain": [
                {
                    "name": "python3",
                    "version": "3.10+",
                },
                {
                    "name": "pyyaml",
                    "version": "6.x",
                    "manager": "pip",
                },
            ],
        }
        tooling_lock.write_text(
            json.dumps(lock_content, indent=2) + "\n", encoding="utf-8"
        )

    ext_manifest = repo_root / "local_extension_manifest.json"
    if not ext_manifest.exists():
        manifest_content = {
            "$schema": "https://das-standard.dev/schemas/local_extension_manifest.schema.json",
            "schemaVersion": "1.0.0",
            "standardManifestVersion": "1.4.0",
            "extensions": [
                {
                    "name": "org.example.project.local-policy",
                    "namespace": "org.example.project",
                    "kind": "other",
                    "extensionPoint": "other",
                    "owner": "project-architecture",
                    "scope": "project-local",
                    "compatibilityNote": "Tracks project-local policy declarations outside the core DAS standard.",
                    "reviewDate": "2026-12-31",
                    "values": ["local-policy"],
                }
            ],
        }
        ext_manifest.write_text(
            json.dumps(manifest_content, indent=2) + "\n", encoding="utf-8"
        )


def create_product_repo_from_template(
    *,
    template_dir: Path,
    dest_dir: Path,
    master_doc_path: Path,
    ui_spec_path: Path,
    change_id: Optional[str] = None,
    intent: str = "",
    init_git: bool = True,
    overwrite: bool = False,
    change_empty: bool = False,
) -> Path:
    if not template_dir.exists():
        raise SystemExit(
            "OPS-001 dasops create failed for command `dasops create`: "
            "Factory template not found. Expected: "
            f"{template_dir}.\n\n"
            "If you installed dasops as a package, run this command from the cloned "
            "factory repo, or pass --factory-root explicitly."
        )

    # Snapshot imports before copying: inputs may live inside the destination.
    master_bytes = master_doc_path.read_bytes()
    ui_bytes = ui_spec_path.read_bytes()
    if change_id:
        _validate_change_id(change_id)
    dest_dir = dest_dir.expanduser().absolute()
    if dest_dir.is_symlink() or (dest_dir.exists() and not dest_dir.is_dir()):
        raise ValueError(f"Destination must be a real directory: {dest_dir}")
    if dest_dir.exists() and any(dest_dir.iterdir()) and not overwrite:
        raise SystemExit(
            f"Destination directory is not empty: {dest_dir}\n"
            "Refusing to overwrite. Use --overwrite if you really want this."
        )
    existing_git = init_git and (dest_dir / ".git").exists()
    if existing_git:
        head = subprocess.run(["git", "rev-parse", "--verify", "HEAD"], cwd=dest_dir,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if head.returncode:
            raise RuntimeError("Existing Git destination needs a committed HEAD before scaffold overwrite")
        index = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=dest_dir)
        if index.returncode != 0:
            raise RuntimeError("Refusing scaffold overwrite with staged user changes; preserve/commit them first")
    dest_dir.parent.mkdir(parents=True, exist_ok=True)
    # Build a complete scaffold before touching the target. TemporaryDirectory
    # owns only this staging directory, never the user's existing destination.
    with tempfile.TemporaryDirectory(prefix=".dasops-create-", dir=dest_dir.parent) as tmp:
        staged = Path(tmp) / "repo"
        shutil.copytree(template_dir, staged)
        seed_machine_readable_artifacts(staged)
        init_repo(repo_root=staged, master_doc_bytes=master_bytes, ui_spec_bytes=ui_bytes)
        if change_id:
            new_change(repo_root=staged, change_id=change_id, intent=intent, empty=change_empty)
        (staged / ".dasops_product_repo").write_text(
            "This is a DAS + OpenSpec PRODUCT repo generated by dasops.\n"
            "Work here (run verify, implement tasks, etc.).\n", encoding="utf-8")
        ensure_product_repo_permissions(staged)
        if not dest_dir.exists():
            if init_git:
                maybe_git_init(staged)
                finalize_bootstrap_provenance(staged)
            else:
                _mark_lock_pin_pending(staged)
            staged.rename(dest_dir)
        else:
            # Validate all existing output types before the first overwrite.
            for source in staged.rglob("*"):
                target = dest_dir / source.relative_to(staged)
                if target.is_symlink() or (target.exists() and target.is_dir() != source.is_dir()):
                    raise ValueError(f"Destination type conflict: {target}")
            shutil.copytree(staged, dest_dir, dirs_exist_ok=True)
            if init_git:
                if existing_git:
                    managed = [str(path.relative_to(staged)) for path in staged.rglob("*") if path.is_file()]
                    subprocess.run(["git", "add", "--", *managed], cwd=dest_dir, check=True)
                    changed = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=dest_dir)
                    if changed.returncode == 1:
                        subprocess.run(["git", "-c", "user.name=dasops", "-c", "user.email=dasops@local",
                                        "commit", "-m", "chore: update DAS scaffold", "--only", "--", *managed],
                                       cwd=dest_dir, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    elif changed.returncode:
                        raise RuntimeError("Unable to inspect scaffold index")
                else:
                    maybe_git_init(dest_dir)
                finalize_bootstrap_provenance(dest_dir)
            else:
                _mark_lock_pin_pending(dest_dir)

    return dest_dir


def create_product_repo(
    *,
    factory_root: Path,
    dest_dir: Path,
    master_doc_path: Path,
    ui_spec_path: Path | None = None,
    standard_release: str = "1.4.0",
    from_suite: Path | None = None,
    headless_note_path: Path | None = None,
    context_pack_path: Path | None = None,
    extension_manifest_path: Path | None = None,
    change_id: Optional[str] = None,
    intent: str = "",
    init_git: bool = True,
    overwrite: bool = False,
    change_empty: bool = False,
) -> Path:
    if standard_release == "1.5.0-beta.1":
        from .scaffold_v15 import create
        return create(factory_root=factory_root, dest_dir=dest_dir, master_doc_path=master_doc_path,
                      ui_spec_path=ui_spec_path, from_suite=from_suite, headless_note_path=headless_note_path,
                      context_pack_path=context_pack_path, extension_manifest_path=extension_manifest_path,
                      change_id=change_id, intent=intent, init_git=init_git, overwrite=overwrite, change_empty=change_empty)
    if standard_release != "1.4.0":
        raise ValueError("Unsupported Standard release: " + standard_release)
    if any(value is not None for value in (from_suite, headless_note_path, context_pack_path, extension_manifest_path)):
        raise ValueError("Suite/conditional-document create inputs require Standard 1.5")
    if ui_spec_path is None:
        raise ValueError("Standard 1.4 create requires --ui-spec")
    return create_product_repo_from_template(
        template_dir=factory_template_dir(factory_root),
        dest_dir=dest_dir,
        master_doc_path=master_doc_path,
        ui_spec_path=ui_spec_path,
        change_id=change_id,
        intent=intent,
        init_git=init_git,
        overwrite=overwrite,
        change_empty=change_empty,
    )


def finalize_bootstrap_provenance(repo_root: Path) -> str | None:
    """Record the immutable bootstrap commit without creating a self-reference.

    A commit cannot contain its own object ID.  The generated repository therefore
    records the first bootstrap commit in ``tooling_lock.json`` and commits that
    provenance update separately.  The resulting working tree is clean, the pin
    resolves to a reachable immutable baseline, and later product commits do not
    need to rewrite the lock.
    """
    lock_path = repo_root / "tooling_lock.json"
    if not lock_path.is_file() or not (repo_root / ".git").exists():
        raise RuntimeError("Bootstrap provenance incomplete: tooling lock or Git repository is missing")
    try:
        bootstrap_commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise RuntimeError("Bootstrap provenance failed; no successful source identity was recorded") from exc
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("Invalid bootstrap tooling lock") from exc
    sot = lock.get("sourceOfTruth")
    if not isinstance(sot, dict):
        raise RuntimeError("Invalid bootstrap sourceOfTruth")
    sot["pinValue"] = bootstrap_commit
    sot.pop("pinState", None)
    lock_path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    try:
        subprocess.run(["git", "add", "tooling_lock.json"], cwd=str(repo_root), check=True)
        staged = subprocess.run(
            ["git", "diff", "--cached", "--quiet"],
            cwd=str(repo_root),
            check=False,
        )
        if staged.returncode != 0:
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=dasops",
                    "-c",
                    "user.email=dasops@local",
                    "commit",
                    "-m",
                    "chore: record bootstrap source identity",
                    "--only", "--", "tooling_lock.json",
                ],
                cwd=str(repo_root),
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise RuntimeError("Bootstrap provenance failed; no successful source identity was recorded") from exc
    return bootstrap_commit


def _mark_lock_pin_pending(repo_root: Path) -> None:
    """Mark no-git generated repos as explicitly unpinned and fail-closed."""
    lock_path = repo_root / "tooling_lock.json"
    if not lock_path.exists():
        return
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    sot = lock.get("sourceOfTruth", {})
    if not isinstance(sot, dict):
        return
    if sot.get("pinValue") == "replace-with-product-commit":
        sot.pop("pinValue", None)
    if not sot.get("pinValue"):
        sot["pinState"] = "pending"
    lock_path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")


def maybe_git_init(repo_root: Path) -> None:
    if (repo_root / ".git").exists():
        return

    def run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            cmd,
            cwd=str(repo_root),
            check=check,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

    try:
        try:
            run(["git", "init", "-b", "main"], check=True)
        except Exception:
            run(["git", "init"], check=True)
            subprocess.run(
                ["git", "branch", "-m", "main"],
                cwd=str(repo_root),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )

        run(["git", "add", "-A"], check=True)
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
            check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise RuntimeError("Git bootstrap failed; product creation is incomplete") from exc


def init_repo(
    repo_root: Path,
    master_doc_path: Optional[Path] = None,
    ui_spec_path: Optional[Path] = None,
    master_doc_bytes: Optional[bytes] = None,
    ui_spec_bytes: Optional[bytes] = None,
    change_id: Optional[str] = None,
    change_intent: Optional[str] = None,
) -> None:
    if master_doc_path is not None:
        master_doc_bytes = master_doc_path.read_bytes()
    if ui_spec_path is not None:
        ui_spec_bytes = ui_spec_path.read_bytes()

    if master_doc_bytes is None:
        raise ValueError("master_doc missing: provide --master-doc or master_doc_bytes")
    if ui_spec_bytes is None:
        raise ValueError("ui_spec missing: provide --ui-spec or ui_spec_bytes")

    if change_id:
        _validate_change_id(change_id)
        if (repo_root / "openspec" / "changes" / change_id).exists():
            raise ValueError("Change already exists; refusing partial document import")
    docs_dir = repo_root / "docs"
    targets = [docs_dir / "master_doc.md", docs_dir / "ui_spec.md"]
    for target in targets:
        for parent in (target, *target.parents):
            if parent == repo_root:
                break
            if parent.is_symlink() or (parent.exists() and
                    (not parent.is_file() if parent == target else not parent.is_dir())):
                raise ValueError(f"Document import target conflict: {target}")
        if target.exists() and target.stat().st_nlink != 1:
            raise ValueError(f"Document import target is shared: {target}")
    before = {target: target.read_bytes() if target.exists() else None for target in targets}
    docs_dir.mkdir(parents=True, exist_ok=True)
    try:
        targets[0].write_bytes(master_doc_bytes)
        targets[1].write_bytes(ui_spec_bytes)
    except OSError:
        for target, original in before.items():
            if original is None:
                target.unlink(missing_ok=True)
            else:
                target.write_bytes(original)
        raise

    if change_id:
        new_change(repo_root=repo_root, change_id=change_id, intent=change_intent or "")


def _validate_change_id(change_id: str) -> None:
    try:
        validate_id("change_id", change_id)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None



def new_change(repo_root: Path, change_id: str, intent: str = "", *, empty: bool = False) -> Path:
    _validate_change_id(change_id)
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

    ospec_meta = change_dir / ".openspec.yaml"
    if not ospec_meta.exists():
        ospec_meta.write_text(
            f"schema: das-standard\ncreated: {date.today().isoformat()}\n",
            encoding="utf-8",
        )

    lock_dir = change_dir / "task_locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    gitkeep = lock_dir / ".gitkeep"
    if not gitkeep.exists():
        gitkeep.write_text("", encoding="utf-8")

    return change_dir
