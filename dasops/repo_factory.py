from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import date
from pathlib import Path
from typing import Optional


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

    dest_dir = dest_dir.expanduser().resolve()
    if dest_dir.exists() and any(dest_dir.iterdir()):
        if not overwrite:
            raise SystemExit(
                f"Destination directory is not empty: {dest_dir}\n"
                "Refusing to overwrite. Use --overwrite if you really want this."
            )
    else:
        dest_dir.mkdir(parents=True, exist_ok=True)

    shutil.copytree(template_dir, dest_dir, dirs_exist_ok=True)

    seed_machine_readable_artifacts(dest_dir)

    init_repo(
        repo_root=dest_dir,
        master_doc_path=master_doc_path,
        ui_spec_path=ui_spec_path,
    )

    if change_id:
        new_change(
            repo_root=dest_dir,
            change_id=change_id,
            intent=intent,
            empty=change_empty,
        )

    marker = dest_dir / ".dasops_product_repo"
    if not marker.exists():
        marker.write_text(
            "This is a DAS + OpenSpec PRODUCT repo generated by dasops.\n"
            "Work here (run verify, implement tasks, etc.).\n",
            encoding="utf-8",
        )

    ensure_product_repo_permissions(dest_dir)

    if init_git:
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
    ui_spec_path: Path,
    change_id: Optional[str] = None,
    intent: str = "",
    init_git: bool = True,
    overwrite: bool = False,
    change_empty: bool = False,
) -> Path:
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
    if not lock_path.exists() or not (repo_root / ".git").exists():
        return None
    try:
        bootstrap_commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    sot = lock.get("sourceOfTruth", {})
    if not isinstance(sot, dict):
        return None
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
                ],
                cwd=str(repo_root),
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
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
            check=False,
        )
    except FileNotFoundError:
        return
    except Exception:
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
    docs_dir = repo_root / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)

    if master_doc_path is not None:
        master_doc_bytes = master_doc_path.read_bytes()
    if ui_spec_path is not None:
        ui_spec_bytes = ui_spec_path.read_bytes()

    if master_doc_bytes is None:
        raise ValueError("master_doc missing: provide --master-doc or master_doc_bytes")
    if ui_spec_bytes is None:
        raise ValueError("ui_spec missing: provide --ui-spec or ui_spec_bytes")

    (docs_dir / "master_doc.md").write_bytes(master_doc_bytes)
    (docs_dir / "ui_spec.md").write_bytes(ui_spec_bytes)

    if change_id:
        new_change(repo_root=repo_root, change_id=change_id, intent=change_intent or "")


def new_change(repo_root: Path, change_id: str, intent: str = "", *, empty: bool = False) -> Path:
    if not change_id or ".." in change_id.split("/") or "/" in change_id or "\\" in change_id:
        raise SystemExit(f"Invalid change_id: {change_id!r} (must not contain path separators or '..')")
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
