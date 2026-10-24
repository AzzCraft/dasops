from __future__ import annotations

from .task_markdown import table_rows, task_files

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml


LOCK_KEYS = {
    "version",
    "taskId",
    "owner",
    "status",
    "claimedAt",
    "updatedAt",
    "heartbeatAt",
    "leaseSeconds",
    "lockToken",
}
TASK_ALLOWED_STATUSES = {"TODO", "IN_PROGRESS", "DONE", "BLOCKED", "PROPOSED"}
TOOLING_LOCK_REQUIRED_KEYS = {
    "schemaVersion",
    "standardManifestVersion",
    "sourceOfTruth",
    "verifyRuntime",
    "suiteVersionClosureRef",
    "suiteLockRef",
    "verifyRegistryRef",
    "toolchain",
}
TOOLING_LOCK_REF_KEYS = {"kind", "uri", "pinType", "pinValue", "floating"}
EXTENSION_MANIFEST_REQUIRED_KEYS = {"schemaVersion", "standardManifestVersion", "extensions"}
EXTENSION_MANIFEST_EXTENSION_KEYS = {"name", "compatibilityNote", "reviewDate"}


@dataclass(frozen=True)
class DoctorReport:
    repo_root: Path
    repo_type: str
    problems: list[str]
    warnings: list[str]


def _validate_tooling_ref(
    *,
    problems: list[str],
    payload: object,
    ref_key: str,
    expected_kind: str,
    expected_uri_fragment: str | None = None,
) -> None:
    if not isinstance(payload, dict):
        problems.append(f"tooling_lock.json {ref_key} must be an object")
        return
    ref_missing = sorted(TOOLING_LOCK_REF_KEYS - set(payload))
    if ref_missing:
        problems.append(f"tooling_lock.json {ref_key} missing keys: {ref_missing}")
    observed_kind = payload.get("kind")
    if observed_kind != expected_kind:
        problems.append(
            f"tooling_lock.json {ref_key}.kind must be {expected_kind!r} (observed {observed_kind!r})"
        )
    if expected_uri_fragment:
        observed_uri = str(payload.get("uri", "")).strip()
        if expected_uri_fragment not in observed_uri:
            problems.append(
                f"tooling_lock.json {ref_key}.uri must include {expected_uri_fragment!r}"
            )


def run_doctor(repo_root: Path) -> DoctorReport:
    problems: list[str] = []
    warnings: list[str] = []

    is_product_repo = (repo_root / ".dasops_product_repo").exists()
    is_factory_repo = (repo_root / ".dasops_factory_repo").exists()

    if not is_product_repo and not is_factory_repo:
        raise SystemExit(
            "dasops doctor: could not detect a DASOPS repo in this directory.\n"
            "Expected one of: .dasops_product_repo or .dasops_factory_repo\n"
            f"Checked: {repo_root}"
        )

    repo_type = "product" if is_product_repo else "factory"

    if is_product_repo and (repo_root / ".dasops-scaffold.json").is_file():
        from .scaffold_v15 import verify
        result = verify(repo_root, scope="scaffold")
        pending = result["pendingItems"]
        runtime_problems = [p for p in pending if p.startswith("runtime:")]
        return DoctorReport(repo_root, "product", result["problems"] + runtime_problems,
                            [p for p in pending if p not in runtime_problems])

    if is_product_repo:
        required = [
            repo_root / "docs" / "master_doc.md",
            repo_root / "docs" / "ui_spec.md",
            repo_root / "docs" / "USER_MANUAL.md",
            repo_root / "docs" / "policies" / "AGENT_OPERATING_MODEL.md",
            repo_root / "AGENTS.override.md",
            repo_root / "CLAUDE.md",
            repo_root / "progress.txt",
            repo_root / "STANDARD_REF.md",
            repo_root / "tooling_lock.json",
            repo_root / "local_extension_manifest.json",
            repo_root / "openspec" / "config.yaml",
        ]
        for path in required:
            if not path.exists():
                problems.append(f"Missing required file: {path.relative_to(repo_root)}")

        legacy_standard = repo_root / "docs" / "standards" / "DAS_STANDARD.md"
        if legacy_standard.exists():
            problems.append("Found copied standard doc. Use STANDARD_REF.md instead.")

        cfg_path = repo_root / "openspec" / "config.yaml"
        if cfg_path.exists():
            try:
                cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
                schema = str(cfg.get("schema", "")).strip()
                if schema and schema != "das-standard":
                    warnings.append(
                        f"openspec/config.yaml schema is '{schema}' (expected 'das-standard')"
                    )
            except Exception as exc:
                warnings.append(f"Could not parse openspec/config.yaml: {exc}")

        if (repo_root / "docs" / "deltas").exists():
            problems.append(
                "Found docs/deltas/. Use openspec/changes/<change-id>/ instead (deterministic)."
            )

        stray_tasks: list[Path] = []
        for path in task_files(repo_root):
            rel = path.relative_to(repo_root)
            allowed = (
                len(rel.parts) == 4
                and rel.parts[0] == "openspec"
                and rel.parts[1] == "changes"
                and rel.parts[3] == "tasks.md"
            ) or rel.parts[:2] == ("openspec", "schemas")
            if not allowed:
                stray_tasks.append(rel)
        if stray_tasks:
            problems.append(
                "Found stray tasks.md outside openspec/changes/<change-id>/tasks.md:\n  - "
                + "\n  - ".join(str(path) for path in sorted(stray_tasks))
            )

        # JSON schema validation: tooling_lock.json
        tl_path = repo_root / "tooling_lock.json"
        if tl_path.exists():
            try:
                tl_data = json.loads(tl_path.read_text(encoding="utf-8"))
                from jsonschema import Draft202012Validator
                from referencing import Registry
                from .repo_factory import default_factory_root
                schema_path = repo_root / "openspec/schemas/das-standard/tooling_lock.schema.json"
                if not schema_path.exists():
                    schema_path = default_factory_root() / "templates/das-product/openspec/schemas/das-standard/tooling_lock.schema.json"
                try:
                    schema = json.loads(schema_path.read_text())
                    Draft202012Validator.check_schema(schema)
                    Draft202012Validator(schema, registry=Registry()).validate(tl_data)
                except Exception as exc:
                    problems.append(f"tooling_lock.json schema validation failed: {exc}")
                if not isinstance(tl_data, dict):
                    problems.append("tooling_lock.json root must be an object")
                else:
                    tl_missing = sorted(TOOLING_LOCK_REQUIRED_KEYS - set(tl_data))
                    if tl_missing:
                        problems.append(f"tooling_lock.json missing required keys: {tl_missing}")
                    _validate_tooling_ref(
                        problems=problems,
                        payload=tl_data.get("sourceOfTruth"),
                        ref_key="sourceOfTruth",
                        expected_kind="git",
                    )
                    # Reject unresolved pinValue in sourceOfTruth
                    sot = tl_data.get("sourceOfTruth", {})
                    if isinstance(sot, dict):
                        pin_state = str(sot.get("pinState", "")).strip().lower()
                        pin_type = str(sot.get("pinType", "")).strip()
                        pin = str(sot.get("pinValue", "")).strip()
                        if pin_state == "pending" and not pin:
                            problems.append(
                                "tooling_lock.json sourceOfTruth.pinState is pending; sourceOfTruth.pinValue must be a real git commit"
                            )
                        if sot.get("kind") == "git" and pin_type not in {"commit", "tag"}:
                            problems.append(
                                f"tooling_lock.json sourceOfTruth.pinType must be 'commit' or 'tag' (observed {pin_type!r})"
                            )
                        _UNRESOLVED_PINS = ("replace-with-product-commit", "fake-sha256", "tbd", "todo", "placeholder", "")
                        if pin.lower() in _UNRESOLVED_PINS:
                            problems.append(f"tooling_lock.json sourceOfTruth.pinValue is unresolved: {pin!r}")
                        if pin_type == "commit" and pin and not re.fullmatch(r"[0-9a-f]{7,40}", pin):
                            problems.append(
                                f"tooling_lock.json sourceOfTruth.pinValue must be a git commit hash: {pin!r}"
                            )
                    _validate_tooling_ref(
                        problems=problems,
                        payload=tl_data.get("verifyRuntime"),
                        ref_key="verifyRuntime",
                        expected_kind="package",
                    )
                    _validate_tooling_ref(
                        problems=problems,
                        payload=tl_data.get("suiteVersionClosureRef"),
                        ref_key="suiteVersionClosureRef",
                        expected_kind="file",
                        expected_uri_fragment="suite_version_closure.json",
                    )
                    _validate_tooling_ref(
                        problems=problems,
                        payload=tl_data.get("suiteLockRef"),
                        ref_key="suiteLockRef",
                        expected_kind="file",
                        expected_uri_fragment="suite_lock.json",
                    )
                    _validate_tooling_ref(
                        problems=problems,
                        payload=tl_data.get("verifyRegistryRef"),
                        ref_key="verifyRegistryRef",
                        expected_kind="file",
                        expected_uri_fragment="cadence-registry/registry.json",
                    )
                    toolchain = tl_data.get("toolchain")
                    if not isinstance(toolchain, list) or not toolchain:
                        problems.append(
                            "tooling_lock.json toolchain must be a non-empty array"
                        )
                    elif any(not isinstance(item, dict) for item in toolchain):
                        problems.append(
                            "tooling_lock.json toolchain entries must be objects"
                        )
            except (json.JSONDecodeError, ValueError) as exc:
                problems.append(f"tooling_lock.json is not valid JSON: {exc}")

        # JSON schema validation: local_extension_manifest.json
        em_path = repo_root / "local_extension_manifest.json"
        if em_path.exists():
            try:
                em_data = json.loads(em_path.read_text(encoding="utf-8"))
                if not isinstance(em_data, dict):
                    problems.append("local_extension_manifest.json root must be an object")
                else:
                    em_missing = sorted(EXTENSION_MANIFEST_REQUIRED_KEYS - set(em_data))
                    if em_missing:
                        problems.append(
                            f"local_extension_manifest.json missing required keys: {em_missing}"
                        )
                    if "extensions" in em_data:
                        extensions = em_data["extensions"]
                        if not isinstance(extensions, list):
                            problems.append(
                                "local_extension_manifest.json extensions must be an array"
                            )
                        elif not extensions:
                            problems.append(
                                "local_extension_manifest.json must declare at least one project-local extension"
                            )
                        else:
                            for index, item in enumerate(extensions):
                                if not isinstance(item, dict):
                                    problems.append(
                                        f"local_extension_manifest.json extension[{index}] must be an object"
                                    )
                                    continue
                                missing_keys = sorted(
                                    key for key in EXTENSION_MANIFEST_EXTENSION_KEYS if not item.get(key)
                                )
                                if missing_keys:
                                    problems.append(
                                        f"local_extension_manifest.json extension[{index}] missing keys: {missing_keys}"
                                    )
            except (json.JSONDecodeError, ValueError) as exc:
                problems.append(f"local_extension_manifest.json is not valid JSON: {exc}")

        # One guarded canonical snapshot per change; no nested per-lock reads.
        from . import legacy_task_state as state
        from .locks import _snapshot, is_stale
        changes_dir = repo_root / "openspec" / "changes"
        if changes_dir.is_symlink():
            problems.append("Invalid task changes directory")
        elif changes_dir.exists():
            for change in sorted(changes_dir.iterdir()):
                try:
                    if change.is_symlink():
                        raise state.StateError("invalid_state_directory")
                    if not change.is_dir():
                        continue
                    if not (change / "tasks.md").exists() and not (change / "task_locks").exists():
                        continue
                    with state.guard(change):
                        _, rows, locks = _snapshot(change)
                    for lock in locks.values():
                        if lock.status == "IN_PROGRESS" and is_stale(lock):
                            warnings.append(f"Stale IN_PROGRESS lock: {change.name}/{lock.task_id}")
                    for row in rows.values():
                        if row.status not in TASK_ALLOWED_STATUSES:
                            problems.append(f"Invalid task status: {change.name}/{row.task_id}")
                        if not row.verify_gate.strip(" `") or row.verify_gate.strip(" `") == "-":
                            problems.append(f"Missing verify gate: {change.name}/{row.task_id}")
                except (state.StateError, ValueError, OSError) as exc:
                    problems.append(f"Invalid task state {change.relative_to(repo_root)}: {exc}")

    if is_factory_repo:
        if not (repo_root / "dasops" / "__main__.py").exists():
            problems.append("Missing dasops/__main__.py")
        if not (repo_root / "templates" / "das-product").exists():
            problems.append("Missing templates/das-product")

    return DoctorReport(
        repo_root=repo_root,
        repo_type=repo_type,
        problems=problems,
        warnings=warnings,
    )
