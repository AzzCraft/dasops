from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

SUPPORTED_PUBLIC_TIERS = ("oss",)


def build_install_cadence_command(
    *,
    tier: str,
    from_suite: str | None = None,
    git_base: str | None = None,
    org: str | None = None,
    use_ssh: bool = False,
    force: bool = False,
) -> list[str]:
    if tier not in SUPPORTED_PUBLIC_TIERS:
        raise ValueError("Public Cadence installation supports only tier=oss")
    if from_suite and (git_base or org or use_ssh):
        raise ValueError("Choose a local Suite source or a remote source")
    if from_suite:
        suite = Path(from_suite).expanduser().resolve()
        if not suite.is_dir() or not ((suite / "suite_lock.json").is_file() or (suite.parent / "cadence-oss").is_dir()):
            raise ValueError("Local source requires das-suite with sibling cadence-oss")
    elif not (git_base and git_base.strip()) and not (org and org.strip()):
        raise ValueError("Provide --from-suite, --git-base or --org explicitly")
    cmd = ["bash", "./scripts/install_cadence_vendor.sh", "--tier", tier]
    if from_suite:
        cmd.extend(["--from-suite", str(suite)])
    if git_base:
        cmd.extend(["--git-base", git_base])
    if org:
        cmd.extend(["--org", org])
    if use_ssh:
        cmd.append("--ssh")
    if force:
        cmd.append("--force")
    return cmd


def load_vendor_lock(path: str | Path) -> dict[str, Any]:
    """Load a tooling_lock.json as vendor specification."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def validate_vendor_integrity(
    vendor_lock: dict[str, Any],
    installed_artifacts: dict[str, str],
) -> list[str]:
    """Verify installed versions match vendor lock pins.

    Returns a list of drift descriptions (empty if all match).
    """
    drifts: list[str] = []
    if "sourceOfTruth" in vendor_lock or "verifyRuntime" in vendor_lock:
        runtime = vendor_lock.get("verifyRuntime")
        if not isinstance(runtime, dict) or not runtime.get("pinValue"):
            return ["Standard lock requires a fixed verifyRuntime"]
        if installed_artifacts.get("verifyRuntime") != runtime:
            return ["Standard runtime requires verified installed source, binary and resources"]
        return []
    pins = vendor_lock.get("pins", vendor_lock.get("components"))
    if not isinstance(pins, dict) or not pins:
        return ["unsupported or empty vendor lock contract"]
    for name, expected_version in pins.items():
        actual = installed_artifacts.get(name)
        if actual is None:
            drifts.append(f"{name}: not installed (expected {expected_version})")
        elif actual != expected_version:
            drifts.append(f"{name}: installed {actual}, expected {expected_version}")
    return drifts


def enforce_vendor_lock(repo_root: str | Path) -> list[str]:
    """Check that repo's tooling_lock.json matches installed artifacts.

    Returns list of drift messages (empty = compliant).
    """
    lock_path = Path(repo_root) / "tooling_lock.json"
    if not lock_path.exists():
        return ["tooling_lock.json not found"]
    vendor_lock = load_vendor_lock(lock_path)
    if vendor_lock.get("standardManifestVersion") == "1.5.0-beta.1":
        from .scaffold_v15 import STATE, installed as check_installed, load
        try:
            root = Path(repo_root).resolve()
            selected_runtime = load(root / STATE)["selectedSources"]["runtime"]
            if vendor_lock.get("verifyRuntime") != selected_runtime:
                return ["tooling_lock.json verifyRuntime differs from selected Suite runtime"]
            check_installed(root)
            return []
        except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as exc:
            return [str(exc)]
    installed = _detect_installed(repo_root)
    return validate_vendor_integrity(vendor_lock, installed)


def _detect_installed(repo_root: str | Path) -> dict[str, str]:
    """Detect installed tool versions from VERSION files and markers."""
    installed: dict[str, str] = {}
    version_file = Path(repo_root) / "VERSION"
    if version_file.exists():
        installed["self"] = version_file.read_text().strip()
    cadence_dir = Path(repo_root) / ".cadence"
    if cadence_dir.is_dir():
        for marker in cadence_dir.glob("*.version"):
            name = marker.stem
            installed[name] = marker.read_text().strip()
    return installed
