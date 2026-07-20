from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from tests._root_contract import repository_root_for_test_file

REPO_ROOT = repository_root_for_test_file(__file__)
DASOPS_ROOT = REPO_ROOT


def _run(
    cmd: list[str],
    *,
    cwd: Path,
    timeout: int = 120,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    run_env = os.environ.copy()
    run_env["PYTHONDONTWRITEBYTECODE"] = "1"
    if env:
        run_env.update(env)
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=run_env)


def _pythonpath(*paths: Path) -> dict[str, str]:
    env = os.environ.copy()
    existing = env.get("PYTHONPATH", "")
    value = os.pathsep.join(str(path) for path in paths)
    if existing:
        value = value + os.pathsep + existing
    return {"PYTHONPATH": value}


def _write_product_inputs(root: Path) -> tuple[Path, Path]:
    master = root / "master_doc.md"
    ui_spec = root / "ui_spec.md"
    master.write_text(
        "\n".join(
            [
                "# Product Master Doc",
                "## Conformance profile",
                "## Repo topology",
                "## Contracts",
                "## Traceability",
                "## Verification",
                "## Execution plan",
                "",
            ]
        ),
        encoding="utf-8",
    )
    ui_spec.write_text("# UI Spec\n\nNo UI for this smoke fixture.\n", encoding="utf-8")
    return master, ui_spec


def _build_and_install_wheel(tmp_path: Path) -> tuple[list[str], dict[str, str]]:
    wheelhouse = tmp_path / "wheelhouse"
    try:
        proc = _run(
            [sys.executable, "-m", "pip", "wheel", ".", "--no-deps", "--no-build-isolation", "-w", str(wheelhouse)],
            cwd=DASOPS_ROOT,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        wheels = sorted(wheelhouse.glob("dasops-*.whl"))
        assert wheels, "OPS-001 did not build a dasops wheel"
        target = tmp_path / "wheel-install"
        proc = _run([sys.executable, "-m", "pip", "install", "--no-deps", "--target", str(target), str(wheels[0])], cwd=tmp_path)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        return [sys.executable, "-m", "dasops"], _pythonpath(target)
    finally:
        # Legacy setuptools leaves these ignored paths in the source checkout.
        # A verifier must leave an export candidate unchanged before it is
        # archived, even when the wheel command itself fails.
        for residue in ("build", "dasops.egg-info", "UNKNOWN.egg-info"):
            shutil.rmtree(DASOPS_ROOT / residue, ignore_errors=True)


def test_ops_001_installed_wheel_create_new_change_and_verify_smoke(tmp_path: Path) -> None:
    dasops_cmd, dasops_env = _build_and_install_wheel(tmp_path)
    master_doc, ui_spec = _write_product_inputs(tmp_path)
    product = tmp_path / "product"

    proc = _run(
        [
            *dasops_cmd,
            "create",
            "--dest",
            str(product),
            "--master-doc",
            str(master_doc),
            "--ui-spec",
            str(ui_spec),
            "--change-id",
            "initial",
            "--intent",
            "OPS-001 wheel smoke",
            "--change-empty",
        ],
        cwd=tmp_path,
        env=dasops_env,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (product / "scripts" / "verify").is_file()
    assert (product / "openspec" / "changes" / "initial" / "CHANGE.md").is_file()

    proc = _run(
        [
            *dasops_cmd,
            "new-change",
            "--id",
            "smoke",
            "--intent",
            "post-install smoke",
            "--repo-root",
            str(product),
        ],
        cwd=tmp_path,
        env=dasops_env,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (product / "openspec" / "changes" / "smoke" / "tasks.md").is_file()

    proc = _run(["bash", "scripts/verify"], cwd=product)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_ops_001_missing_factory_template_names_broken_create_command(tmp_path: Path) -> None:
    master_doc, ui_spec = _write_product_inputs(tmp_path)
    empty_factory = tmp_path / "empty-factory"
    empty_factory.mkdir()

    proc = _run(
        [
            sys.executable,
            "-m",
            "dasops",
            "create",
            "--dest",
            str(tmp_path / "product"),
            "--master-doc",
            str(master_doc),
            "--ui-spec",
            str(ui_spec),
            "--factory-root",
            str(empty_factory),
            "--no-git",
        ],
        cwd=REPO_ROOT,
        env=_pythonpath(DASOPS_ROOT),
    )

    output = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "OPS-001" in output
    assert "dasops create" in output
    assert "templates/das-product" in output
