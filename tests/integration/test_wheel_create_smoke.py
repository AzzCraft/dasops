from __future__ import annotations

import os
import json
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
    # Build from a disposable copy.  A packaging smoke test must not leave
    # build/ or *.egg-info residue in the candidate it is certifying.
    source = tmp_path / "source"
    shutil.copytree(
        DASOPS_ROOT,
        source,
        ignore=shutil.ignore_patterns(
            ".pytest_cache", "__pycache__", "build", "dist", "*.egg-info"
        ),
    )
    wheelhouse = tmp_path / "wheelhouse"
    # The verifier provisions the exact build backend from
    # requirements-verify.txt.  Avoid build isolation here: it would otherwise
    # make the release test depend on a live package index rather than the
    # reviewed, pinned verification environment.
    proc = _run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            ".",
            "--no-build-isolation",
            "--no-deps",
            "-w",
            str(wheelhouse),
        ],
        cwd=source,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    wheels = sorted(wheelhouse.glob("dasops-*.whl"))
    assert wheels, "OPS-001 did not build a dasops wheel"
    target = tmp_path / "wheel-install"
    proc = _run([sys.executable, "-m", "pip", "install", "--no-deps", "--target", str(target), str(wheels[0])], cwd=tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return [sys.executable, "-m", "dasops"], _pythonpath(target)


def test_ops_001_installed_wheel_create_new_change_and_verify_smoke(tmp_path: Path) -> None:
    dasops_cmd, dasops_env = _build_and_install_wheel(tmp_path)
    _probe_installed_candidate_kernel(tmp_path)
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

    proc = _run(["bash", "scripts/verify", "--scope", "scaffold"], cwd=product)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def _probe_installed_candidate_kernel(tmp_path: Path) -> None:
    # Exercise package imports and bundled SQL/schema from outside the source
    # tree with isolated import flags. This temporary development wheel is not
    # the final frozen beta payload or installed product qualification.
    from tests.protected.test_candidate_store import fixture, sha
    from dasops.standards_contracts import exact_json as codec
    source = tmp_path / 'candidate-fixture'; source.mkdir(mode=0o700)
    binding, commit, archive, _ = fixture(source,content={'README.md':(b'installed fixture',False),
        'run.py':(b'print("installed reference")\n',False)})
    inputs = tmp_path / 'candidate-inputs'; inputs.mkdir(mode=0o700)
    (inputs / 'binding').write_bytes(codec.canonical(binding))
    (inputs / 'commit').write_bytes(commit)
    (inputs / 'archive').write_bytes(archive)
    installed = tmp_path / 'wheel-install'
    schemas = {path.name: sha(path.read_bytes())
               for path in (DASOPS_ROOT / 'dasops/standards_contracts').glob('*.schema.json')}
    assert 'bundle_preview_v2.schema.json' in schemas
    program = '''import hashlib,json,sys
from pathlib import Path
from importlib.resources import files
installed,inputs,work=map(Path,sys.argv[1:4]);sys.path.insert(0,str(installed))
import dasops
from dasops.protected.candidates import CandidateStore
from dasops.protected.candidates.versions import VersionTreeManager
from dasops.protected.sqlite.store import CoordinationDatabase,TaskKey
from dasops.standards_contracts import exact_json as codec
assert Path(dasops.__file__).is_relative_to(installed)
for name,digest in json.loads(sys.argv[4]).items():
    actual=files('dasops.standards_contracts').joinpath(name).read_bytes()
    assert 'sha256:'+hashlib.sha256(actual).hexdigest()==digest, 'missing or changed installed contract: '+name
D='sha256:'+'1'*64
def authorized(connection,operation,actor,epoch): return connection.in_transaction and actor=='installed-fixture' and epoch==1
root=work/'installed-candidate-artifacts';root.mkdir(mode=0o700)
control=work/'installed-candidate-control';control.mkdir(mode=0o700)
with CandidateStore(root) as store:
    result=store.receive((inputs/'binding').read_bytes(),commit_bytes=(inputs/'commit').read_bytes(),archive_bytes=(inputs/'archive').read_bytes())
    view=store.prepare_reference_view(result['candidateDigest'])
    assert view['profile']=='das-python-native-reference-view/v1' and len(view['mapping'])==2
    assert (Path(view['viewPath'])/'run.py').read_bytes()==b'print("installed reference")\\n'
    db=CoordinationDatabase.create(control/'state.db',authority_domain='domain',instance_id='fixture')
    try:
        db.create_change('project','change',actor='installed-fixture',now=100,authorize=authorized)
        db.add_task(TaskKey('domain','project','change','task'),D,actor='installed-fixture',now=100,authorize=authorized)
        kernel=VersionTreeManager(db,store,ownership={'tree/README.md':('fixture-owner',D)},tool_digest=D,policy_digest=D)
        kernel.register_candidate(result['candidateDigest'],actor='installed-fixture',now=100,authorize=authorized)
        kernel.install_target('target','instance',result['candidateDigest'],actor='installed-fixture',now=100,authorize=authorized)
        actual=kernel.read_target('target','instance',actor='installed-fixture',now=100,authorize=authorized)
        db.check_integrity()
        print(json.dumps(actual))
    finally: db.close()
'''
    proc = _run([sys.executable,'-I','-c',program,str(installed),str(inputs),str(tmp_path),json.dumps(schemas)],cwd=tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    result = json.loads(proc.stdout)
    assert result['candidateDigest'] == sha(codec.canonical(binding))
    assert result['generation'] == 1 and result['authority'] is False and result['qualification'] is False


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
