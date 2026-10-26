"""Tests for dasops.vendor — lock enforcement."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from dasops.vendor import load_vendor_lock, validate_vendor_integrity, enforce_vendor_lock


class TestVendorLock(unittest.TestCase):
    def test_load_vendor_lock(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "tooling_lock.json"
            p.write_text(json.dumps({"schemaVersion": "1.0.0", "pins": {"cadence": "1.0.0"}}))
            lock = load_vendor_lock(p)
            self.assertEqual(lock["pins"]["cadence"], "1.0.0")

    def test_validate_no_drift(self):
        lock = {"pins": {"cadence": "1.0.0"}}
        installed = {"cadence": "1.0.0"}
        drifts = validate_vendor_integrity(lock, installed)
        self.assertEqual(drifts, [])

    def test_validate_detects_version_drift(self):
        lock = {"pins": {"cadence": "1.0.0"}}
        installed = {"cadence": "2.0.0"}
        drifts = validate_vendor_integrity(lock, installed)
        self.assertEqual(len(drifts), 1)
        self.assertIn("expected 1.0.0", drifts[0])

    def test_validate_detects_missing_install(self):
        lock = {"pins": {"cadence": "1.0.0"}}
        installed = {}
        drifts = validate_vendor_integrity(lock, installed)
        self.assertEqual(len(drifts), 1)
        self.assertIn("not installed", drifts[0])

    def test_enforce_missing_lock(self):
        with tempfile.TemporaryDirectory() as d:
            drifts = enforce_vendor_lock(d)
            self.assertEqual(len(drifts), 1)
            self.assertIn("not found", drifts[0])

    def test_v15_enforcement_binds_lock_and_reports_observer_failures(self):
        import subprocess
        from unittest.mock import patch

        runtime = {"kind": "git", "uri": "https://github.com/AzzCraft/cadence-oss.git",
                   "pinType": "commit", "pinValue": "a" * 40, "floating": False}
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / ".dasops-scaffold.json").write_text(json.dumps({"selectedSources": {"runtime": runtime}}))
            lock = {"standardManifestVersion": "1.5.0-beta.1", "verifyRuntime": runtime}
            lock_path = root / "tooling_lock.json"
            lock_path.write_text(json.dumps(lock))
            # The installed observer is independently exercised by native integration;
            # this unit check proves it cannot substitute for comparing the input lock.
            with patch("dasops.scaffold_v15.installed") as observer:
                self.assertEqual(enforce_vendor_lock(root), [])
                observer.assert_called_once_with(root)
                observer.reset_mock()
                for changed in ({**runtime, "pinValue": "b" * 40},
                                {**runtime, "uri": "https://github.com/AzzCraft/other.git"}, None):
                    with self.subTest(runtime=changed):
                        lock_path.write_text(json.dumps({**lock, "verifyRuntime": changed}))
                        self.assertIn("differs from selected Suite runtime", enforce_vendor_lock(root)[0])
                        observer.assert_not_called()
            lock_path.write_text(json.dumps(lock))
            with patch("dasops.scaffold_v15.installed", side_effect=subprocess.TimeoutExpired("cadence", 10)):
                self.assertTrue(enforce_vendor_lock(root))


if __name__ == "__main__":
    unittest.main()


def _legacy_fixture(tmp_path, monkeypatch):
    import os
    import subprocess
    import sys
    from tests.test_template_verify_frontend import copy_template_repo
    product = copy_template_repo(str(tmp_path))
    release = tmp_path / 'release'; suite = release / 'das-suite'; suite.mkdir(parents=True)
    source = release / 'cadence-oss'; (source / 'cadence-core/cmd/cadence').mkdir(parents=True)
    (source / 'VERSION').write_text('1.5.0-beta.1\n')
    (source / 'resource.json').write_text('{}\n')
    for name in ('LICENSE','NOTICE','THIRD_PARTY_NOTICES.md'):
        (source/name).write_text('fixture\n')
    (source/'cadence-registry').mkdir()
    from hashlib import sha256
    (source/'cadence-registry/registry.json').write_text(json.dumps({'registryId':'fixture','entries':[
        {'id':'fixture','ref':'../resource.json','digest':'sha256:'+sha256(b'{}\n').hexdigest()}]}))
    # A controlled native stand-in tests installation/error plumbing; the
    # integration test separately builds and observes the real Cadence binary.
    (source / 'cadence-core/cmd/cadence/fixture.py').write_text(
        f'#!{sys.executable}\n'
        'import hashlib,json,os,sys,time\nfrom pathlib import Path\n'
        'if sys.argv[1:]==["version","--json"]:\n'
        ' print(json.dumps(dict(sourceRevision="COMMIT",sourceModified=False,releaseVersion="1.5.0-beta.1",binarySha256="sha256:"+hashlib.sha256(Path(__file__).read_bytes()).hexdigest())))\n'
        'else:\n Path("native-called").write_text(" ".join(sys.argv[1:]))\n'
        ' if os.environ.get("FIXTURE_WAIT"):\n  while not Path("native-release").exists(): time.sleep(0.01)\n'
        ' sys.exit(int(os.environ.get("FIXTURE_NATIVE_EXIT","0")))\n')
    def git(*args):
        return subprocess.check_output(['git','-C',str(source),*args],stderr=subprocess.PIPE).decode().strip()
    git('init','-q'); git('add','.')
    git('-c','user.name=fixture','-c','user.email=fixture@example.invalid','commit','-qm','selected source')
    commit = git('rev-parse','HEAD')
    lock_path=product/'tooling_lock.json';lock=json.loads(lock_path.read_text())
    lock['verifyRuntime']={'kind':'git','uri':'./vendor/cadence/cadence-oss','pinType':'commit','pinValue':commit,'floating':False}
    lock_path.write_text(json.dumps(lock))
    tools = tmp_path / 'tools'; tools.mkdir()
    go = tools / 'go'
    go.write_text(f'#!{sys.executable}\n'+
        'import os,subprocess,sys\nfrom pathlib import Path\n'
        'if os.environ.get("FIXTURE_BUILD_FAIL"): sys.exit(7)\n'
        'commit=subprocess.check_output(["git","rev-parse","HEAD"],text=True).strip()\n'
        'if os.environ.get("FIXTURE_IDENTITY_FAIL"): commit="0"*40\n'
        'out=Path(sys.argv[sys.argv.index("-o")+1])\n'
        'out.write_text(Path("cmd/cadence/fixture.py").read_text().replace("COMMIT",commit));out.chmod(0o755)\n')
    go.chmod(0o755)
    global_bin = tools / 'cadence'
    global_bin.write_text('#!/bin/sh\nprintf called > "'+str(tmp_path/'global-called')+'"\nexit 0\n')
    global_bin.chmod(0o755)
    monkeypatch.setenv('PATH',str(tools)+os.pathsep+os.environ['PATH'])
    def run(*args):
        return subprocess.run(list(args),cwd=product,text=True,capture_output=True)
    return product,suite,source,commit,run,git


def test_vendor_failures_preserve_previous_and_relative_source(tmp_path, monkeypatch):
    from dasops.vendor import build_install_cadence_command
    author = Path(__file__).resolve().parents[1]
    assert (author/'dasops/legacy_runtime.py').read_bytes() == (author/'templates/das-product/scripts/cadence_runtime.py').read_bytes()
    product,suite,source,commit,run,git = _legacy_fixture(tmp_path,monkeypatch)
    install = ['bash','scripts/install_cadence_vendor.sh','--from-suite',str(suite)]
    assert run(*install).returncode != 0
    assert not (product/'vendor/cadence').exists()
    old = product/'vendor/cadence';old.mkdir();(old/'sentinel').write_text('old')
    for bad in ('main','abc','0'*40):
        assert run(*install,'--commit',bad,'--force').returncode != 0
        assert (old/'sentinel').read_text() == 'old'
    for fault in ('FIXTURE_BUILD_FAIL','FIXTURE_IDENTITY_FAIL'):
        monkeypatch.setenv(fault,'1')
        assert run(*install,'--commit',commit,'--force').returncode != 0
        assert (old/'sentinel').read_text() == 'old'
        monkeypatch.delenv(fault)
    # A newer HEAD and uncommitted content must not replace the selected commit.
    (source/'resource.json').write_text('{"later":true}\n');git('add','.')
    git('-c','user.name=fixture','-c','user.email=fixture@example.invalid','commit','-qm','later source')
    (source/'resource.json').write_text('dirty\n')
    monkeypatch.chdir(tmp_path)
    command=build_install_cadence_command(tier='oss',from_suite='release/das-suite',commit=commit,force=True)
    assert Path(command[command.index('--from-suite')+1]).is_absolute()
    done=run(*command)
    assert done.returncode == 0,done.stdout+done.stderr
    assert (old/'cadence-oss/resource.json').read_text() == '{}\n'
    assert not (old/'sentinel').exists()
    assert not (old/'cadence-oss/.git').exists()
    assert not (old/'cadence-oss/cadence-core').exists()
    assert not list((product/'vendor').glob('.cadence-install.*'))
    assert run('./cadencew','version','--json').returncode == 0
    assert not (tmp_path/'global-called').exists()
    # The remote-source route must checkout the same exact commit too.
    git('clone','--bare',str(source),str(suite.parent/'cadence-oss.git'))
    cloned=run('bash','scripts/install_cadence_vendor.sh','--git-base',str(suite.parent),'--commit',commit,'--force')
    assert cloned.returncode == 0,cloned.stdout+cloned.stderr
    assert (old/'cadence-oss/resource.json').read_text() == '{}\n'


def test_legacy_runtime_and_scope_fail_closed_with_recovery(tmp_path, monkeypatch):
    product,suite,source,commit,run,git = _legacy_fixture(tmp_path,monkeypatch)
    wrapper=run('./cadencew','version')
    assert wrapper.returncode != 0 and not (tmp_path/'global-called').exists()
    for scope in ([],['--scope','full']):
        checked=run('bash','scripts/verify',*scope)
        assert checked.returncode != 0 and 'installed fixed Cadence' in checked.stdout
    structure=run('bash','scripts/verify','--scope','scaffold')
    assert structure.returncode == 0 and 'Cadence execution pending' in structure.stdout
    install=['bash','scripts/install_cadence_vendor.sh','--from-suite',str(suite),'--commit',commit]
    done=run(*install);assert done.returncode == 0,done.stdout+done.stderr
    assert enforce_vendor_lock(product) == []
    checked=run('bash','scripts/verify')
    assert checked.returncode == 0,checked.stdout+checked.stderr
    assert (product/'native-called').read_text() == 'verify --profile dev'
    monkeypatch.setenv('FIXTURE_NATIVE_EXIT','9')
    failed=run('bash','scripts/verify')
    assert failed.returncode != 0 and 'Full checks passed' not in failed.stdout
    monkeypatch.delenv('FIXTURE_NATIVE_EXIT')
    base=product/'vendor/cadence'
    for target in (base/'.cadence/bin/cadence',base/'cadence-oss/resource.json',product/'tooling_lock.json'):
        original=target.read_bytes()
        if target.name=='tooling_lock.json':
            data=json.loads(original);data['verifyRuntime']['pinValue']='other';target.write_text(json.dumps(data))
        else:target.write_bytes(original+b'changed\n')
        assert run('./cadencew','version','--json').returncode != 0
        assert enforce_vendor_lock(product)
        assert not (tmp_path/'global-called').exists()
        target.write_bytes(original)
        assert run('./cadencew','version','--json').returncode == 0
    recovered=run(*install,'--force')
    assert recovered.returncode == 0,recovered.stdout+recovered.stderr
    assert run('bash','scripts/verify').returncode == 0
    assert not list((product/'vendor').glob('.cadence-install.*'))
    resource=base/'cadence-oss/resource.json';content=resource.read_bytes()
    external=tmp_path/'external.json';external.write_bytes(content)
    resource.unlink();resource.symlink_to(external)
    assert run('./cadencew','version','--json').returncode != 0
    resource.unlink();resource.write_bytes(content)
    assert run('./cadencew','version','--json').returncode == 0


def test_legacy_install_rejects_mismatched_declared_commit(tmp_path, monkeypatch):
    product,suite,source,commit,run,git = _legacy_fixture(tmp_path,monkeypatch)
    path=product/'tooling_lock.json';lock=json.loads(path.read_text())
    lock['verifyRuntime']={'kind':'git','uri':str(source),'pinType':'commit','pinValue':'0'*40,'floating':False}
    path.write_text(json.dumps(lock));before=path.read_bytes()
    old=product/'vendor/cadence';old.mkdir();(old/'sentinel').write_text('old')
    result=run('bash','scripts/install_cadence_vendor.sh','--from-suite',str(suite),'--commit',commit,'--force')
    assert result.returncode!=0, 'mismatched runtime declaration installed successfully'
    assert (old/'sentinel').read_text()=='old' and path.read_bytes()==before


def test_legacy_publication_failure_preserves_backup(tmp_path, monkeypatch):
    import shutil
    import sys
    product,suite,source,commit,run,git = _legacy_fixture(tmp_path,monkeypatch)
    old=product/'vendor/cadence';old.mkdir();(old/'sentinel').write_text('old')
    real_mv=shutil.which('mv')
    shim=tmp_path/'tools/mv'
    shim.write_text(f'#!{sys.executable}\n'+
        'import os,sys\nfrom pathlib import Path\n'
        'if any(arg.endswith("/new") for arg in sys.argv[1:]):\n'
        ' target=Path(sys.argv[-1]);target.mkdir();(target/"foreign").write_text("keep");sys.exit(1)\n'
        f'os.execv({real_mv!r},[{real_mv!r},*sys.argv[1:]])\n')
    shim.chmod(0o755)
    result=run('bash','scripts/install_cadence_vendor.sh','--from-suite',str(suite),'--commit',commit,'--force')
    assert result.returncode!=0
    assert (old/'foreign').read_text()=='keep'
    backups=list((product/'vendor').glob('.cadence-install.*/previous/sentinel'))
    assert len(backups)==1 and backups[0].read_text()=='old', 'previous install was destroyed during failed publication'


def test_vendor_observer_reports_malformed_lock(tmp_path):
    for raw in ('[]','null','{','{"standardManifestVersion":"1.4.0","standardManifestVersion":"1.5.0-beta.1"}'):
        (tmp_path/'tooling_lock.json').write_text(raw)
        try:result=enforce_vendor_lock(tmp_path)
        except Exception as exc:raise AssertionError('public observer leaked '+type(exc).__name__) from exc
        assert result and isinstance(result[0],str)


def test_runtime_read_guard_survives_exec_and_serializes_install(tmp_path, monkeypatch):
    import fcntl
    import os
    import subprocess
    import time
    product,suite,source,commit,run,git = _legacy_fixture(tmp_path,monkeypatch)
    command=['bash','scripts/install_cadence_vendor.sh','--from-suite',str(suite),'--commit',commit]
    result=run(*command);assert result.returncode==0,result.stderr
    child=subprocess.Popen(['./cadencew','verify'],cwd=product,env={**os.environ,'FIXTURE_WAIT':'1'},stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    writer=None
    try:
        limit=time.monotonic()+5
        while not (product/'native-called').exists() and child.poll() is None and time.monotonic()<limit:
            time.sleep(0.01)
        assert (product/'native-called').exists(),child.communicate(timeout=1)
        with (product/'.cadence/tmp/install.guard').open('r+b') as guard:
            try:fcntl.flock(guard.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:pass
            else:raise AssertionError('reader released guard before native execution ended')
        writer=subprocess.Popen([*command,'--force'],cwd=product,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:writer.wait(timeout=0.2)
        except subprocess.TimeoutExpired:pass
        else:raise AssertionError('replacement did not wait for native reader')
        (product/'native-release').write_text('continue')
        output=child.communicate(timeout=5);assert child.returncode==0,output
        output=writer.communicate(timeout=10);assert writer.returncode==0,output
        assert run('./cadencew','version','--json').returncode==0
    finally:
        (product/'native-release').write_text('continue')
        for process in (child,writer):
            if process is not None and process.poll() is None:
                process.kill();process.communicate(timeout=5)


def test_native_identity_requires_literal_false(tmp_path, monkeypatch):
    import hashlib
    from types import SimpleNamespace
    from dasops import legacy_runtime as legacy, scaffold_v15 as modern
    import pytest
    binary=tmp_path/'cadence';binary.write_bytes(b'controlled bytes')
    sha='sha256:'+hashlib.sha256(binary.read_bytes()).hexdigest()
    identity=dict(sourceRevision='a'*40,sourceModified=False,releaseVersion='1.5.0-beta.1',binarySha256=sha)
    record=dict(runtime={'pinValue':'a'*40},releaseVersion='1.5.0-beta.1',binaryPath='cadence',binaryDigest=sha)
    state=dict(selectedSources={'runtime':record['runtime']},resourceDigests={})
    monkeypatch.setattr(modern,'load',lambda path:record if str(path).endswith('.dasops-install.json') else state)
    monkeypatch.setattr(modern,'check_runtime_selection',lambda *args:None)
    monkeypatch.setattr(modern,'VENDOR','.')
    for flag in (None,0,'false',True):
        bad={**identity,'sourceModified':flag}
        monkeypatch.setattr(legacy.subprocess,'check_output',lambda *a,**kw:json.dumps(bad).encode())
        monkeypatch.setattr(modern.subprocess,'run',lambda *a,**kw:SimpleNamespace(returncode=0,stdout=json.dumps(bad)))
        with pytest.raises(ValueError,match='identity differs'):legacy.binary_identity(binary,'a'*40,'1.5.0-beta.1',sha)
        with pytest.raises(ValueError,match='identity differs'):modern.installed(tmp_path)
    monkeypatch.setattr(legacy.subprocess,'check_output',lambda *a,**kw:json.dumps(identity).encode())
    monkeypatch.setattr(modern.subprocess,'run',lambda *a,**kw:SimpleNamespace(returncode=0,stdout=json.dumps(identity)))
    legacy.binary_identity(binary,'a'*40,'1.5.0-beta.1',sha)
    assert modern.installed(tmp_path)==binary
