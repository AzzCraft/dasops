"""Tests for dasops.vendor — lock enforcement."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
import pytest

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


def _modern_runtime_fixture(root):
    """Real process/record fixture; no compiler or fake install-success claim."""
    import sys
    from dasops import scaffold_v15 as scaffold
    runtime = dict(kind='git', uri='https://example.invalid/cadence.git',
                   pinType='commit', pinValue='a'*40, floating=False)
    base = root/scaffold.VENDOR
    binary = base/'.cadence/bin/cadence'; binary.parent.mkdir(parents=True)
    binary.write_text(
        f'#!{sys.executable}\n'
        'import hashlib,json,sys,time\nfrom pathlib import Path\n'
        'if sys.argv[1:]==["version","--json"]:\n'
        ' print(json.dumps(dict(sourceRevision="'+'a'*40+'",sourceModified=False,releaseVersion="1.2.0-beta.1",goos="linux",goarch="amd64",goVersion="fixture",binarySha256="sha256:"+hashlib.sha256(Path(__file__).read_bytes()).hexdigest())))\n'
        'else:\n Path("native-called").write_text("started")\n'
        ' while not Path("native-release").exists(): time.sleep(0.01)\n'
        ' sys.exit(7)\n')
    binary.chmod(0o755)
    (base/'resource.json').write_text('{}\n')
    resources = {'resource.json':scaffold.digest(b'{}\n')}
    scaffold.write_json(root/scaffold.STATE,dict(selectedSources={'runtime':runtime},resourceDigests=resources))
    scaffold.write_json(root/'tooling_lock.json',dict(verifyRuntime=runtime))
    for path in ('tooling/das/suite/suite_version_closure.json','tooling/das/suite_version_closure.json'):
        scaffold.write_json(root/path,dict(refs={'verifyRuntime':runtime}))
    scaffold.write_json(base/'.dasops-install.json',dict(runtime=runtime,releaseVersion='1.2.0-beta.1',
        binaryPath='.cadence/bin/cadence',binaryDigest=scaffold.digest(binary.read_bytes())))
    return binary


@pytest.mark.parametrize('interrupt_wrapper',[False,True])
def test_v15_runtime_read_guard_serializes_replacement(tmp_path,interrupt_wrapper):
    import fcntl
    import subprocess
    import sys
    import time
    _modern_runtime_fixture(tmp_path)
    guard_dir=tmp_path/'.cadence/tmp';guard_dir.mkdir(parents=True)
    child=subprocess.Popen([sys.executable,'-c',
        'from pathlib import Path; from dasops.scaffold_v15 import run_native; '
        'raise SystemExit(run_native(Path.cwd(),["verify"]))'],cwd=tmp_path,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    writer=None
    try:
        limit=time.monotonic()+5
        while not (tmp_path/'native-called').exists() and child.poll() is None and time.monotonic()<limit:
            time.sleep(0.01)
        assert (tmp_path/'native-called').exists(),child.communicate(timeout=1)
        if interrupt_wrapper:
            child.terminate();child.wait(timeout=5)
        with (guard_dir/'install.guard').open('a+b') as guard:
            try:fcntl.flock(guard.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:pass
            else:raise AssertionError('1.5 runtime was executing without its read guard')
        writer=subprocess.Popen([sys.executable,'-c',
            'from pathlib import Path; from dasops import scaffold_v15 as s; '
            's._install_locked=lambda *a: Path("writer-entered").write_text("entered"); '
            's.install(Path.cwd(),Path.cwd(),True)'],cwd=tmp_path,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:writer.wait(timeout=0.2)
        except subprocess.TimeoutExpired:pass
        else:raise AssertionError('replacement entered while runtime was executing')
        assert not (tmp_path/'writer-entered').exists()
        (tmp_path/'native-release').write_text('continue')
        output=child.communicate(timeout=5);assert child.returncode==(-15 if interrupt_wrapper else 7),output
        output=writer.communicate(timeout=5);assert writer.returncode==0,output
        assert (tmp_path/'writer-entered').read_text()=='entered'
    finally:
        (tmp_path/'native-release').write_text('continue')
        for process in (child,writer):
            if process is not None and process.poll() is None:
                process.kill();process.communicate(timeout=5)


def test_v15_runtime_rejects_linked_vendor_ancestors(tmp_path):
    import pytest
    from dasops import scaffold_v15 as scaffold
    binary=_modern_runtime_fixture(tmp_path)
    assert scaffold.installed(tmp_path)==binary
    for name in ('vendor','vendor/cadence','vendor/cadence/cadence-oss'):
        path=tmp_path/name;relocated=tmp_path/'relocated'
        path.rename(relocated);path.symlink_to(relocated,target_is_directory=True)
        try:
            with pytest.raises(ValueError,match='linked'):scaffold.installed(tmp_path)
        finally:path.unlink();relocated.rename(path)
    assert scaffold.installed(tmp_path)==binary


def test_v15_runtime_rejects_nonobject_native_identity(tmp_path,monkeypatch):
    import pytest
    import subprocess
    from dasops import scaffold_v15 as scaffold
    _modern_runtime_fixture(tmp_path)
    for value in ('[]','null','0','"identity"'):
        monkeypatch.setattr(scaffold.subprocess,'run',lambda *a,**kw:subprocess.CompletedProcess(a,0,stdout=value))
        with pytest.raises(ValueError,match='identity'):scaffold.installed(tmp_path)


def test_v15_install_preserves_concurrent_empty_destination(tmp_path,monkeypatch):
    import subprocess
    import pytest
    from dasops import scaffold_v15 as s
    product=tmp_path/'product';binary=_modern_runtime_fixture(product)
    binary_bytes=binary.read_bytes();target=product/s.VENDOR
    old_record=(target/'.dasops-install.json').read_bytes()
    suite=tmp_path/'suite';source=suite/'source';source.mkdir(parents=True)
    state=s.load(product/s.STATE)
    s.write_json(suite/'suite_version_closure.json',dict(refs={'verifyRuntime':state['selectedSources']['runtime']}))
    (source/'resource.json').write_bytes(b'{}\n')
    (source/'VERSION').write_text('1.2.0-beta.1\n')
    for name in ('LICENSE','NOTICE','THIRD_PARTY_NOTICES.md'):(source/name).write_text('fixture\n')
    monkeypatch.setattr(s,'suite_inputs',lambda *a:(suite,{'cadence-oss':source},{}))
    monkeypatch.setattr(s,'git',lambda *a:'a'*40)
    monkeypatch.setattr(s,'resource_manifest',lambda *a:state['resourceDigests'])
    original_run=s.subprocess.run;original_rename=Path.rename
    def build(args,*a,**kw):
        if args[:2]==['go','build']:
            output=Path(args[args.index('-o')+1]);output.write_bytes(binary_bytes);output.chmod(0o755)
            return subprocess.CompletedProcess(args,0)
        return original_run(args,*a,**kw)
    occupied=[]
    def collide(path,destination):
        result=original_rename(path,destination)
        if path==target:
            target.mkdir(mode=0o700);occupied.append(target.stat().st_ino)
        return result
    monkeypatch.setattr(s.subprocess,'run',build);monkeypatch.setattr(Path,'rename',collide)
    with pytest.raises(s.PublicationRecoveryRequired,match='preserved previous installation'):
        s.install(product,suite,force=True)
    assert occupied and target.stat().st_ino==occupied[0] and list(target.iterdir())==[]
    backups=list(target.parent.glob('.cadence-install-*/previous'))
    assert len(backups)==1 and (backups[0]/'.dasops-install.json').read_bytes()==old_record
    target.rmdir();s._publish(backups[0],target)
    assert s.installed(product)==binary
