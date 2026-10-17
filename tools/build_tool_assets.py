#!/usr/bin/env python3
"""Finite offline beta tool build, controlled outside the candidate domain.

Run from the reviewed workflow revision, never the candidate checkout. Materials
are independently pinned input; this helper grants no signing/publication authority.
The dasops tools copy must remain identical to this single author.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import time
import uuid

VERSION = '1.2.0-beta.1'
SHA = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')

# This fixed worker is mounted from trusted control, not selected by candidate code.
WORKER = r'''
import contextlib,hashlib,importlib.metadata,json,os,resource,shutil,subprocess,sys,zipfile
from pathlib import Path
c=json.loads(Path('/control/worker-input.json').read_bytes())
resource.setrlimit(resource.RLIMIT_FSIZE,(64*1024**2,64*1024**2))
if c['operation']=='build':
    shutil.copytree('/candidate','/tmp/source');os.chdir('/tmp/source')
    artifacts=Path('/tmp/artifacts');artifacts.mkdir()
    os.environ.update(SOURCE_DATE_EPOCH=str(c['epoch']),PYTHONDONTWRITEBYTECODE='1',TZ='UTC',LANG='C.UTF-8',
        PIP_NO_INDEX='1',PIP_DISABLE_PIP_VERSION_CHECK='1',GOTOOLCHAIN='local',GOPROXY='off',GOSUMDB='off',
        GOENV='off',GOWORK='off',GOFLAGS='',GOOS='linux',GOARCH='amd64',CGO_ENABLED='0',
        GOROOT='/toolchain',GOCACHE='/tmp/go-cache',GOMODCACHE='/tmp/go-mod-cache')
    if c['component']=='dasops':
        deps=Path('/tmp/dependencies');deps.mkdir()
        for name in c['wheels']:
            with zipfile.ZipFile('/wheels/'+name) as a:a.extractall(deps)
        sys.path.insert(0,str(deps));output=artifacts
        with contextlib.redirect_stdout(sys.stderr):
            from setuptools.build_meta import build_wheel
            name=build_wheel(str(output))
        if name!='dasops-1.2.0b1-py3-none-any.whl':raise RuntimeError('wrong wheel identity')
    else:
        if Path('cadence-core/cmd/cadence/release_version.txt').read_text().strip()!=c['version']:
            raise RuntimeError('stale embedded VERSION')
        subprocess.run(['/toolchain/bin/go','build','-trimpath','-mod=vendor','-buildvcs=false',
                        '-o','/tmp/artifacts/cadence-linux-amd64','./cmd/cadence'],cwd='cadence-core',check=True)
        name='cadence-linux-amd64'
    if (artifacts/name).stat().st_size>32*1024**2:raise RuntimeError('payload budget exceeded')
    shutil.copyfile(artifacts/name,'/output/result')
else:
    if c['component']=='dasops':
        subprocess.run([sys.executable,'-I','-m','venv','/tmp/install'],check=True)
        subprocess.run(['/tmp/install/bin/python','-I','-m','pip','install','--no-index','--no-deps',
                        '--no-compile','/asset/dasops-1.2.0b1-py3-none-any.whl'],check=True,stdout=sys.stderr)
        code="import dasops,importlib.metadata as m,json;print(json.dumps({'version':m.version('dasops'),'module':dasops.__file__}))"
        value=json.loads(subprocess.check_output(['/tmp/install/bin/python','-I','-B','-c',code],cwd='/tmp'))
        if value['version']!='1.2.0b1' or not value['module'].startswith('/tmp/install/'):
            raise RuntimeError('installation fallback or wrong package')
    else:
        value=json.loads(subprocess.check_output(['/asset/cadence-linux-amd64','version','--json'],cwd='/tmp'))
        if value['releaseVersion']!=c['version'] or value['goos']!='linux' or value['goarch']!='amd64':
            raise RuntimeError('wrong native identity')
    Path('/output/result').write_text(json.dumps(value,sort_keys=True)+'\n')
'''


def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()


def tree_digest(root):
    rows=[];total=0
    for path in sorted(root.rglob('*')):
        info=path.lstat()
        if stat.S_ISDIR(info.st_mode):continue
        if not stat.S_ISREG(info.st_mode):raise ValueError('source/material tree contains links or special files')
        total+=info.st_size
        if len(rows)>=25000 or total>2*1024**3:raise ValueError('source/material tree exceeds finite build budget')
        rows.append([path.relative_to(root).as_posix(),stat.S_IMODE(info.st_mode),info.st_size,sha(path)])
    if not rows:raise ValueError('empty source/material tree')
    return hashlib.sha256(json.dumps(rows,separators=(',',':')).encode()).hexdigest()


def load_exact(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size>65536:raise ValueError('ordinary bounded control JSON required')
    def pairs(items):
        d={}
        for k,v in items:
            if k in d:raise ValueError('duplicate control field')
            d[k]=v
        return d
    return json.loads(path.read_bytes(),object_pairs_hook=pairs)


def material_path(root,row):
    if not isinstance(row,dict) or set(row)!={'path','sha256'} or not SHA.fullmatch(str(row['sha256'])):
        raise ValueError('material path/hash binding required')
    relative=Path(row['path'])
    if relative.is_absolute() or '..' in relative.parts:raise ValueError('material path escapes root')
    path=root/relative
    if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()) or not path.is_file() or sha(path)!=row['sha256']:
        raise ValueError('material bytes differ')
    return path


def preflight(component,source,materials,materials_sha,materials_root):
    # Bind mounts refer to this host's pinned trees; a remote daemon sees other files.
    if (os.environ.get('DOCKER_HOST','') and not os.environ['DOCKER_HOST'].startswith('unix://')) or os.environ.get('DOCKER_CONTEXT','default') not in {'','default'}:
        raise ValueError('this finite build requires the local default Docker daemon')
    if not SHA.fullmatch(materials_sha) or sha(materials)!=materials_sha:raise ValueError('materials control digest differs')
    c=load_exact(materials)
    common={'imageId','platform','sourceDateEpoch'}
    required=common|({'buildWheels'} if component=='dasops' else {'goRoot','goTreeSha256'})
    if not required <= set(c) or set(c)-required-{'imageArchive'} or c['platform']!='linux/amd64' or not re.fullmatch(r'sha256:[0-9a-f]{64}',str(c['imageId'])):
        raise ValueError('fixed Linux build materials required')
    if type(c['sourceDateEpoch']) is not int or not 315532800<=c['sourceDateEpoch']<=2147483647:
        raise ValueError('fixed reproducible epoch required')
    if (source/'VERSION').read_text().strip()!=VERSION:raise ValueError('wrong component version')
    bound={};go=None
    if component=='dasops':
        wheels=c['buildWheels']
        if not isinstance(wheels,dict) or len(wheels)!=3:raise ValueError('three pinned backend wheels required')
        names=set()
        for name,row in wheels.items():
            if Path(name).name!=name or not name.endswith('-py3-none-any.whl'):raise ValueError('invalid build wheel')
            names.add(name.split('-')[0]);bound[name]=material_path(materials_root,row)
        if names!={'setuptools','wheel','packaging'}:raise ValueError('unsupported backend material')
    else:
        relative=Path(c['goRoot'])
        if relative.is_absolute() or '..' in relative.parts:raise ValueError('Go root escapes material root')
        go=materials_root/relative
        if go.is_symlink() or not go.resolve().is_relative_to(materials_root.resolve()) or tree_digest(go)!=c['goTreeSha256']:
            raise ValueError('Go toolchain bytes differ')
    archive=material_path(materials_root,c['imageArchive']) if 'imageArchive' in c else None
    try:
        raw=subprocess.check_output(['docker','image','inspect',c['imageId']],stderr=subprocess.PIPE,timeout=20)
    except subprocess.CalledProcessError:
        if archive is None:raise ValueError('missing pinned image; an offline imageArchive is required')
        subprocess.run(['docker','image','load','--input',str(archive)],check=True,capture_output=True,timeout=120)
        raw=subprocess.check_output(['docker','image','inspect',c['imageId']],timeout=20)
    inspect=json.loads(raw)[0]
    if inspect['Id']!=c['imageId'] or inspect['Os']!='linux' or inspect['Architecture']!='amd64':
        raise ValueError('actual build image differs')
    return c,bound,go


def container(c,control,output,mounts):
    # A single existing file is writable; the kernel caps it even for hostile backends.
    result=output/'result';result.touch(mode=0o600,exist_ok=False)
    name='das-tool-build-'+uuid.uuid4().hex
    command=['docker','run','--rm','--name',name,'--stop-timeout=2','--pull=never','--network=none','--read-only',
             '--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=128',
             '--memory=2g','--cpus=2','--user',f'{os.getuid()}:{os.getgid()}',
             '--tmpfs',f'/tmp:rw,exec,nosuid,nodev,size=1536m,uid={os.getuid()},gid={os.getgid()}',
             '--mount',f'type=bind,src={control.resolve()},dst=/control,readonly',
             '--mount',f'type=bind,src={result.resolve()},dst=/output/result',
             '--entrypoint','/usr/local/bin/python3']
    for source,target in mounts:command+=['--mount',f'type=bind,src={source.resolve()},dst={target},readonly']
    command+=[c['imageId'],'-I','-B','/control/worker.py']
    with (output.parent/(output.name+'.log')).open('xb') as log:
        process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        start=time.monotonic();size=0
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout,selectors.EVENT_READ)
                while selector.get_map():
                    if time.monotonic()-start>=600:raise ValueError('build consumer timeout')
                    for key,_ in selector.select(.1):
                        data=os.read(key.fileobj.fileno(),65536)
                        if not data:selector.unregister(key.fileobj);continue
                        size+=len(data)
                        if size>16*1024**2:raise ValueError('build consumer output limit')
                        log.write(data)
            if process.wait(timeout=10):raise ValueError('isolated build/install consumer failed; retain raw log')
        finally:
            # Reap only our unique container; a killed Docker client alone is not termination.
            try:subprocess.run(['docker','rm','--force',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
            finally:
                if process.poll() is None:process.kill()
                process.wait(timeout=10);process.stdout.close()


def build(component,source,materials,materials_sha,materials_root,out,source_commit,control_commit):
    if not COMMIT.fullmatch(source_commit) or not COMMIT.fullmatch(control_commit):raise ValueError('exact source/control commits required')
    c,wheels,go=preflight(component,source,materials,materials_sha,materials_root)
    original=tree_digest(source);out.mkdir()
    control=out/'control';control.mkdir();(control/'worker.py').write_text(WORKER)
    worker={'component':component,'version':VERSION,'epoch':c['sourceDateEpoch'],'wheels':list(wheels),'operation':'build'}
    (control/'worker-input.json').write_text(json.dumps(worker))
    mounts=[(source,'/candidate')]+[(path,'/wheels/'+name) for name,path in wheels.items()]
    if go:mounts.append((go,'/toolchain'))
    filename='dasops-1.2.0b1-py3-none-any.whl' if component=='dasops' else 'cadence-linux-amd64'
    hashes=[]
    for index in (1,2):
        target=out/f'build-{index}';target.mkdir();container(c,control,target,mounts)
        (target/'result').rename(target/filename)
        if {p.name for p in target.iterdir()}!={filename}:raise ValueError('unexpected candidate output member')
        payload=target/filename;info=payload.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>32*1024**2:
            raise ValueError('ordinary bounded payload required')
        if component=='cadence-oss':payload.chmod(0o700)
        hashes.append(sha(payload))
    if hashes[0]!=hashes[1]:raise ValueError('independent build bytes differ')
    if tree_digest(source)!=original:raise ValueError('source changed during build')
    preflight(component,source,materials,materials_sha,materials_root)
    worker['operation']='install';(control/'worker-input.json').write_text(json.dumps(worker))
    installed=out/'installation';installed.mkdir();container(c,control,installed,[(out/'build-1','/asset')])
    (installed/'result').rename(installed/'installation.json')
    original_install=installed/'installation.json'
    if (original_install.is_symlink() or not original_install.is_file() or original_install.stat().st_size>65536
            or {p.name for p in installed.iterdir()}!={'installation.json'}):
        raise ValueError('ordinary bounded installation observation required')
    binding={'schemaVersion':'1.0.0','component':component,'version':VERSION,'sourceCommit':source_commit,
             'controlCommit':control_commit,'sourceTreeSha256':original,'recipeSha256':sha(Path(__file__)),
             'materialsSha256':materials_sha,'imageId':c['imageId'],'platform':c['platform'],
             'payload':filename,'payloadSha256':hashes[0],'payloadBytes':(out/'build-1'/filename).stat().st_size}
    (out/'build-1/tool-build-binding.json').write_text(json.dumps(binding,sort_keys=True,indent=2)+'\n')
    return binding


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--component',choices=['dasops','cadence-oss'],required=True)
    for name in ('source','materials','materials-root','out'):p.add_argument('--'+name,type=Path,required=True)
    for name in ('materials-sha256','source-commit','control-commit'):p.add_argument('--'+name,required=True)
    a=p.parse_args()
    print(json.dumps(build(a.component,a.source,a.materials,a.materials_sha256,a.materials_root,a.out,a.source_commit,a.control_commit)))


if __name__=='__main__':main()
