#!/usr/bin/env python3
"""Acquire only the reviewed Linux inputs for the fixed 1.2.0-beta.1 builder.

Run from the default-branch control workflow. This does not execute candidate
code, create signatures, or publish releases. The dasops copy is identical.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import urllib.request

from build_tool_assets import sha

IMAGE_ID = 'sha256:a36c24f9cbdf4fd0f52d67f0823eeac19c2028c637cecc392d97f980d4fec56b'
IMAGE_REF = 'docker.io/library/python@' + IMAGE_ID
GO_URL = 'https://go.dev/dl/go1.26.9.linux-amd64.tar.gz'
GO_SHA = '42d158b4d8f7b61ac0a830567c940a86098fb7aac52e467a5ebec03ef5cc2f8d'
# Full official distribution, not a stripped/read-only GOTOOLCHAIN module cache.
GO_TREE = 'f72592e4216c2466120148e7aa4fdffec759b4fb52c4048a743d7aec4586893e'
EPOCHS = {'cadence-oss': 1793074441, 'dasops': 1793074507}
WHEELS = {
    'setuptools-84.1.0-py3-none-any.whl': (
        '18/02/b4bbb90f8f29e334898ff45c6d9b1fffaa6f378017052b3023a06262b5f7',
        '5231689c6ac8156cd155cfb98c3fd6fb252c3e7e9bd3d78b64d3c55f132624c9'),
    'wheel-0.46.2-py3-none-any.whl': (
        '13/2c/5e079cefe955ae58e5a052fe037c850ce493eb7269dedeb960237e78fb0f',
        '33ae60725d69eaa249bc1982e739943c23b34b58d51f1cb6253453773aca6e65'),
    'packaging-26.3-py3-none-any.whl': (
        '63/34/ba1c580383c9eada3711951fef0795c80b829a078d72188184bcab9dd527',
        'd7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c'),
}


def download(url, expected, path):
    # URLs and digests come only from the reviewed constants above.
    with urllib.request.urlopen(url, timeout=90) as response, path.open('xb') as dest:
        total = 0
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > 128 * 1024**2:
                raise ValueError('download exceeds fixed material budget')
            dest.write(chunk)
    if sha(path) != expected:
        raise ValueError('upstream material checksum differs')


def go_tree(bundle):
    """Match the builder's tree digest without extracting executable material."""
    rows, names, total = [], set(), 0
    with tarfile.open(bundle, 'r:') as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            if (not (member.isfile() or member.isdir()) or path.is_absolute()
                    or str(path) != member.name.rstrip('/') or '..' in path.parts
                    or not path.is_relative_to('go') or path in names
                    or member.mode & ~0o777 or member.size < 0):
                raise ValueError('nonregular Go archive member')
            names.add(path)
            total += member.size
            if len(names) > 25000 or total > 2 * 1024**3:
                raise ValueError('Go archive exceeds fixed material budget')
            if member.isfile():
                with archive.extractfile(member) as source:
                    digest = hashlib.sha256()
                    for chunk in iter(lambda: source.read(1024 * 1024), b''):
                        digest.update(chunk)
                rows.append([path.relative_to('go').as_posix(), member.mode, member.size, digest.hexdigest()])
    if not rows:
        raise ValueError('empty Go archive')
    return hashlib.sha256(json.dumps(sorted(rows, key=lambda row: PurePosixPath(row[0])), separators=(',', ':')).encode()).hexdigest()


def prepare(component, out):
    epoch = EPOCHS[component]
    out.mkdir()  # Preserve any existing directory; a retry uses a new job directory.
    subprocess.run(['docker', '--context', 'default', 'pull', '--platform=linux/amd64', IMAGE_REF],
                   check=True, timeout=300, stdout=sys.stderr)
    info = json.loads(subprocess.check_output(
        ['docker', '--context', 'default', 'image', 'inspect', IMAGE_REF], timeout=30))[0]
    if info['Id'] != IMAGE_ID or info['Os'] != 'linux' or info['Architecture'] != 'amd64':
        raise ValueError('downloaded image identity differs')
    image = out / 'python-image.tar'
    subprocess.run(['docker', '--context', 'default', 'image', 'save', '--output', str(image), IMAGE_ID],
                   check=True, timeout=180, stdout=sys.stderr)
    config = dict(imageId=IMAGE_ID, platform='linux/amd64', sourceDateEpoch=epoch,
                  imageArchive={'path': image.name, 'sha256': sha(image)})
    if component == 'cadence-oss':
        compressed, bundle = out / 'go.tar.gz', out / 'go-toolchain.tar'
        download(GO_URL, GO_SHA, compressed)
        with gzip.open(compressed, 'rb') as source, bundle.open('xb') as dest:
            shutil.copyfileobj(source, dest)
        if go_tree(bundle) != GO_TREE:
            raise ValueError('upstream Go tree differs from reviewed material')
        compressed.unlink()
        config.update(goRoot='go', goTreeSha256=GO_TREE)
    else:
        (out / 'wheels').mkdir()
        config['buildWheels'] = {}
        for name, (location, digest) in WHEELS.items():
            path = out / 'wheels' / name
            download(f'https://files.pythonhosted.org/packages/{location}/{name}', digest, path)
            config['buildWheels'][name] = {'path': 'wheels/' + name, 'sha256': digest}
    manifest = out / 'build-materials.json'
    manifest.write_text(json.dumps(config, sort_keys=True, indent=2) + '\n')
    return sha(manifest)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--component', choices=tuple(EPOCHS), required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    print('materials_sha256=' + prepare(args.component, args.out))
