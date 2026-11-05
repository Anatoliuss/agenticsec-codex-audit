"""Explicit image/binary builds; never called by preflight, dry-run, or tests.

docker/podman: builds the jq binary and the analysis tools image locally.
singularity:   you cannot build images on an HPC without fakeroot, so instead
               this builds the jq binary natively (gcc + autotools on the node)
               and `singularity pull`s the prebuilt tools image (built by this
               repo's GitHub Actions workflow, pushed to GHCR) into a local .sif.
"""
import argparse
import hashlib
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .core import ASSETS, backend, container_runtime, read_json, resolve, sha256, write_json

JQ_REPO = 'https://github.com/jqlang/jq'
JQ_COMMIT = 'f58787c'
DEFAULT_TOOLS_IMAGE = os.environ.get(
    'BINARY_EVAL_TOOLS_IMAGE', 'ghcr.io/anatoliuss/agenticsec-codex-audit-tools:latest')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', default='artifacts/openhands-jq')
    p.add_argument('--base', default='debian:bookworm-slim')
    p.add_argument('--tools-image', default=None,
                   help='singularity: docker://<ref> tools image to pull (default: %s)' % DEFAULT_TOOLS_IMAGE)
    args = p.parse_args()
    out = resolve(args.output)
    if out.exists() and any(out.iterdir()):
        p.error('Output directory is not empty; use a new directory to preserve previous artifacts')
    if backend() == 'singularity':
        build_singularity(out, args.tools_image or DEFAULT_TOOLS_IMAGE)
    else:
        build_docker(out, args.base, args.tools_image or 'agenticsec-openhands-tools:local', p)


# --------------------------------------------------------------------------- docker / podman
def build_docker(out, base, tools_image, p):
    rt = container_runtime()
    subprocess.run([rt, 'pull', base], check=True)
    image = read_inspect(base)
    # Use a registry digest in FROM; local sha256 IDs are not portable build references.
    digests = image.get('RepoDigests', [])
    if not digests:
        p.error('Base image has no repository digest')
    base = digests[0]
    build = [rt, 'build', '--platform=linux/amd64', '--build-arg', f'BASE={base}']
    subprocess.run([*build, '--target', 'binary', '--output', f'type=local,dest={out}', str(ASSETS)], check=True)
    subprocess.run([*build, '--target', 'tools', '-t', tools_image, str(ASSETS)], check=True)
    manifest = read_json(out / 'build.json')
    manifest.update(base_image=base, tools_image_id=read_inspect(tools_image)['Id'],
                    built_at=datetime.now(timezone.utc).isoformat(),
                    dockerfile_sha256=sha256(ASSETS / 'Dockerfile'),
                    build_script_sha256=sha256(ASSETS / 'build_jq.sh'))
    write_json(out / 'build.json', manifest)
    print(f'Artifacts: {out}\nAnalysis image: {manifest["tools_image_id"]}')


def read_inspect(image):
    import json
    return json.loads(subprocess.check_output([container_runtime(), 'image', 'inspect', image], text=True))[0]


# --------------------------------------------------------------------------- singularity
def build_singularity(out, tools_ref):
    out.mkdir(parents=True, exist_ok=True)
    build_jq_native(out)
    rt = container_runtime()
    sif = out / 'tools.sif'
    # Rootless pull of the GitHub Actions-built image; no fakeroot needed.
    subprocess.run([rt, 'pull', '--force', str(sif), f'docker://{tools_ref}'], check=True)
    manifest = read_json(out / 'build.json')
    manifest.update(tools_image_ref=tools_ref, tools_image_id=sha256(sif),
                    tools_image_path=str(sif), tools_image_kind='singularity-sif',
                    built_at=datetime.now(timezone.utc).isoformat())
    write_json(out / 'build.json', manifest)
    print(f'Artifacts: {out}\nAnalysis .sif: {sif} ({manifest["tools_image_id"]})\n'
          f'Set sandbox.image to: {sif}')


def build_jq_native(out):
    """Compile jq at the pinned commit on this host (no container). Needs gcc,
    make, git, autoconf/automake/libtool and bison/flex on PATH (module load
    them on an HPC). Built --without-oniguruma so no libonig is required; the
    CVE-2026-44777 recursion bug is in the module loader, not the regex engine."""
    src = out / 'jq-src'
    if src.exists():
        shutil.rmtree(src)
    subprocess.run(['git', 'clone', JQ_REPO, str(src)], check=True)
    subprocess.run(['git', '-C', str(src), 'checkout', '--detach', JQ_COMMIT], check=True)
    revision = subprocess.check_output(['git', '-C', str(src), 'rev-parse', 'HEAD'], text=True).strip()
    if not revision.startswith(JQ_COMMIT):
        raise SystemExit(f'Resolved commit {revision} does not match {JQ_COMMIT}')
    subprocess.run(['autoreconf', '-fi'], cwd=src, check=True)
    # Fixed, non-PIE build so exported virtual addresses are directly comparable.
    subprocess.run(['./configure', '--without-oniguruma', '--disable-shared',
                    'CFLAGS=-O0 -g -fno-pie', 'LDFLAGS=-no-pie'], cwd=src, check=True)
    subprocess.run(['make', '-j2'], cwd=src, check=True)

    shutil.copy(src / 'jq', out / 'jq.unstripped')
    (out / 'symbols.txt').write_bytes(subprocess.check_output(['nm', '-n', str(out / 'jq.unstripped')]))
    shutil.copy(src / 'jq', out / 'jq')
    subprocess.run(['strip', '--strip-all', str(out / 'jq')], check=True)
    shutil.copy(src / 'COPYING', out / 'jq.LICENSE')
    shutil.rmtree(src, ignore_errors=True)

    def digest(name):
        return hashlib.sha256((out / name).read_bytes()).hexdigest()
    write_json(out / 'build.json', {
        'repository': JQ_REPO, 'requested_commit': JQ_COMMIT, 'resolved_commit': revision,
        'binary_sha256': digest('jq'), 'unstripped_sha256': digest('jq.unstripped'),
        'flags': {'CFLAGS': '-O0 -g -fno-pie', 'LDFLAGS': '-no-pie'},
        'configure': ['./configure', '--without-oniguruma', '--disable-shared'],
        'compiler': subprocess.check_output(['gcc', '--version'], text=True).splitlines()[0],
        'platform': subprocess.check_output(['uname', '-m'], text=True).strip(),
        'symbol_map': 'symbols.txt', 'stripped': True, 'build': 'native (no container)',
    })


if __name__ == '__main__':
    main()
