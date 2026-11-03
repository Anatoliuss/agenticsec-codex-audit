"""Explicit Docker builds; never called by preflight, dry-run, or tests."""
import argparse
import subprocess
from datetime import datetime, timezone

from .core import ASSETS, container_runtime, read_json, resolve, write_json, sha256


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', default='artifacts/openhands-jq')
    p.add_argument('--base', default='debian:bookworm-slim')
    p.add_argument('--tools-image', default='agenticsec-openhands-tools:local')
    args = p.parse_args()
    out = resolve(args.output)
    if out.exists() and any(out.iterdir()):
        p.error('Output directory is not empty; use a new directory to preserve previous artifacts')
    rt = container_runtime()
    subprocess.run([rt, 'pull', args.base], check=True)
    image = read_inspect(args.base)
    # Use a registry digest in FROM; local sha256 IDs are not portable build references.
    digests = image.get('RepoDigests', [])
    if not digests:
        p.error('Base image has no repository digest')
    base = digests[0]
    build = [rt, 'build', '--platform=linux/amd64', '--build-arg', f'BASE={base}']
    subprocess.run([*build, '--target', 'binary', '--output', f'type=local,dest={out}', str(ASSETS)], check=True)
    subprocess.run([*build, '--target', 'tools', '-t', args.tools_image, str(ASSETS)], check=True)
    manifest = read_json(out / 'build.json')
    manifest.update(base_image=base, tools_image_id=read_inspect(args.tools_image)['Id'],
                    built_at=datetime.now(timezone.utc).isoformat(),
                    dockerfile_sha256=sha256(ASSETS / 'Dockerfile'),
                    build_script_sha256=sha256(ASSETS / 'build_jq.sh'))
    write_json(out / 'build.json', manifest)
    print(f'Artifacts: {out}\nAnalysis image: {manifest["tools_image_id"]}')


def read_inspect(image):
    import json
    return json.loads(subprocess.check_output([container_runtime(), 'image', 'inspect', image], text=True))[0]


if __name__ == '__main__':
    main()
