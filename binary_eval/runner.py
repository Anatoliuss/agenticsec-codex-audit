"""Supervise paired OpenHands runs without exposing evaluator data to tools."""
from __future__ import annotations

import importlib.metadata
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

from .core import (ROOT, CONFIGURATIONS, assess, backend, build_prompts, comparison_key,
                   container_runtime, parse_findings, read_json, resolve, sandbox_command,
                   sandbox_exec_argv, sandbox_stop_argv, sha256, validate_config, write_json)


def command(args, timeout=30):
    return subprocess.check_output(args, text=True, encoding='utf-8',
                                   stderr=subprocess.STDOUT, timeout=timeout).strip()


def validate_artifacts(cfg):
    binary = resolve(cfg['target']['binary'])
    manifest = read_json(resolve(cfg['target']['manifest']))
    with binary.open('rb') as stream:
        header = stream.read(20)
    if header[:4] != b'\x7fELF' or header[4:6] != b'\x02\x01' or header[18:20] != b'\x3e\x00':
        raise ValueError('Expected an x86-64 little-endian ELF binary')
    digest = sha256(binary)
    if manifest.get('binary_sha256') != digest:
        raise ValueError('Binary hash differs from build manifest')
    revision = manifest.get('resolved_commit', '')
    import re
    if not re.fullmatch(r'f58787c[0-9a-f]{33}', revision):
        raise ValueError('Build manifest must resolve f58787c to its full commit')
    if manifest.get('repository') != cfg['target']['repository']:
        raise ValueError('Build repository differs from configured target')
    return binary, manifest, digest


def preflight(cfg):
    validate_config(cfg)
    binary, manifest, digest = validate_artifacts(cfg)
    if importlib.metadata.version('openhands-sdk') != cfg['sdk_version']:
        raise ValueError('Install the pinned openhands/requirements.txt')
    rt = container_runtime()
    if backend() == 'singularity':
        docker_version = command([rt, '--version'])
        sif = resolve(cfg['sandbox']['image'])
        if not sif.exists():
            raise ValueError(f'Analysis image {sif} not found; run `python -m binary_eval.build` first')
        image_id = sha256(sif)
        if image_id != manifest.get('tools_image_id'):
            raise ValueError('Analysis .sif differs from the build manifest; re-pull or rebuild')
        image_ref, network_isolation = str(sif), 'singularity --net --network none'
        versions = command([rt, 'exec', str(sif), 'cat', '/tool-versions.txt'])
    else:
        try:  # podman is daemonless and may have no .Server.Version; fall back to --version
            docker_version = command([rt, 'version', '--format', '{{.Server.Version}}'])
        except subprocess.SubprocessError:
            docker_version = command([rt, '--version'])
        image = json.loads(command([rt, 'image', 'inspect', cfg['sandbox']['image']]))[0]
        if image.get('Os') != 'linux' or image.get('Architecture') != 'amd64':
            raise ValueError('Analysis image must be linux/amd64')
        if image['Id'] != manifest.get('tools_image_id'):
            raise ValueError('Analysis image differs from the build manifest; rebuild or restore the recorded image')
        image_id, image_ref, network_isolation = image['Id'], image['Id'], 'docker --network=none'
        versions = command([rt, 'run', '--rm', '--network=none', '--read-only',
                            '--cap-drop=ALL', '--security-opt=no-new-privileges', image['Id'],
                            'cat', '/tool-versions.txt'])
    headers = {}
    key = os.environ.get(cfg['model']['api_key_env'])
    if key:
        headers['Authorization'] = 'Bearer ' + key
    request = Request(cfg['model']['base_url'].rstrip('/') + '/models', headers=headers)
    with urlopen(request, timeout=15) as response:
        models = json.load(response)
    if cfg['model']['id'] not in [m.get('id') for m in models.get('data', [])]:
        raise ValueError('Configured model ID is not advertised by the serving endpoint')
    return dict(binary=str(binary), binary_sha256=digest, build=manifest,
                image_id=image_id, image_ref=image_ref, backend=backend(),
                container_runtime=rt, docker_version=docker_version,
                network_isolation=network_isolation, tool_versions=versions, model_listing=models,
                server_provenance='operator-supplied; /models confirms ID, not weights/revision')


def finalize_record(record, out, truth):
    """Normalize worker artifacts without interpreting execution failures as misses."""
    out = Path(out)
    raw = (out / 'final.txt').read_text(encoding='utf-8') if (out / 'final.txt').exists() else ''
    record.update(raw_findings=raw, summary=None, findings=[], token_usage=None,
                  tool_calls=0, sdk_tool_calls=0, evidence_issues=[])
    if (out / 'metrics.json').exists():
        try:
            metrics = read_json(out / 'metrics.json')
            record['llm_metrics'] = metrics
            # A zero-initialized SDK accumulator does not prove usage was reported.
            if metrics.get('token_usages'):
                record['token_usage'] = metrics.get('accumulated_token_usage')
        except (OSError, ValueError, AttributeError) as exc:
            record['metrics_error'] = f'Partial metrics unavailable: {exc}'
    if (out / 'tools.jsonl').exists():
        record['tool_calls'] = len((out / 'tools.jsonl').read_text(encoding='utf-8').splitlines())
    if (out / 'events.jsonl').exists():
        for line in (out / 'events.jsonl').read_text(encoding='utf-8').splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue  # A killed worker can leave an incomplete final line.
            if event.get('tool_name') and event.get('action') is not None:
                record['sdk_tool_calls'] += 1
    if record['status'] == 'completed':
        state = record.get('worker', {}).get('execution_status')
        if state != 'finished':
            record.update(status='execution_failure', error=f'Conversation did not finish: {state}')
    if record['status'] == 'completed':
        try:
            parsed = parse_findings(raw)
            record.update(status='ok', **parsed)
        except (ValueError, TypeError) as exc:
            record.update(status='malformed_output' if raw else 'no_output', error=str(exc))
    for f in record['findings']:
        for ev in f['evidence']:
            ref = ev['reference']
            # References are names of host-captured tool output, never arbitrary paths.
            import re
            if not re.fullmatch(r'tool-\d{4,}\.txt', ref) or not (out / ref).is_file():
                record['evidence_issues'].append(dict(finding=f['id'], reference=ref, issue='unverified_reference'))
    record['assessment'] = assess(record['status'], record['findings'], truth,
                                  record['provenance']['binary_sha256'])
    record['ground_truth'] = truth
    return record


def run_one(cfg, provenance, batch_id, configuration):
    run_id = batch_id + '__' + configuration
    out = resolve(cfg['results_dir']) / 'runs' / run_id
    out.mkdir(parents=True, exist_ok=False)
    prompts = build_prompts(cfg, configuration)
    write_json(out / 'config.json', cfg)
    write_json(out / 'prompts.json', prompts)
    truth_path = resolve(cfg['target']['ground_truth'])
    truth = read_json(truth_path) if truth_path.exists() else {}
    record = dict(run_id=run_id, batch_id=batch_id, backend='openhands',
                  project_identity='agenticsec-codex-audit', configuration=configuration,
                  sample_id='jq_f58787c', started_at=datetime.now(timezone.utc).isoformat(),
                  config=cfg, prompts=prompts, provenance=provenance,
                  comparison_key=comparison_key(cfg, provenance['binary_sha256'], provenance['image_id'], prompts['system']),
                  status='input_failure', error=None, exit_code=None,
                  raw_trajectory='events.jsonl', tool_log='tools.jsonl')
    write_json(out / 'run.json', record)
    container = 'binary-audit-' + uuid.uuid4().hex
    workdir = out / 'sandbox-work'
    start = time.monotonic()
    try:
        # docker/podman start a detached container; singularity has nothing to
        # start (each exec binds a persistent host /work), so just make that dir.
        start_argv = None if backend() == 'singularity' else \
            sandbox_command(container, provenance['image_ref'], provenance['binary'], cfg)
        if start_argv:
            record['sandbox_command'] = start_argv
            command(start_argv)
        else:
            workdir.mkdir(parents=True, exist_ok=True)
        # A second hash check detects replacement between preflight and mount.
        inside_hash = command(sandbox_exec_argv(container, provenance['image_ref'], provenance['binary'],
                                                str(workdir), 'sha256sum /target/jq', 30)).split()[0]
        if inside_hash != provenance['binary_sha256']:
            raise ValueError('Mounted binary changed after preflight')
        write_json(out / 'sandbox.json', dict(backend=backend(), name=container,
                   image=provenance['image_ref'], binary=provenance['binary'], workdir=str(workdir)))
        worker = [sys.executable, '-m', 'binary_eval.sdk_worker', str(out / 'config.json'),
                  str(out / 'prompts.json'), str(out), container]
        env = os.environ.copy()
        env.update(LITELLM_LOCAL_MODEL_COST_MAP='True', DO_NOT_TRACK='1',
                   OPENHANDS_LOG_DIR=str(out / 'sdk-logs'))
        # SDK discovers ambient plugins in the user's home. Give each worker an
        # empty home and cache so personal skills/MCP tools cannot enter the run.
        isolated_home = out / 'controller-home'
        isolated_home.mkdir()
        env.update(HOME=str(isolated_home), USERPROFILE=str(isolated_home),
                   XDG_CONFIG_HOME=str(isolated_home / 'config'),
                   XDG_CACHE_HOME=str(isolated_home / 'cache'),
                   APPDATA=str(isolated_home / 'config'),
                   LOCALAPPDATA=str(isolated_home / 'cache'))
        # Disable inherited tracing integrations for reproducible local runs.
        for key in list(env):
            if key.startswith(('LAMINAR_', 'LMNR_', 'OTEL_')):
                env.pop(key)
        start_agent = time.monotonic()
        with (out / 'worker.log').open('w', encoding='utf-8') as log:
            proc = subprocess.run(worker, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT,
                                  timeout=cfg['limits']['time_budget_seconds'], check=False)
        record['agent_runtime_seconds'] = round(time.monotonic() - start_agent, 3)
        record['exit_code'] = proc.returncode
        record['status'] = 'completed' if proc.returncode == 0 else 'execution_failure'
        if proc.returncode:
            record['error'] = 'Worker failed; see worker.log'
        if (out / 'worker.json').exists():
            record['worker'] = read_json(out / 'worker.json')
    except subprocess.TimeoutExpired:
        record.update(status='timeout', error='Time budget exceeded; partial logs preserved')
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        record.update(status='execution_failure', error=str(exc))
    except KeyboardInterrupt:
        record.update(status='interrupted', error='Interrupted by operator')
        raise
    finally:
        stop_argv = sandbox_stop_argv(container)
        if stop_argv:
            try:
                command(stop_argv)
            except (OSError, subprocess.SubprocessError) as exc:
                record['cleanup_error'] = str(exc)
        record['runtime_seconds'] = round(time.monotonic() - start, 3)
        finalize_record(record, out, truth)
        write_json(out / 'run.json', record)
    return record


def run_pair(cfg, configurations=CONFIGURATIONS):
    provenance = preflight(cfg)
    batch = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
    # Freeze code/dependency provenance once for both independent conversations.
    provenance['controller_packages'] = sorted(f'{d.metadata["Name"]}=={d.version}'
                                              for d in importlib.metadata.distributions())
    provenance['harness_sha256'] = {p.name: sha256(p) for p in sorted((ROOT / 'binary_eval').glob('*.py'))}
    records = []
    for configuration in configurations:
        record = run_one(cfg, provenance, batch, configuration)
        records.append(record)
        print(f"{record['run_id']}: {record['status']}")
    return records
