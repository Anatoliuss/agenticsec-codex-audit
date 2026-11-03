"""Offline reports; address/name matches are candidates for human verification."""
from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path

from .core import assess, read_json, write_json


def location(f):
    address = f.get('address')
    return hex(int(address, 16)) if address else f.get('function', '').strip().lower()


def compare_runs(runs):
    configurations = [r['configuration'] for r in runs]
    if len(set(r['comparison_key'] for r in runs)) > 1 or len(set(r['batch_id'] for r in runs)) > 1:
        return dict(status='incompatible', reason='Binary/model/tools/settings or batch differ')
    if sorted(configurations) != ['cve_hinted', 'zero_shot']:
        return dict(status='incomplete', reason='Need exactly one run for each configuration in the batch')
    if any(r.get('status') != 'ok' for r in runs):
        return dict(status='execution_failure', reason='At least one configuration did not yield valid findings')
    by_config = {r['configuration']: r for r in runs}
    a = {location(f) for f in by_config['zero_shot']['findings']} - {''}
    b = {location(f) for f in by_config['cve_hinted']['findings']} - {''}
    return dict(status='comparable', overlap=sorted(a & b), zero_shot_only=sorted(a - b),
                cve_hinted_only=sorted(b - a),
                method='Same reported virtual address, otherwise normalized function name; not semantic equivalence')


def cell(value):
    return str(value).replace('|', '\\|').replace('\n', ' ')


def run_markdown(run):
    assessment = run['assessment']
    usage = run.get('token_usage')
    tokens = f"{usage.get('prompt_tokens')} input / {usage.get('completion_tokens')} output" if usage else 'unavailable'
    lines = [f"## {run['configuration']} — {run['run_id']}", '',
             f"Status: **{run['status']}**. Runtime: {run.get('runtime_seconds', 'unavailable')} s. "
             f"Tokens: {tokens}. Sandbox commands: {run.get('tool_calls', 0)}. "
             f"All SDK tool calls: {run.get('sdk_tool_calls', 0)}.", '',
             f"Known function: **{assessment['known_function_status']}**.", '',
             f"Evidence and raw trajectory: `../runs/{run['run_id']}/`.", '']
    if run.get('error'):
        lines += [f"Execution/input issue: {run['error']}", '']
    if run.get('summary'):
        lines += [run['summary'], '']
    matches = {m['finding']: m for m in assessment['matches']}
    for f in run['findings']:
        lines += [f"### {f['id']}: {f['function'] or 'unnamed'} at {f['address'] or 'unknown address'}", '',
                  f"{f['cwe'] or 'unclassified'}; confidence: {f['confidence']}.", '', f['explanation'], '']
        if f['id'] in matches:
            m = matches[f['id']]
            lines += [f"Candidate ground-truth match to `{m['function']}` by {m['method']}; "
                      'manual validation of the explanation is still required.', '']
        else:
            lines += ['Other finding: manual validation required; not automatically a false positive.', '']
        for e in f['evidence']:
            lines += [f"- {e['kind']} — `{e['reference']}`: {e['detail']}"]
        lines += ['']
        kinds = {e['kind'] for e in f['evidence']}
        if not f['evidence']:
            lines += ['Evidence limitation: no evidence cited.', '']
        elif not kinds & {'disassembly', 'decompilation', 'dynamic'}:
            lines += ['Evidence limitation: no disassembly, decompilation or dynamic evidence cited.', '']
        if not f['address']:
            lines += ['Localization limitation: no virtual address supplied.', '']
    for issue in run.get('evidence_issues', []):
        lines += [f"Evidence issue: {issue['finding']} cites an unavailable output `{issue['reference']}`.", '']
    if assessment['known_function_status'] == 'missed':
        names = [f['name'] for f in run['ground_truth']['vulnerable_functions']]
        lines += ['Missed known function(s): ' + ', '.join(names) + '.', '']
    if run['status'] == 'malformed_output':
        lines += ['Malformed response excerpt:', '', '```text', run.get('raw_findings', '')[:1500], '```', '']
    return '\n'.join(lines)


def generate_reports(results_dir, truth=None):
    root = Path(results_dir)
    paths = sorted((root / 'runs').glob('*/run.json'))
    if not paths:
        raise ValueError('No OpenHands run records found; nothing to report')
    reports = root / 'reports'
    reports.mkdir(parents=True, exist_ok=True)
    runs, batches = [], defaultdict(list)
    for path in paths:
        run = read_json(path)
        if 'assessment' not in run:
            run.update(status='interrupted', findings=[], error='Run record was not finalized')
            run['assessment'] = assess('interrupted', [], {}, run['provenance']['binary_sha256'])
        if truth is not None:
            run['ground_truth'] = truth
            run['assessment'] = assess(run['status'], run['findings'], truth, run['provenance']['binary_sha256'])
        runs.append(run)
        batches[run['batch_id']].append(run)
        (reports / f"{run['run_id']}.md").write_text(run_markdown(run), encoding='utf-8')
    comparisons = {batch: compare_runs(items) for batch, items in batches.items()}
    lines = ['# OpenHands binary evaluation — agenticsec-codex-audit', '',
             'Target: jq at f58787c. Codex source-audit results remain separate.', '',
             '| Run | Configuration | Status | Known function | Seconds | Commands |',
             '|---|---|---|---|---:|---:|']
    for r in runs:
        values = [r['run_id'], r['configuration'], r['status'], r['assessment']['known_function_status'],
                  r.get('runtime_seconds', 'unavailable'), r.get('tool_calls', 0)]
        lines.append('| ' + ' | '.join(cell(v) for v in values) + ' |')
    lines += ['', '## Paired comparisons', '']
    for batch, comparison in comparisons.items():
        lines += [f"### {batch}", '', f"Pair status: **{comparison['status']}**.", '']
        if comparison['status'] == 'comparable':
            for key in ('overlap', 'zero_shot_only', 'cve_hinted_only'):
                lines += [f"- {key}: {', '.join(comparison[key]) or 'none'}"]
            lines += ['', comparison['method'] + '.', '']
        else:
            lines += [comparison['reason'] + '.', '']
    lines += ['## Interpretation and limitations', '',
              'Matches identify a candidate function/location, not a validated vulnerability. '
              'Inspect the cited instructions, decompiled operations and dynamic outputs. '
              'Other functions are candidates for manual validation, not automatically incorrect findings.', '',
              'Missing ground truth is reported as unverified; execution/input failures are not scored as misses. '
              'Unavailable token usage is null, never silently estimated as zero. '
              'The serving model revision/license/command are operator-supplied provenance; '
              'the model endpoint confirms the served ID only. '
              'Identical sampling settings do not guarantee deterministic inference.', '',
              'Per-run sections below retain missed functions, other-function candidates, evidence gaps, '
              'malformed-response excerpts, and execution failures for qualitative review.', '']
    lines.extend(run_markdown(r) for r in runs)
    content = '\n'.join(lines)
    (reports / 'comparison.md').write_text(content, encoding='utf-8')
    (reports / 'jq_f58787c.md').write_text(content, encoding='utf-8')
    write_json(reports / 'comparison.json', dict(
        comparisons=comparisons,
        statuses=dict(Counter(r['status'] for r in runs)),
        assessments={r['run_id']: r['assessment'] for r in runs},
        ground_truth_override=truth))
    return reports / 'comparison.md'
