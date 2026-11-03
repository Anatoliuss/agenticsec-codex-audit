"""Offline behavior tests: python -m unittest test_binary_eval -v."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from binary_eval.core import (build_prompts, validate_config, parse_findings,
                              assess, comparison_key, sandbox_command)
from binary_eval.runner import finalize_record

ROOT = Path(__file__).resolve().parent


def config():
    cfg = json.loads((ROOT / 'openhands/config.example.json').read_text())
    cfg['model'].update(id='test/coder', revision='a' * 40, license='Apache-2.0')
    cfg['serving'].update(image='local/server@sha256:' + 'b' * 64,
                          command=['vllm', 'serve', 'test/coder', '--revision', 'a' * 40])
    return cfg


def finding(address='0x401000', function='sub_401000'):
    return dict(id='F1', function=function, address=address, cwe='CWE-674',
                explanation='Unbounded recursive call on nested input.',
                evidence=[dict(kind='disassembly', reference='tool-0001.txt',
                               detail='0x401020 calls 0x401000 without a depth guard')],
                confidence='medium')


class BinaryEvaluationTests(unittest.TestCase):
    def test_prompts_only_hint_cve_and_never_ground_truth(self):
        cfg = config()
        plain = build_prompts(cfg, 'zero_shot')
        hinted = build_prompts(cfg, 'cve_hinted')
        self.assertNotIn('CVE-', plain['task'])
        self.assertNotIn('CWE-674', plain['system'] + plain['task'])
        self.assertEqual(plain['system'], hinted['system'])
        self.assertIn('CVE-2026-44777', hinted['task'])
        self.assertNotIn('f58787c', plain['task'])

    def test_config_requires_model_revision_and_serving_provenance(self):
        cfg = config()
        validate_config(cfg)
        for section, key, value in [('model', 'revision', 'main'),
                                     ('model', 'license', ''),
                                     ('serving', 'image', 'vllm:latest')]:
            bad = copy.deepcopy(cfg)
            bad[section][key] = value
            with self.assertRaises(ValueError):
                validate_config(bad)
        cfg['limits']['max_iterations'] = 0
        with self.assertRaises(ValueError):
            validate_config(cfg)

    def test_sandbox_only_mounts_binary_readonly_and_has_no_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / 'jq'
            binary.write_bytes(b'\x7fELF')
            cmd = sandbox_command('test-container', 'sha256:' + 'a' * 64, binary, config())
            self.assertIn('--network=none', cmd)
            self.assertIn('--read-only', cmd)
            mounts = [cmd[i + 1] for i, v in enumerate(cmd) if v == '--mount']
            self.assertEqual(len(mounts), 1)
            self.assertIn('target=/target/jq,readonly', mounts[0])
            self.assertNotIn('/var/run/docker.sock', ' '.join(cmd))

    def test_malformed_findings_are_not_accepted(self):
        self.assertEqual(parse_findings(json.dumps({'summary': 'none', 'findings': []}))['findings'], [])
        for obj in [[], {}, {'summary': 'x', 'findings': [{}]},
                    {'summary': 'x', 'findings': [finding('not an address')]}]:
            with self.assertRaises(ValueError):
                parse_findings(json.dumps(obj))

    def test_verified_address_matches_stripped_function(self):
        truth = dict(status='verified', binary_sha256='a' * 64,
                     cve='CVE-2026-44777',
                     reference='annotation row 4', vulnerable_functions=[
                         dict(name='known_function', addresses=['0x401000'])])
        result = assess('ok', [finding()], truth, 'a' * 64)
        self.assertEqual(result['known_function_status'], 'located')
        self.assertEqual(result['matches'][0]['method'], 'address')
        self.assertEqual(assess('ok', [finding()], truth, 'b' * 64)['known_function_status'],
                         'unverified_ground_truth')

    def test_failure_or_missing_truth_is_not_a_missed_function(self):
        self.assertEqual(assess('timeout', [], {}, 'a' * 64)['known_function_status'], 'not_evaluated')
        self.assertEqual(assess('ok', [], {}, 'a' * 64)['known_function_status'], 'unverified_ground_truth')

    def test_comparison_fingerprint_includes_binary_model_and_settings(self):
        cfg = config()
        key = comparison_key(cfg, 'a' * 64, 'sha256:tools', 'system text')
        different = copy.deepcopy(cfg)
        different['sampling']['temperature'] = 0.8
        self.assertNotEqual(key, comparison_key(different, 'a' * 64, 'sha256:tools', 'system text'))
        self.assertNotEqual(key, comparison_key(cfg, 'b' * 64, 'sha256:tools', 'system text'))

    def test_partial_output_does_not_override_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / 'final.txt').write_text(json.dumps({'summary': 'x', 'findings': [finding()]}))
            rec = dict(status='timeout', provenance={'binary_sha256': 'a' * 64})
            result = finalize_record(rec, out, {})
            self.assertEqual(result['status'], 'timeout')
            self.assertEqual(result['assessment']['known_function_status'], 'not_evaluated')
            self.assertIsNone(result['token_usage'])

    def test_reports_never_pair_different_experiments(self):
        from binary_eval.reporting import compare_runs
        a = dict(configuration='zero_shot', comparison_key='A', batch_id='batch', findings=[])
        b = dict(configuration='cve_hinted', comparison_key='B', batch_id='batch', findings=[])
        self.assertEqual(compare_runs([a, b])['status'], 'incompatible')

    def test_reports_show_missing_configuration_and_evidence_limits(self):
        from binary_eval.reporting import compare_runs
        a = dict(configuration='zero_shot', comparison_key='A', batch_id='batch', findings=[])
        self.assertEqual(compare_runs([a])['status'], 'incomplete')

    def test_nonfinished_worker_is_not_success_even_with_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / 'final.txt').write_text(json.dumps({'summary': 'x', 'findings': []}))
            rec = dict(status='completed', worker={'execution_status': 'stuck'},
                       provenance={'binary_sha256': 'a' * 64})
            self.assertEqual(finalize_record(rec, out, {})['status'], 'execution_failure')

    def test_successful_pair_writes_reports_and_preserves_evidence(self):
        from binary_eval.reporting import generate_reports
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for configuration in ('zero_shot', 'cve_hinted'):
                run_id = 'batch__' + configuration
                out = root / 'runs' / run_id
                out.mkdir(parents=True)
                (out / 'final.txt').write_text(json.dumps({'summary': 'Synthetic test only', 'findings': [finding()]}))
                (out / 'tool-0001.txt').write_text('Synthetic disassembly fixture')
                (out / 'tools.jsonl').write_text('{}\n')
                rec = dict(run_id=run_id, batch_id='batch', configuration=configuration,
                           comparison_key='A', status='completed', runtime_seconds=2,
                           worker={'execution_status': 'finished'}, provenance={'binary_sha256': 'a' * 64})
                rec = finalize_record(rec, out, {})
                self.assertEqual(rec['status'], 'ok')
                self.assertEqual(rec['evidence_issues'], [])
                (out / 'run.json').write_text(json.dumps(rec))
            report = generate_reports(root)
            summary = json.loads((report.parent / 'comparison.json').read_text())
            self.assertEqual(summary['comparisons']['batch']['overlap'], ['0x401000'])
            self.assertIn('unverified_ground_truth', report.read_text())
            self.assertTrue((report.parent / 'jq_f58787c.md').exists())

    def test_serving_token_budget_flags_are_not_mistaken_for_credentials(self):
        cfg = config()
        cfg['serving']['command'] += ['--max-num-batched-tokens', '8192']
        validate_config(cfg)

    def test_ground_truth_other_cve_is_not_accepted(self):
        truth = dict(status='verified', binary_sha256='a' * 64, reference='wrong row',
                     cve='CVE-2020-0001', vulnerable_functions=[dict(name='sub_401000', addresses=[])])
        self.assertEqual(assess('ok', [finding()], truth, 'a' * 64)['known_function_status'],
                         'unverified_ground_truth')

    def test_truncated_metrics_preserve_timeout_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / 'metrics.json').write_text('{"accumulated_token_usage":')
            rec = dict(status='timeout', provenance={'binary_sha256': 'a' * 64})
            result = finalize_record(rec, out, {})
            self.assertEqual(result['status'], 'timeout')
            self.assertIsNone(result['token_usage'])
            self.assertIn('metrics_error', result)

    def test_shell_command_stays_inside_container_and_preserves_tool_path(self):
        from binary_eval.sdk_worker import DockerShell
        with tempfile.TemporaryDirectory() as tmp:
            def docker_process(args, **kwargs):
                self.assertEqual(args[:5], ['docker', 'exec', '-w', '/work', 'sandbox-123'])
                self.assertEqual(args[-3:], ['bash', '-c', 'python -c "import angr"'])
                self.assertNotIn('shell', kwargs)
                kwargs['stdout'].write('angr imported')
                import subprocess
                return subprocess.CompletedProcess(args, 0)
            with patch('binary_eval.sdk_worker.subprocess.run', side_effect=docker_process):
                output = DockerShell('sandbox-123', tmp, 5)('python -c "import angr"')
            self.assertIn('tool-0001.txt', output)
            self.assertEqual((Path(tmp) / 'tool-0001.txt').read_text(), 'angr imported')


if __name__ == '__main__':
    unittest.main()
