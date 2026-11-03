"""python -m binary_eval {dry-run,preflight,run,report} --config PATH"""
import argparse
import json
import sys

from .core import ASSETS, CONFIGURATIONS, build_prompts, read_json, resolve


def main():
    p = argparse.ArgumentParser(description='OpenHands binary evaluation alongside the Codex audit')
    p.add_argument('action', choices=['dry-run', 'preflight', 'run', 'report'])
    p.add_argument('--config', default=str(ASSETS / 'config.example.json'))
    p.add_argument('--configuration', choices=CONFIGURATIONS, action='append')
    args = p.parse_args()
    cfg = read_json(resolve(args.config))
    if args.action == 'dry-run':
        # No SDK import, Docker commands, HTTP requests, or filesystem writes.
        print(json.dumps({c: build_prompts(cfg, c) for c in args.configuration or CONFIGURATIONS}, indent=2))
    elif args.action == 'report':
        from .reporting import generate_reports
        truth_path = resolve(cfg['target']['ground_truth'])
        truth = read_json(truth_path) if truth_path.exists() else None
        print(generate_reports(resolve(cfg['results_dir']), truth))
    else:
        from .runner import preflight, run_pair
        if args.action == 'preflight':
            result = preflight(cfg)
            print(json.dumps(result, indent=2))
        else:
            results = run_pair(cfg, args.configuration or CONFIGURATIONS)
            from .reporting import generate_reports
            print(generate_reports(resolve(cfg['results_dir'])))
            return 0 if all(r['status'] == 'ok' for r in results) else 1
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError) as exc:
        print(f'Configuration/input error: {exc}', file=sys.stderr)
        sys.exit(2)
