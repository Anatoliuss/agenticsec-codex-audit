#!/usr/bin/env python3
"""Run the Codex audit over the benchmark, in both configurations.

For each (sample, configuration) this:
  1. checks out the sample's repo at the pinned commit into a scratch workdir;
  2. invokes `codex exec` with the system + task prompt, capturing the raw
     event stream (JSONL) to results/<run_id>.jsonl;
  3. parses the final message for the findings JSON;
  4. writes a run record (run_record.schema.json) to results/<run_id>.json.

The only difference between the two configurations is the task prompt: the
CVE hint. Model, sandbox, tools, and time budget are held constant via
config.yaml.

Codex runs execute untrusted project build/run steps, so run this inside the
Docker image for the sample (see benchmark/samples/*/Dockerfile) or another
isolated sandbox. Use --dry-run to exercise the plumbing without calling Codex
or cloning anything (useful in CI / offline).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def load_config(path: Path) -> dict:
    if yaml is None:
        raise SystemExit("PyYAML is required to read config.yaml (pip install pyyaml)")
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def checkout_repo(sample: common.Sample, workdir: Path) -> Path:
    """Clone + checkout the pinned commit. Returns the source dir."""
    src = workdir / "src"
    subprocess.run(["git", "clone", "--quiet", sample.repo_url, str(src)], check=True)
    subprocess.run(["git", "-C", str(src), "checkout", "--quiet", sample.commit], check=True)
    return src


def build_codex_cmd(cfg: dict, system: str, task: str, workdir: Path) -> list[str]:
    c = cfg["codex"]
    prompt = f"{system}\n\n---\n\n{task}"
    cmd = [
        c.get("bin", "codex"), "exec",
        "--json",
        "--model", c["model"],
        "--sandbox", c.get("sandbox", "workspace-write"),
        "--cd", str(workdir),
        "--skip-git-repo-check",
    ]
    ap = c.get("approval_policy")
    if ap:
        cmd += ["--ask-for-approval", ap] if ap != "never" else ["--dangerously-bypass-approvals-and-sandbox"] if c.get("sandbox") == "danger-full-access" else ["-a", "never"]
    cmd += list(c.get("extra_args", []))
    cmd += [prompt]
    return cmd


def run_one(sample: common.Sample, configuration: str, cfg: dict,
            results_dir: Path, dry_run: bool, rep: int = 0) -> dict:
    c = cfg["codex"]
    cve_id = sample.cve_ids[0] if sample.cve_ids else None
    system = common.system_prompt()
    task = common.render_task_prompt(sample, configuration, cve_id=cve_id)

    run_id = f"{sample.sample_id}__{configuration}__r{rep}__{uuid.uuid4().hex[:8]}"
    transcript_path = results_dir / f"{run_id}.jsonl"
    record_path = results_dir / f"{run_id}.json"

    hint = None
    if configuration == "cve_hinted":
        hint = {
            "cve_id": cve_id,
            "hint_text": f"This project revision is associated with {cve_id}.",
            "withheld": ["vulnerable_function_name"],
        }

    record = {
        "run_id": run_id,
        "sample_id": sample.sample_id,
        "configuration": configuration,
        "model": c["model"],
        "model_settings": {
            "reasoning_effort": c.get("reasoning_effort"),
            "temperature": c.get("temperature"),
            "sandbox": c.get("sandbox"),
            "approval_policy": c.get("approval_policy"),
            "time_budget_seconds": c.get("time_budget_seconds"),
            "tools": ["read", "build", "run", "shell"],
        },
        "repo_url": sample.repo_url,
        "repo_revision": sample.commit,
        "binary": sample.binary,
        "hint": hint,
        "prompt_system_sha256": common.sha256_text(system),
        "prompt_task_sha256": common.sha256_text(task),
        "prompt_task_rendered": task,
        "started_at": _now(),
        "finished_at": None,
        "runtime_seconds": 0.0,
        "status": "ok",
        "exit_code": None,
        "raw_transcript_path": transcript_path.name,
        "parsed_findings": None,
        "parse_error": None,
        "known_cve": sample.cve_ids,
        "known_vulnerable_functions": sample.vulnerable_functions,
        "notes": "",
    }

    if dry_run:
        record["status"] = "ok"
        record["finished_at"] = _now()
        record["notes"] = "dry-run: Codex not invoked; no findings produced."
        common.dump_json(record, record_path)
        return record

    workdir = Path(tempfile.mkdtemp(prefix=f"codexrun_{sample.sample_id}_"))
    t0 = time.time()
    final_text = ""
    try:
        src = checkout_repo(sample, workdir)
        cmd = build_codex_cmd(cfg, system, task, src)
        budget = int(c.get("time_budget_seconds", 7200))
        with open(transcript_path, "w", encoding="utf-8") as tf:
            proc = subprocess.run(
                cmd, stdout=tf, stderr=subprocess.STDOUT,
                timeout=budget, check=False,
            )
        record["exit_code"] = proc.returncode
        final_text = extract_final_message(transcript_path)
        obj, err = common.extract_findings_json(final_text)
        record["parsed_findings"] = obj
        record["parse_error"] = err
        if err:
            record["status"] = "malformed_output" if final_text else "no_output"
        elif proc.returncode != 0:
            record["status"] = "error"
    except subprocess.TimeoutExpired:
        record["status"] = "timeout"
        record["notes"] = f"exceeded time budget of {c.get('time_budget_seconds')}s"
    except subprocess.CalledProcessError as e:
        record["status"] = "build_failure" if "clone" not in str(e) else "error"
        record["notes"] = f"git/checkout failed: {e}"
    except Exception as e:  # pragma: no cover
        record["status"] = "error"
        record["notes"] = f"{type(e).__name__}: {e}"
    finally:
        record["runtime_seconds"] = round(time.time() - t0, 2)
        record["finished_at"] = _now()
        shutil.rmtree(workdir, ignore_errors=True)

    common.dump_json(record, record_path)
    return record


def extract_final_message(transcript_path: Path) -> str:
    """Pull Codex's final agent message out of the JSONL event stream.

    Codex `exec --json` emits one JSON event per line. We keep the text of the
    last assistant/agent message event. Event shapes vary across Codex
    versions, so we look for a few known keys defensively."""
    final = ""
    try:
        with open(transcript_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                txt = _event_text(ev)
                if txt:
                    final = txt
    except FileNotFoundError:
        return ""
    return final


def _event_text(ev: dict) -> str | None:
    if not isinstance(ev, dict):
        return None
    # common shapes: {"type":"item.completed","item":{"type":"agent_message","text":...}}
    item = ev.get("item") or ev.get("msg") or {}
    for key in ("text", "message", "content", "last_agent_message"):
        v = item.get(key) if isinstance(item, dict) else None
        if isinstance(v, str) and v.strip():
            return v
        v2 = ev.get(key)
        if isinstance(v2, str) and v2.strip():
            return v2
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default=str(Path(__file__).parent / "config.yaml"))
    ap.add_argument("--sample", action="append", help="sample_id(s); default all")
    ap.add_argument("--configuration", choices=["zero_shot", "cve_hinted"],
                    action="append", help="default: both")
    ap.add_argument("--results-dir", default=None)
    ap.add_argument("--dry-run", action="store_true",
                    help="exercise plumbing without calling Codex or cloning.")
    args = ap.parse_args()

    cfg = load_config(Path(args.config))
    samples = ([common.load_sample(s) for s in args.sample]
               if args.sample else common.load_all_samples())
    configs = args.configuration or cfg["run"]["configurations"]
    reps = int(cfg["run"].get("repetitions", 1))
    results_dir = Path(args.results_dir or (Path(args.config).parent / cfg["run"]["results_dir"])).resolve()
    results_dir.mkdir(parents=True, exist_ok=True)

    print(f"results -> {results_dir}")
    for sample in samples:
        for configuration in configs:
            for rep in range(reps):
                rec = run_one(sample, configuration, cfg, results_dir,
                              dry_run=args.dry_run, rep=rep)
                print(f"  {rec['run_id']}: {rec['status']} "
                      f"({rec['runtime_seconds']}s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
