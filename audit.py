#!/usr/bin/env python3
"""Step 1 - run Codex on every benchmark sample, zero-shot and CVE-hinted.

For each (sample, configuration) this
  1. downloads a snapshot of the project at the benchmark commit (a GitHub
     tarball with no git history, so Codex cannot read the later fix commit);
  2. runs `codex exec` on it with the same model, sandbox, tools and time
     budget in both configurations. Only the task prompt differs (the CVE hint);
  3. writes results/runs/<run_id>.json  (run record: settings, prompts, hint,
     runtime, status, findings, known CVE + vulnerable functions) and
     results/runs/<run_id>.jsonl (Codex's raw event stream: every command it
     ran, what it saw, and its final answer).

Usage:
  python audit.py --dry-run          # print the prompts and command, run nothing
  python audit.py                    # all samples x both configurations
  python audit.py --sample P10_faad2_1073aee --configuration zero_shot
  python audit.py --check-samples    # check the ground truth against the real source
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path

from common import (PROMPTS, ROOT, RUNS, codex_command, codex_version, fill,
                    load_config, load_samples, now, run_codex, save_json)

CONFIGS = ("zero_shot", "cve_hinted")
CACHE = ROOT / ".cache"


def build_prompts(sample: dict, configuration: str) -> tuple[str, str, dict | None]:
    """Return (system prompt, task prompt, hint). The hint is None for zero-shot."""
    system = fill("system.md", minutes=load_config()["time_budget_seconds"] // 60)
    base = dict(project=sample["project"], commit=sample["commit"], binary=sample["binary"])
    if configuration == "zero_shot":
        return system, fill("zero_shot.md", **base), None
    cves = [v["cve"] for v in sample["vulnerabilities"]]
    hint = {"cve_ids": cves,
            "text": f"This project revision is associated with {' and '.join(cves)}.",
            "withheld": ["vulnerable function name", "vulnerable file", "sink lines"]}
    return system, fill("cve_hinted.md", hint=hint["text"], **base), hint


def fetch_source(sample: dict, dest: Path) -> Path:
    """Unpack the project at the benchmark commit into dest; returns the source root."""
    CACHE.mkdir(exist_ok=True)
    tarball = CACHE / f"{sample['project']}-{sample['commit']}.tar.gz"
    if not tarball.exists():
        partial = tarball.with_suffix(".part")
        urllib.request.urlretrieve(f"{sample['repo_url']}/archive/{sample['commit']}.tar.gz", partial)
        partial.replace(tarball)
    with tarfile.open(tarball) as tar:
        safe = {"filter": "data"} if hasattr(tarfile, "data_filter") else {}
        tar.extractall(dest, **safe)
    (src,) = [p for p in dest.iterdir() if p.is_dir()]  # GitHub wraps it in <repo>-<sha>/
    return src


def definition_line(source: str, function: str) -> int | None:
    """Line number where `function` is defined (a column-0 line naming it, not a prototype)."""
    for n, line in enumerate(source.splitlines(), 1):
        if re.match(rf"[A-Za-z_][\w\s\*]*?\b{function}\s*\(|{function}\s*\(", line) and ";" not in line:
            return n
    return None


def check_samples(samples: dict) -> None:
    """Validate each sample against its real source: the commit downloads, the
    CVE id is well-formed, and the vulnerable file defines the vulnerable function."""
    report = {"checked_at": now(), "samples": {}}
    for sid, sample in samples.items():
        checks = []
        with tempfile.TemporaryDirectory() as tmp:
            src = fetch_source(sample, Path(tmp))
            for v in sample["vulnerabilities"]:
                path = src / v["file"]
                text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
                line = definition_line(text, v["vulnerable_function"])
                check = {"vuln_id": v["vuln_id"], "cve": v["cve"],
                         "cve_id_well_formed": bool(re.fullmatch(r"CVE-\d{4}-\d{4,}", v["cve"])),
                         "file": v["file"], "file_exists": path.exists(),
                         "function": v["vulnerable_function"], "defined_at_line": line,
                         "expected_line": v.get("function_decl_line")}
                check["ok"] = check["cve_id_well_formed"] and check["file_exists"] and line is not None
                checks.append(check)
                print(f"{'OK  ' if check['ok'] else 'FAIL'} {sid}: {v['cve']} -> "
                      f"{v['vulnerable_function']} at {v['file']}:{line}")
        report["samples"][sid] = checks
    save_json(report, ROOT / "results" / "sample_validation.json")


def last_error(transcript: Path) -> str | None:
    """The last error Codex reported in its event stream (e.g. a refusal), if any."""
    message = None
    for line in transcript.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue  # stderr log lines are mixed into the stream
        if event.get("type") == "error":
            message = event.get("message")
    return message


def run_one(sample: dict, configuration: str, cfg: dict, dry_run: bool = False) -> dict | None:
    system, task, hint = build_prompts(sample, configuration)
    prompt = f"{system}\n---\n\n{task}"
    run_id = f"{sample['sample_id']}__{configuration}__{time.strftime('%Y%m%d-%H%M%S')}"
    transcript = RUNS / f"{run_id}.jsonl"

    tmp = tempfile.mkdtemp(prefix=f"audit_{sample['sample_id']}_")
    try:
        last_message = Path(tmp) / "last_message.json"
        cmd = codex_command(cfg, model=cfg["model"], sandbox=cfg["sandbox"],
                            schema=PROMPTS / "findings.schema.json", last_message=last_message)
        if dry_run:
            print(f"=== {run_id}\n$ {' '.join(cmd)}  < prompt\n\n{prompt}\n")
            return None

        record = {
            "run_id": run_id, "sample_id": sample["sample_id"], "configuration": configuration,
            "model": cfg["model"], "reasoning_effort": cfg["reasoning_effort"],
            "sandbox": cfg["sandbox"], "time_budget_seconds": cfg["time_budget_seconds"],
            "codex_version": codex_version(cfg),
            "codex_command": [a.replace(str(ROOT), "<repo>").replace(tmp, "<tmp>") for a in cmd],
            "repo_url": sample["repo_url"], "repo_revision": sample["commit"], "binary": sample["binary"],
            "hint": hint,
            "prompt_system": system, "prompt_task": task,
            "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
            "started_at": now(), "runtime_seconds": None,
            "status": None, "exit_code": None, "error": None,
            "raw_transcript": transcript.name, "final_message": None,
            "summary": None, "findings": [],
            "known_cves": [v["cve"] for v in sample["vulnerabilities"]],
            "known_vulnerable_functions": [v["vulnerable_function"] for v in sample["vulnerabilities"]],
        }
        RUNS.mkdir(parents=True, exist_ok=True)
        t0 = time.time()
        try:
            src = fetch_source(sample, Path(tmp) / "src")
        except Exception as e:  # download / unpack problem: nothing for Codex to audit
            record.update(status="input_failure", error=f"{type(e).__name__}: {e}")
        else:
            try:
                record["exit_code"] = run_codex(cmd, prompt, cwd=src, transcript=transcript,
                                                timeout=cfg["time_budget_seconds"])
                raw = last_message.read_text(encoding="utf-8") if last_message.exists() else ""
                record["final_message"] = raw
                try:
                    answer = json.loads(raw)
                    record.update(status="ok", summary=answer["summary"], findings=answer["findings"])
                except (json.JSONDecodeError, KeyError, TypeError) as e:
                    record["status"] = "malformed_output" if raw.strip() else (
                        "error" if record["exit_code"] else "no_output")
                    record["error"] = f"could not parse final message: {e}" if raw.strip() else \
                        last_error(transcript) or f"codex exited {record['exit_code']} without a final message"
            except subprocess.TimeoutExpired:
                record.update(status="timeout", error=f"exceeded {cfg['time_budget_seconds']}s budget")
        record["runtime_seconds"] = round(time.time() - t0, 1)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    save_json(record, RUNS / f"{run_id}.json")
    return record


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sample", action="append", help="sample id (repeatable); default: all")
    ap.add_argument("--configuration", action="append", choices=CONFIGS, help="default: both")
    ap.add_argument("--model", help="override the audit model from config.json")
    ap.add_argument("--dry-run", action="store_true", help="print prompts + command only")
    ap.add_argument("--check-samples", action="store_true", help="validate ground truth against source")
    args = ap.parse_args()

    cfg, samples = load_config(), load_samples()
    if args.model:
        cfg["model"] = args.model
    chosen ={sid: samples[sid] for sid in args.sample} if args.sample else samples
    if args.check_samples:
        return check_samples(chosen)
    for sample in chosen.values():
        for configuration in args.configuration or CONFIGS:
            rec = run_one(sample, configuration, cfg, args.dry_run)
            if rec:
                print(f"{rec['run_id']}: {rec['status']} in {rec['runtime_seconds']}s, "
                      f"{len(rec['findings'])} findings")


if __name__ == "__main__":
    main()
