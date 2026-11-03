#!/usr/bin/env python3
"""Step 2 - judge every audit run against the ground truth, keeping the judge's reasoning.

For each results/runs/<run_id>.json this writes results/judgments/<run_id>.judge.json with
  - matcher: a deterministic check per known vulnerability: does a finding name
    the vulnerable function ("exact"), a related function from match_aliases
    ("alias"), or neither ("none")?
  - the LLM judge's verdict per known vulnerability (identified / partially /
    missed, plus explanation quality) AND its reasoning. The judge runs through
    `codex exec`, so it uses your Codex login (no API key needed);
  - a label and reasoning for every other finding, each flagged
    "manual_validation_required";
  - links to the run record and the ground-truth entries, plus the exact judge
    prompt and the judge's raw response.

Usage:
  python judge.py              # LLM judge + matcher
  python judge.py --offline    # matcher only, no model calls
"""
from __future__ import annotations

import argparse
import json
import re
import tempfile
from pathlib import Path

from common import (JUDGMENTS, PROMPTS, RUNS, codex_command, fill, load_config,
                    load_json, load_samples, now, run_codex, save_json)

MATCHER_VERDICT = {"exact": "identified", "alias": "partially_identified", "none": "missed"}


def names_in(text: str | None) -> set[str]:
    """Identifiers mentioned in a finding's function field, lowercased.
    'frontend/mp4read.c:stszin()' -> {'frontend', 'mp4read', 'c', 'stszin'}"""
    return set(re.findall(r"[a-z_]\w*", (text or "").lower()))


def match(vuln: dict, findings: list[dict]) -> tuple[str, str | None]:
    """(match_type, finding_id) for one known vulnerability: 'exact' if a finding
    names the vulnerable function, 'alias' if it names a related function from
    match_aliases, otherwise ('none', None)."""
    aliases = {a.lower() for a in vuln.get("match_aliases", [])}
    best = ("none", None)
    for f in findings:
        names = names_in(f.get("vulnerable_function"))
        if vuln["vulnerable_function"].lower() in names:
            return "exact", f["id"]
        if best[0] == "none" and names & aliases:
            best = ("alias", f["id"])
    return best


def judge_prompt(run: dict, sample: dict) -> str:
    keys = ("vuln_id", "cve", "bug_class", "vulnerable_function", "match_aliases", "file", "sink_description")
    truth = [{k: v[k] for k in keys if k in v} for v in sample["vulnerabilities"]]
    return fill("judge.md", configuration=run["configuration"],
                ground_truth=json.dumps(truth, indent=2), findings=json.dumps(run["findings"], indent=2))


def ask_llm_judge(prompt: str, cfg: dict) -> str:
    """Run the judge model via `codex exec` in an empty read-only folder; returns its raw JSON answer."""
    with tempfile.TemporaryDirectory() as tmp:
        answer, transcript = Path(tmp) / "judge.json", Path(tmp) / "judge.jsonl"
        cmd = codex_command(cfg, model=cfg["judge_model"], sandbox="read-only",
                            schema=PROMPTS / "judge.schema.json", last_message=answer)
        code = run_codex(cmd, prompt, cwd=tmp, transcript=transcript, timeout=900)
        if not answer.exists():
            tail = transcript.read_text(encoding="utf-8", errors="replace")[-500:]
            raise RuntimeError(f"codex exited {code} without an answer: {tail}")
        return answer.read_text(encoding="utf-8")


def matcher_verdict(run: dict, match_type: str, finding_id: str | None) -> dict:
    """Fallback verdict when there is no LLM verdict (offline, no findings, or a judge error)."""
    if not run["findings"]:
        why = f"Run status '{run['status']}': no findings to judge."
    elif match_type == "none":
        why = "Matcher only: no finding names the vulnerable function or a listed alias."
    else:
        what = "the vulnerable function" if match_type == "exact" else "a related function (alias)"
        why = f"Matcher only: finding {finding_id} names {what}."
    return {"verdict": MATCHER_VERDICT[match_type], "explanation_quality": "n/a",
            "matching_finding_id": finding_id, "reasoning": why}


def judge_run(run: dict, sample: dict, cfg: dict, offline: bool = False) -> dict:
    findings, vulns = run["findings"], sample["vulnerabilities"]
    matches = {v["vuln_id"]: match(v, findings) for v in vulns}
    record = {
        "run_id": run["run_id"], "sample_id": run["sample_id"], "configuration": run["configuration"],
        "links": {"run_record": f"results/runs/{run['run_id']}.json",
                  "ground_truth": [f"benchmark/samples.json#{sample['sample_id']}/{v['vuln_id']}" for v in vulns]},
        "judged_at": now(), "judge_mode": "matcher", "judge_model": None,
        "judge_prompt": None, "judge_raw_response": None, "judge_error": None,
    }

    llm = {}
    if findings and not offline:
        prompt = judge_prompt(run, sample)
        record.update(judge_model=cfg["judge_model"], judge_prompt=prompt)
        try:
            record["judge_raw_response"] = ask_llm_judge(prompt, cfg)
            llm = json.loads(record["judge_raw_response"])
            record["judge_mode"] = "llm"
        except Exception as e:  # keep the matcher result, but record why the LLM verdict is missing
            record["judge_error"] = f"{type(e).__name__}: {e}"
    llm_verdicts = {p["vuln_id"]: p for p in llm.get("per_vuln", [])}

    per_vuln = []
    for v in vulns:
        match_type, finding_id = matches[v["vuln_id"]]
        verdict = llm_verdicts.get(v["vuln_id"]) or matcher_verdict(run, match_type, finding_id)
        per_vuln.append({"vuln_id": v["vuln_id"], "cve": v["cve"], "vulnerable_function": v["vulnerable_function"],
                         "matcher": {"match_type": match_type, "finding_id": finding_id},
                         **{k: verdict[k] for k in ("verdict", "explanation_quality", "matching_finding_id", "reasoning")}})

    # every finding that does not correspond to a known vulnerability goes to manual validation
    matched = {fid for _, fid in matches.values()} | {p["matching_finding_id"] for p in per_vuln}
    labels = {o["finding_id"]: o for o in llm.get("other_findings", [])}
    other = [{"finding_id": f["id"], "vulnerable_function": f["vulnerable_function"],
              "file": f["file"], "lines": f.get("lines", []),
              "label": labels.get(f["id"], {}).get("label", "unjudged"),
              "reasoning": labels.get(f["id"], {}).get("reasoning", "No LLM verdict."),
              "flag": "manual_validation_required"}
             for f in findings if f["id"] not in matched]

    located = [m for m, _ in matches.values()]
    record.update(per_vuln=per_vuln, other_findings=other, overall={
        "run_status": run["status"], "total_vulns": len(vulns),
        "located_exact": located.count("exact"),
        "located_incl_aliases": located.count("exact") + located.count("alias"),
        "identified_by_judge": sum(p["verdict"] == "identified" for p in per_vuln),
        "summary_reasoning": llm.get("summary_reasoning", ""),
    })
    return record


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--offline", action="store_true", help="matcher only, no model calls")
    args = ap.parse_args()

    cfg, samples = load_config(), load_samples()
    runs = sorted(RUNS.glob("*.json"))
    for path in runs:
        run = load_json(path)
        rec = judge_run(run, samples[run["sample_id"]], cfg, args.offline)
        save_json(rec, JUDGMENTS / f"{run['run_id']}.judge.json")
        o = rec["overall"]
        print(f"{run['run_id']}: {o['located_exact']}/{o['total_vulns']} located, "
              f"{o['identified_by_judge']} identified by judge [{rec['judge_mode']}]"
              + (f"  (judge error: {rec['judge_error'][:80]})" if rec["judge_error"] else ""))
    if not runs:
        print(f"no run records in {RUNS}; run audit.py first")


if __name__ == "__main__":
    main()
