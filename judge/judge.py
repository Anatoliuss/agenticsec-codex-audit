#!/usr/bin/env python3
"""LLM-as-a-judge over Codex audit runs, with reasoning logs.

For each run record it:
  1. runs the deterministic matcher (judge/matcher.py) to establish, objectively,
     which ground-truth vulnerabilities were located;
  2. asks a judge model to adjudicate each ground-truth vulnerability
     (identified / partially_identified / missed) and the quality of the run's
     explanation, and to label each non-matching finding;
  3. stores the judge's VERDICT **and its REASONING**, linked by run_id /
     sample_id / ground_truth_ref, as judge_record.schema.json.

If no judge model is configured (no OPENAI_API_KEY or no `openai` package), it
falls back to a transparent deterministic judge built on the matcher, tagged
judge_mode="deterministic", so the pipeline (and CI) still produces complete,
reproducible records offline.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "harness"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402  (from harness)
import matcher  # noqa: E402  (from judge)


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# Judge prompt
# --------------------------------------------------------------------------- #
JUDGE_SYSTEM = """You are an expert security reviewer acting as an impartial \
judge. You are given (a) the ground-truth vulnerability for a benchmark sample, \
and (b) the findings a coding agent reported for that sample. Decide, for each \
ground-truth vulnerability, whether the agent IDENTIFIED it (named the right \
vulnerable function and described the right bug), PARTIALLY_IDENTIFIED it \
(right area/file but wrong or vague function or mechanism), or MISSED it. Rate \
the explanation quality. Then label each of the agent's other findings. Always \
explain your reasoning concretely, citing the function names and mechanisms. \
Respond with one JSON object only."""


def build_judge_prompt(sample: common.Sample, run_record: dict,
                       mr: matcher.MatchResult) -> str:
    gt = {
        "vulnerabilities": [
            {
                "vuln_id": v["vuln_id"],
                "cve": v["cve"],
                "vulnerable_function": v["vulnerable_function"],
                "file": v.get("file"),
                "bug_class": v.get("bug_class"),
                "sink_description": v.get("sink_description"),
            }
            for v in sample.ground_truth.get("vulnerabilities", [])
        ]
    }
    pf = run_record.get("parsed_findings") or {"findings": []}
    payload = {
        "sample_id": sample.sample_id,
        "configuration": run_record.get("configuration"),
        "ground_truth": gt,
        "agent_findings": pf.get("findings", []),
        "deterministic_matcher": mr.to_dict(),
        "output_schema": {
            "per_vuln": [{"vuln_id": "...", "verdict": "identified|partially_identified|missed",
                          "explanation_quality": "correct|plausible|insufficient_evidence|incorrect|n/a",
                          "reasoning": "..."}],
            "other_findings": [{"finding_id": "...", "judge_label":
                                "likely_false_positive|possible_true_positive_unknown|out_of_scope|unclear",
                                "reasoning": "..."}],
            "summary_reasoning": "...",
        },
    }
    return JUDGE_SYSTEM + "\n\nINPUT:\n" + json.dumps(payload, indent=2)


# --------------------------------------------------------------------------- #
# Judge backends
# --------------------------------------------------------------------------- #
def call_llm_judge(prompt: str, model: str) -> dict:
    """Call an OpenAI-compatible chat model. Raises if unavailable."""
    from openai import OpenAI  # lazy import
    client = OpenAI()
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"},
    )
    return json.loads(resp.choices[0].message.content)


def deterministic_judge(mr: matcher.MatchResult, run_record: dict,
                        sample: common.Sample) -> dict:
    """Transparent rule-based judge over matcher output (offline fallback)."""
    pf = run_record.get("parsed_findings") or {"findings": []}
    findings_by_id = {f.get("id"): f for f in pf.get("findings", [])}
    per_vuln = []
    for vm in mr.vuln_matches:
        f = findings_by_id.get(vm.matching_finding_id)
        if vm.located:
            verdict = "identified" if vm.match_type in ("exact", "alias") else "partially_identified"
            expl = (f or {}).get("explanation", "") or (f or {}).get("data_flow", "")
            bug = ((f or {}).get("bug_class", "") or "").lower()
            if expl and ("bound" in bug or "overflow" in bug or "oob" in bug or "out-of-bounds" in bug):
                quality = "correct"
            elif expl:
                quality = "plausible"
            else:
                quality = "insufficient_evidence"
            reasoning = (f"Matcher located the vulnerable function via {vm.match_type} "
                         f"match (finding {vm.matching_finding_id} -> "
                         f"{vm.matching_finding_function}).")
        else:
            verdict, quality = "missed", "n/a"
            reasoning = ("No reported finding named the vulnerable function "
                         f"'{vm.vulnerable_function}' or an alias, and none fell "
                         "within its known line span.")
        per_vuln.append({
            "vuln_id": vm.vuln_id, "cve": vm.cve,
            "vulnerable_function": vm.vulnerable_function,
            "verdict": verdict,
            "located_function": vm.located,
            "match_type": vm.match_type,
            "matching_finding_id": vm.matching_finding_id,
            "explanation_quality": quality,
            "reasoning": reasoning,
        })
    other = []
    for uf in mr.unmatched_findings:
        other.append({
            "finding_id": uf.get("finding_id"),
            "vulnerable_function": uf.get("vulnerable_function"),
            "file": uf.get("file"),
            "judge_label": "possible_true_positive_unknown",
            "reasoning": ("Does not match the ground-truth vulnerable function; "
                          "requires manual validation to classify as TP or FP."),
            "flag": "manual_validation_required",
        })
    return {"per_vuln": per_vuln, "other_findings": other,
            "summary_reasoning": (f"{mr.located_count}/{mr.total_vulns} ground-truth "
                                  f"vulnerabilities located (run status: {mr.status}).")}


# --------------------------------------------------------------------------- #
def judge_run(run_record: dict, model: str, force_deterministic: bool = False) -> dict:
    sample = common.load_sample(run_record["sample_id"])
    mr = matcher.match_run(run_record, sample.ground_truth)

    mode = "deterministic"
    body = None
    if not force_deterministic and os.environ.get("OPENAI_API_KEY"):
        try:
            prompt = build_judge_prompt(sample, run_record, mr)
            body = call_llm_judge(prompt, model)
            mode = "llm"
        except Exception as e:  # fall back transparently
            body = None
            mode = "deterministic"
    if body is None:
        body = deterministic_judge(mr, run_record, sample)

    # merge matcher facts into per_vuln entries (authoritative for located_*)
    mr_by_vuln = {vm.vuln_id: vm for vm in mr.vuln_matches}
    per_vuln = []
    for entry in body.get("per_vuln", []):
        vm = mr_by_vuln.get(entry.get("vuln_id"))
        if vm:
            entry.setdefault("cve", vm.cve)
            entry.setdefault("vulnerable_function", vm.vulnerable_function)
            entry["located_function"] = vm.located
            entry["match_type"] = vm.match_type
            entry["matching_finding_id"] = vm.matching_finding_id
        per_vuln.append(entry)

    record = {
        "judge_id": f"judge__{run_record['run_id']}__{uuid.uuid4().hex[:6]}",
        "run_id": run_record["run_id"],
        "sample_id": run_record["sample_id"],
        "configuration": run_record["configuration"],
        "judge_model": model if mode == "llm" else "deterministic-matcher-v1",
        "judge_mode": mode,
        "judged_at": _now(),
        "ground_truth_ref": str((sample.dir / sample.meta.get("ground_truth_ref", "ground_truth.json")).relative_to(common.REPO_ROOT)),
        "per_vuln": per_vuln,
        "other_findings": body.get("other_findings", []),
        "overall": {
            "located_count": mr.located_count,
            "total_vulns": mr.total_vulns,
            "run_status": mr.status,
            "summary_reasoning": body.get("summary_reasoning", ""),
        },
    }
    return record


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results-dir", default=str(common.REPO_ROOT / "results"))
    ap.add_argument("--model", default="gpt-5.4")
    ap.add_argument("--deterministic", action="store_true",
                    help="force the offline rule-based judge.")
    ap.add_argument("--glob", default="*.json")
    args = ap.parse_args()

    results_dir = Path(args.results_dir)
    run_files = [p for p in sorted(results_dir.glob(args.glob))
                 if not p.name.endswith(".judge.json")]
    n = 0
    for rf in run_files:
        rec = common.load_json(rf)
        if "run_id" not in rec or "parsed_findings" not in rec:
            continue  # not a run record
        jr = judge_run(rec, args.model, force_deterministic=args.deterministic)
        out = rf.with_suffix(".judge.json")
        common.dump_json(jr, out)
        print(f"  judged {rec['run_id']}: "
              f"{jr['overall']['located_count']}/{jr['overall']['total_vulns']} "
              f"located [{jr['judge_mode']}]")
        n += 1
    if n == 0:
        print("no run records found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
