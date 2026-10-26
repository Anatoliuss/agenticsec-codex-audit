#!/usr/bin/env python3
"""Generate per-sample and aggregate Markdown reports from run + judge records.

Reads results/*.json (run records) and results/*.judge.json (judge records),
and writes:
  reports/out/<sample_id>.md      per-sample zero-shot vs CVE-hinted comparison
  reports/out/comparison.md       aggregate comparison + qualitative analysis

The aggregate report covers, per the deliverable spec: whether each
configuration located the known vulnerable function, differences and overlap,
runtime, evidence quality, and representative examples of missed known
functions, incorrect functions, insufficient evidence, malformed responses,
and execution/input failures.
"""
from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "harness"))
import common  # noqa: E402

CONFIGS = ["zero_shot", "cve_hinted"]
CONFIG_LABEL = {"zero_shot": "Zero-shot", "cve_hinted": "CVE-hinted"}


def load_records(results_dir: Path):
    runs, judges = {}, {}
    for p in sorted(results_dir.glob("*.json")):
        rec = common.load_json(p)
        if p.name.endswith(".judge.json"):
            judges[rec["run_id"]] = rec
        elif "run_id" in rec and "configuration" in rec:
            runs[rec["run_id"]] = rec
    return runs, judges


def _findings(run: dict) -> list[dict]:
    pf = run.get("parsed_findings") or {}
    return pf.get("findings", []) if isinstance(pf, dict) else []


def per_sample_md(sample_id: str, runs: dict, judges: dict) -> str:
    sample = common.load_sample(sample_id)
    gt = sample.ground_truth
    L = []
    L.append(f"# {sample_id} — {sample.project} @ {sample.meta['commit_short']}")
    L.append("")
    L.append(f"- **Binary:** `{sample.binary}`")
    L.append(f"- **Commit:** `{sample.commit}`")
    L.append(f"- **Ground-truth vulnerabilities ({gt and len(gt['vulnerabilities'])}):**")
    for v in gt["vulnerabilities"]:
        L.append(f"  - `{v['vulnerable_function']}` — {v['cve']} — {v['bug_class']} "
                 f"({v.get('file')})")
    L.append("")

    sample_runs = {c: [r for r in runs.values()
                       if r["sample_id"] == sample_id and r["configuration"] == c]
                   for c in CONFIGS}

    L.append("## Result summary")
    L.append("")
    L.append("| Configuration | Status | Runtime (s) | Located / Total | #Findings | #Flagged other |")
    L.append("|---|---|---|---|---|---|")
    for c in CONFIGS:
        for r in sample_runs[c]:
            j = judges.get(r["run_id"])
            loc = f"{j['overall']['located_count']}/{j['overall']['total_vulns']}" if j else "–"
            nother = len(j["other_findings"]) if j else 0
            L.append(f"| {CONFIG_LABEL[c]} | {r['status']} | {r['runtime_seconds']} | "
                     f"{loc} | {len(_findings(r))} | {nother} |")
    L.append("")

    for c in CONFIGS:
        for r in sample_runs[c]:
            j = judges.get(r["run_id"])
            L.append(f"### {CONFIG_LABEL[c]} — run `{r['run_id']}`")
            if c == "cve_hinted" and r.get("hint"):
                L.append(f"*Hint given:* {r['hint']['cve_id']} "
                         f"(withheld: {', '.join(r['hint'].get('withheld', []))})")
            L.append("")
            if j:
                for pv in j["per_vuln"]:
                    mark = {"identified": "✅", "partially_identified": "🟡",
                            "missed": "❌"}.get(pv["verdict"], "?")
                    L.append(f"- {mark} **{pv['vulnerable_function']}** "
                             f"({pv['cve']}): *{pv['verdict']}*, "
                             f"explanation: *{pv.get('explanation_quality','n/a')}* "
                             f"(match: {pv.get('match_type','none')})")
                    L.append(f"  - judge: {pv['reasoning']}")
                if j["other_findings"]:
                    L.append("")
                    L.append("  Other findings flagged for manual validation:")
                    for of in j["other_findings"]:
                        L.append(f"  - `{of.get('vulnerable_function')}` "
                                 f"({of.get('file')}) — {of.get('judge_label')}: "
                                 f"{of.get('reasoning')}")
            if r["status"] not in ("ok",):
                L.append(f"  - run note: **{r['status']}** {r.get('notes','')}")
            L.append("")
    return "\n".join(L) + "\n"


def aggregate_md(runs: dict, judges: dict) -> str:
    samples = common.load_all_samples()
    L = []
    L.append("# Codex zero-shot vs CVE-hinted — aggregate comparison")
    L.append("")
    L.append("Benchmark subset: VERITAS P8–P10 (ezxml, libredwg ×2, faad2), "
             "out-of-bounds vulnerabilities.")
    L.append("")

    # headline table
    L.append("## Located known vulnerable function (per sample)")
    L.append("")
    L.append("| Sample | Binary | GT vulns | Zero-shot located | CVE-hinted located | Zero-shot runtime | CVE-hinted runtime |")
    L.append("|---|---|---|---|---|---|---|")
    totals = defaultdict(lambda: [0, 0])  # config -> [located, total]
    for s in samples:
        row = {"zero_shot": ("–", "–"), "cve_hinted": ("–", "–")}
        for c in CONFIGS:
            rs = [r for r in runs.values()
                  if r["sample_id"] == s.sample_id and r["configuration"] == c]
            if rs:
                r = rs[0]
                j = judges.get(r["run_id"])
                if j:
                    loc = j["overall"]["located_count"]
                    tot = j["overall"]["total_vulns"]
                    row[c] = (f"{loc}/{tot}", f"{r['runtime_seconds']}s")
                    totals[c][0] += loc
                    totals[c][1] += tot
        L.append(f"| {s.sample_id} | `{s.binary}` | {len(s.ground_truth['vulnerabilities'])} "
                 f"| {row['zero_shot'][0]} | {row['cve_hinted'][0]} "
                 f"| {row['zero_shot'][1]} | {row['cve_hinted'][1]} |")
    L.append("")
    zs, ch = totals["zero_shot"], totals["cve_hinted"]
    def rec(t):
        return f"{t[0]}/{t[1]} ({100.0*t[0]/t[1]:.0f}%)" if t[1] else "–"
    L.append(f"**Overall recall of the known vulnerable function:** "
             f"zero-shot {rec(zs)}, CVE-hinted {rec(ch)}.")
    L.append("")

    # overlap
    L.append("## Overlap between configurations")
    L.append("")
    L.append("| Sample | Located by zero-shot only | Located by CVE-hinted only | Located by both | Located by neither |")
    L.append("|---|---|---|---|---|")
    for s in samples:
        loc = {}
        for c in CONFIGS:
            rs = [r for r in runs.values()
                  if r["sample_id"] == s.sample_id and r["configuration"] == c]
            s_set = set()
            if rs and judges.get(rs[0]["run_id"]):
                for pv in judges[rs[0]["run_id"]]["per_vuln"]:
                    if pv.get("located_function"):
                        s_set.add(pv["vuln_id"])
            loc[c] = s_set
        only_zs = loc["zero_shot"] - loc["cve_hinted"]
        only_ch = loc["cve_hinted"] - loc["zero_shot"]
        both = loc["zero_shot"] & loc["cve_hinted"]
        allv = {v["vuln_id"] for v in s.ground_truth["vulnerabilities"]}
        neither = allv - loc["zero_shot"] - loc["cve_hinted"]
        L.append(f"| {s.sample_id} | {len(only_zs)} | {len(only_ch)} | {len(both)} | {len(neither)} |")
    L.append("")

    # qualitative buckets
    L.append("## Qualitative analysis")
    L.append("")
    buckets = {"missed_known": [], "incorrect_function": [], "insufficient_evidence": [],
               "malformed": [], "execution_or_input_failure": []}
    for r in runs.values():
        j = judges.get(r["run_id"])
        if r["status"] in ("timeout", "build_failure", "input_failure", "error"):
            buckets["execution_or_input_failure"].append((r, "status=" + r["status"]))
        if r["status"] in ("malformed_output", "no_output"):
            buckets["malformed"].append((r, r.get("parse_error", "")))
        if not j:
            continue
        for pv in j["per_vuln"]:
            if pv["verdict"] == "missed":
                buckets["missed_known"].append((r, pv["vulnerable_function"]))
            if pv.get("explanation_quality") == "insufficient_evidence":
                buckets["insufficient_evidence"].append((r, pv["vulnerable_function"]))
            if pv.get("explanation_quality") == "incorrect":
                buckets["incorrect_function"].append((r, pv["vulnerable_function"]))
        for of in j.get("other_findings", []):
            if of.get("judge_label") == "likely_false_positive":
                buckets["incorrect_function"].append((r, of.get("vulnerable_function")))

    titles = {
        "missed_known": "Missed known vulnerable functions",
        "incorrect_function": "Incorrect / likely-false-positive findings",
        "insufficient_evidence": "Insufficient evidence",
        "malformed": "Malformed or missing responses",
        "execution_or_input_failure": "Execution or input failures",
    }
    for key, title in titles.items():
        L.append(f"### {title} ({len(buckets[key])})")
        if not buckets[key]:
            L.append("- none observed.")
        for r, detail in buckets[key][:12]:
            L.append(f"- `{r['sample_id']}` / {CONFIG_LABEL.get(r['configuration'], r['configuration'])} "
                     f"(run `{r['run_id']}`): {detail}")
        L.append("")

    L.append("## Notes")
    L.append("")
    L.append("- \"Located\" = the deterministic matcher mapped a reported finding to the "
             "ground-truth vulnerable function (exact/alias) or to its file+line span.")
    L.append("- Every non-matching finding is flagged `manual_validation_required`; the "
             "false-positive rate is only final after that manual pass.")
    L.append("- Runtimes are wall-clock per run under the shared time budget in "
             "`harness/config.yaml`.")
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results-dir", default=str(common.REPO_ROOT / "results"))
    ap.add_argument("--out-dir", default=str(Path(__file__).parent / "out"))
    args = ap.parse_args()

    results_dir = Path(args.results_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    runs, judges = load_records(results_dir)

    sample_ids = sorted({r["sample_id"] for r in runs.values()}) or \
        [s.sample_id for s in common.load_all_samples()]
    for sid in sample_ids:
        md = per_sample_md(sid, runs, judges)
        (out_dir / f"{sid}.md").write_text(md, encoding="utf-8")
        print(f"  wrote {sid}.md")
    (out_dir / "comparison.md").write_text(aggregate_md(runs, judges), encoding="utf-8")
    print("  wrote comparison.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
