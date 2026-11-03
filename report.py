#!/usr/bin/env python3
"""Step 3 - turn the run + judge records into Markdown reports.

  results/reports/<sample_id>.md   zero-shot vs CVE-hinted for one sample
  results/reports/comparison.md    aggregate comparison + qualitative analysis

Uses the newest run (and its judgment) for each (sample, configuration).

Usage:  python report.py
"""
from __future__ import annotations

from collections import Counter

from common import JUDGMENTS, REPORTS, RUNS, load_json, load_samples

CONFIGS = {"zero_shot": "Zero-shot", "cve_hinted": "CVE-hinted"}
ICON = {"identified": "✅", "partially_identified": "🟡", "missed": "❌"}
LIMITATIONS = [
    "One run per (sample, configuration): agent runs are nondeterministic, so a difference of "
    "one vulnerability is not meaningful on its own. Re-running audit.py adds runs; reports use the newest.",
    "Only 5 known vulnerabilities across 4 samples, so recall percentages are coarse.",
    "'Located' is name matching on the reported function. 'incl. related fn' also counts the "
    "callers / sibling functions listed in `match_aliases`.",
    "The LLM judge sees the ground-truth description and the findings, not the code. Its labels "
    "for other findings are triage hints: each one still needs manual validation.",
    "P09b's ground truth (CVE-2023-25222 / `bit_read_RC`) is medium confidence; see benchmark/samples.json.",
    "Codex may build and run the target only if the host has the toolchain (gcc, autotools). Run on "
    "Linux or in a container so both configurations get the same build ability.",
]


def latest_runs() -> dict:
    """{(sample_id, configuration): (run, judgment or None)} for the newest run of each pair."""
    pairs = {}
    for path in sorted(RUNS.glob("*.json")):  # run ids end in a timestamp: sorted = oldest first
        run = load_json(path)
        judgment = JUDGMENTS / f"{run['run_id']}.judge.json"
        pairs[(run["sample_id"], run["configuration"])] = (run, load_json(judgment) if judgment.exists() else None)
    return pairs


def table(header: list, rows: list[list]) -> list[str]:
    def cell(c):
        return str(c).replace("|", "\\|").replace("\n", " ")
    return (["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
            + ["| " + " | ".join(cell(c) for c in row) + " |" for row in rows])


def fn_name(finding: dict) -> str:
    return finding["vulnerable_function"].split("(")[0].strip()


def counts(counter: Counter) -> str:
    return ", ".join(f"{k}: {n}" for k, n in counter.most_common()) or "–"


def fraction(overall: dict | None, key: str) -> str:
    return f"{overall[key]}/{overall['total_vulns']}" if overall else "–"


# --------------------------------------------------------------------------- per sample
def vuln_cell(judgment: dict | None, vuln_id: str) -> str:
    if judgment is None:
        return "not judged"
    p = next(p for p in judgment["per_vuln"] if p["vuln_id"] == vuln_id)
    return (f"{ICON[p['verdict']]} {p['verdict']} (matcher: {p['matcher']['match_type']}, "
            f"explanation: {p['explanation_quality']})")


def summary_column(run: dict | None, judgment: dict | None, sample: dict) -> list:
    if run is None:
        return ["not run"] * (6 + len(sample["vulnerabilities"]))
    return [f"`{run['run_id']}`",
            run["status"] + (f": {run['error']}" if run.get("error") else ""),
            run["runtime_seconds"],
            run["hint"]["text"] if run["hint"] else "none",
            len(run["findings"]),
            *[vuln_cell(judgment, v["vuln_id"]) for v in sample["vulnerabilities"]],
            len(judgment["other_findings"]) if judgment else "not judged"]


def sample_report(sample: dict, pairs: dict) -> str:
    sid = sample["sample_id"]
    runs = {c: pairs.get((sid, c), (None, None)) for c in CONFIGS}
    L = [f"# {sid}: {sample['project']} @ {sample['commit'][:7]} (binary `{sample['binary']}`)", "",
         "Known vulnerabilities (ground truth):", ""]
    L += [f"- **{v['vuln_id']}** `{v['vulnerable_function']}` in `{v['file']}`: {v['cve']}, {v['bug_class']}"
          for v in sample["vulnerabilities"]]

    labels = ["Run", "Status", "Runtime (s)", "Hint given", "Findings reported",
              *[f"Known: `{v['vulnerable_function']}`" for v in sample["vulnerabilities"]],
              "Other findings (flagged for manual validation)"]
    columns = [summary_column(*runs[c], sample) for c in CONFIGS]
    L += ["", "## Summary", ""] + table(["", *CONFIGS.values()], [list(r) for r in zip(labels, *columns)])

    L += ["", "## Judge verdicts and reasoning", ""]
    for c, name in CONFIGS.items():
        run, j = runs[c]
        if not j:
            continue
        L += [f"### {name} (judge: {j['judge_model'] or 'matcher only'})", ""]
        L += [f"- {ICON[p['verdict']]} **{p['vulnerable_function']}** ({p['cve']}): {p['reasoning']}"
              for p in j["per_vuln"]]
        if j["judge_error"]:
            L.append(f"- judge error: {j['judge_error']}")
        if j["overall"]["summary_reasoning"]:
            L.append(f"- summary: {j['overall']['summary_reasoning']}")
        L.append("")

    rows = []
    for c, name in CONFIGS.items():
        run, j = runs[c]
        if not run:
            continue
        verdicts = {}
        if j:
            verdicts.update({p["matching_finding_id"]: f"matches {p['vuln_id']}" for p in j["per_vuln"]})
            verdicts.update({o["finding_id"]: f"{o['label']} (flagged)" for o in j["other_findings"]})
        for f in run["findings"]:
            rows.append([name, f["id"], f"`{fn_name(f)}`",
                         f"{f['file']}:{','.join(map(str, f.get('lines', [])))}",
                         f["bug_class"], f["evidence_type"], f["confidence"], verdicts.get(f["id"], "")])
    L += ["## All reported findings", ""]
    L += table(["Config", "ID", "Function", "Location", "Bug class", "Evidence", "Confidence", "Judge"], rows) \
        if rows else ["No findings reported."]

    zs, ch = ({fn_name(f) for f in runs[c][0]["findings"]} if runs[c][0] else set() for c in CONFIGS)
    fmt = lambda names: ", ".join(f"`{n}`" for n in sorted(names)) or "–"  # noqa: E731
    L += ["", "## Overlap of reported functions", "",
          f"- Both configurations: {fmt(zs & ch)}",
          f"- Zero-shot only: {fmt(zs - ch)}",
          f"- CVE-hinted only: {fmt(ch - zs)}"]
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------- aggregate
def comparison_report(samples: dict, pairs: dict) -> str:
    n_vulns = sum(len(s["vulnerabilities"]) for s in samples.values())
    L = ["# Codex zero-shot vs CVE-hinted: aggregate comparison", "",
         f"Benchmark: VERITAS P8-P10, {len(samples)} samples, {n_vulns} known out-of-bounds vulnerabilities."]
    if pairs:
        r = next(iter(pairs.values()))[0]
        L.append(f"Settings (identical for both configurations): model `{r['model']}`, reasoning effort "
                 f"`{r['reasoning_effort']}`, sandbox `{r['sandbox']}`, time budget {r['time_budget_seconds']}s, "
                 f"{r['codex_version'] or 'codex version unknown'}.")

    rows, totals = [], {c: Counter() for c in CONFIGS}
    for sid in samples:
        for c, name in CONFIGS.items():
            run, j = pairs.get((sid, c), (None, None))
            if not run:
                rows.append([sid, name, "not run", "", "", "", "", "", ""])
                continue
            o, t = (j or {}).get("overall"), totals[c]
            t.update(runs=1, runtime=run["runtime_seconds"], findings=len(run["findings"]))
            if o:
                t.update(vulns=o["total_vulns"], exact=o["located_exact"], incl=o["located_incl_aliases"],
                         judge=o["identified_by_judge"], flagged=len(j["other_findings"]))
            rows.append([sid, name, run["status"], run["runtime_seconds"], len(run["findings"]),
                         fraction(o, "located_exact"), fraction(o, "located_incl_aliases"),
                         fraction(o, "identified_by_judge"), len(j["other_findings"]) if j else "–"])
    L += ["", "## Did each configuration locate the known vulnerable function?", ""]
    L += table(["Sample", "Configuration", "Status", "Runtime (s)", "Findings", "Located (exact)",
                "Located (incl. related fn)", "Judge: identified", "Other findings flagged"], rows)

    def pct(t, k):
        return f"{t[k]}/{t['vulns']} ({100 * t[k] / t['vulns']:.0f}%)" if t["vulns"] else "–"
    rows = []
    for c, name in CONFIGS.items():
        t = totals[c]
        mean_runtime = round(t["runtime"] / t["runs"], 1) if t["runs"] else "–"
        rows.append([name, pct(t, "exact"), pct(t, "incl"), pct(t, "judge"), mean_runtime,
                     t["findings"], t["flagged"]])
    L += ["", "## Totals per configuration", ""]
    L += table(["Configuration", "Located (exact)", "Located (incl. related fn)", "Judge: identified",
                "Mean runtime (s)", "Findings", "Other findings flagged"], rows)
    diff = totals["cve_hinted"]["exact"] - totals["zero_shot"]["exact"]
    L += ["", f"Difference (CVE-hinted minus zero-shot): {diff:+d} known vulnerable functions located (exact)."]

    L += ["", "## Overlap: which known vulnerabilities each configuration located (incl. related fn)", ""]
    rows = []
    for sid, s in samples.items():
        found = {}
        for c in CONFIGS:
            j = pairs.get((sid, c), (None, None))[1]
            found[c] = {p["vulnerable_function"] for p in (j or {}).get("per_vuln", [])
                        if p["matcher"]["match_type"] != "none"}
        zs, ch = found["zero_shot"], found["cve_hinted"]
        everything = {v["vulnerable_function"] for v in s["vulnerabilities"]}
        rows.append([sid] + [", ".join(f"`{n}`" for n in sorted(group)) or "–"
                             for group in (zs & ch, zs - ch, ch - zs, everything - zs - ch)])
    L += table(["Sample", "Both", "Zero-shot only", "CVE-hinted only", "Neither"], rows)

    L += ["", "## Evidence quality", ""]
    rows = []
    for c, name in CONFIGS.items():
        quality, evidence, confidence = Counter(), Counter(), Counter()
        for (sid, cc), (run, j) in pairs.items():
            if cc != c:
                continue
            evidence.update(f["evidence_type"] for f in run["findings"])
            confidence.update(f["confidence"] for f in run["findings"])
            quality.update(p["explanation_quality"] for p in (j or {}).get("per_vuln", []) if p["verdict"] != "missed")
        rows.append([name, counts(quality), counts(evidence), counts(confidence)])
    L += table(["Configuration", "Judge: explanation quality of located vulns", "Evidence type (all findings)",
                "Confidence (all findings)"], rows)

    buckets = {k: [] for k in ("Missed known vulnerable functions", "Incorrect or imprecise functions",
                               "Insufficient evidence", "Malformed or missing responses",
                               "Execution or input failures")}
    for (sid, c), (run, j) in sorted(pairs.items()):
        where = f"`{sid}` / {CONFIGS[c]}"
        if run["status"] in ("malformed_output", "no_output"):
            buckets["Malformed or missing responses"].append(f"{where}: {run['error']}")
        if run["status"] in ("timeout", "error", "input_failure"):
            buckets["Execution or input failures"].append(f"{where}: {run['status']}: {run['error']}")
        for p in (j or {}).get("per_vuln", []):
            text = f"{where}: `{p['vulnerable_function']}` ({p['cve']}): {p['reasoning']}"
            if p["verdict"] == "missed" and run["status"] == "ok":
                buckets["Missed known vulnerable functions"].append(text)
            if p["verdict"] == "partially_identified" or p["explanation_quality"] == "incorrect":
                buckets["Incorrect or imprecise functions"].append(text)
            if p["explanation_quality"] == "insufficient_evidence":
                buckets["Insufficient evidence"].append(text)
        for o in (j or {}).get("other_findings", []):
            if o["label"] == "likely_false_positive":
                buckets["Incorrect or imprecise functions"].append(
                    f"{where}: reported `{o['vulnerable_function']}` ({o['file']}), judged likely false positive: {o['reasoning']}")
    L += ["", "## Representative cases", ""]
    for title, items in buckets.items():
        L += [f"### {title} ({len(items)})", ""] + [f"- {i}" for i in items[:6]] + (["- none"] if not items else []) + [""]

    L += ["## Limitations", ""] + [f"- {x}" for x in LIMITATIONS]
    return "\n".join(L) + "\n"


def main() -> None:
    samples, pairs = load_samples(), latest_runs()
    if not pairs:
        print(f"no run records in {RUNS}; run audit.py and judge.py first")
        return
    REPORTS.mkdir(parents=True, exist_ok=True)
    for sid, sample in samples.items():
        (REPORTS / f"{sid}.md").write_text(sample_report(sample, pairs), encoding="utf-8")
    (REPORTS / "comparison.md").write_text(comparison_report(samples, pairs), encoding="utf-8")
    print(f"wrote {len(samples) + 1} reports to {REPORTS}")


if __name__ == "__main__":
    main()
