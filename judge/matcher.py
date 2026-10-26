"""Deterministic matcher: did a run locate the known vulnerable function?

This is the objective, reproducible half of evaluation. The LLM judge
(judge.py) adds a semantic verdict on top; this module never calls a model.

A ground-truth vulnerability is considered LOCATED by a run if some reported
finding names the vulnerable function (or one of its match_aliases), after
normalization. If the finding gives the right file and a line inside the
function's known span but a different/empty function name, that counts as a
weaker "file_line" match.

Every finding that does not map to any ground-truth vulnerability is returned
in `unmatched_findings` and flagged for manual validation (these are candidate
false positives / newly-found issues).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any

_PREFIXES = ("dwg_", "ezxml_", "faad_", "mp4_")


def normalize_fn(name: str) -> str:
    if not name:
        return ""
    n = name.strip().lower()
    n = re.sub(r"\(.*$", "", n)          # drop argument list
    n = n.split("::")[-1]                # drop C++ scope
    n = n.lstrip("*& ")
    n = re.sub(r"[^a-z0-9_]", "", n)
    return n


def _fn_variants(name: str) -> set[str]:
    base = normalize_fn(name)
    out = {base}
    for p in _PREFIXES:
        if base.startswith(p):
            out.add(base[len(p):])
    return {v for v in out if v}


def _same_fn(a: str, b: str) -> bool:
    return bool(_fn_variants(a) & _fn_variants(b))


@dataclass
class VulnMatch:
    vuln_id: str
    cve: str
    vulnerable_function: str
    located: bool = False
    match_type: str = "none"          # exact | alias | file_line | none
    matching_finding_id: str | None = None
    matching_finding_function: str | None = None


@dataclass
class MatchResult:
    run_id: str
    sample_id: str
    configuration: str
    status: str
    located_count: int = 0
    total_vulns: int = 0
    vuln_matches: list[VulnMatch] = field(default_factory=list)
    unmatched_findings: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


def _finding_file(f: dict) -> str:
    return (f.get("file") or "").strip().lower()


def match_run(run_record: dict, ground_truth: dict) -> MatchResult:
    findings = []
    pf = run_record.get("parsed_findings")
    if isinstance(pf, dict):
        findings = pf.get("findings") or []

    vulns = ground_truth.get("vulnerabilities", [])
    res = MatchResult(
        run_id=run_record.get("run_id", ""),
        sample_id=run_record.get("sample_id", ""),
        configuration=run_record.get("configuration", ""),
        status=run_record.get("status", ""),
        total_vulns=len(vulns),
    )

    matched_finding_ids: set[str] = set()

    for v in vulns:
        vm = VulnMatch(
            vuln_id=v.get("vuln_id", ""),
            cve=v.get("cve", ""),
            vulnerable_function=v.get("vulnerable_function", ""),
        )
        aliases = [v["vulnerable_function"]] + list(v.get("match_aliases", []))
        gt_file = (v.get("file") or "").strip().lower()
        gt_line = v.get("sink_hint_line")
        decl = v.get("function_decl_line")

        best = None  # (rank, finding, match_type, fn)
        for f in findings:
            ffn = f.get("vulnerable_function", "")
            # 1) exact function name
            if _same_fn(ffn, v["vulnerable_function"]):
                best = (3, f, "exact", ffn); break
            # 2) alias function name
            if any(_same_fn(ffn, a) for a in aliases):
                if not best or best[0] < 2:
                    best = (2, f, "alias", ffn)
            # 3) file + line within function span
            if gt_file and _finding_file(f).endswith(gt_file):
                flines = f.get("lines") or []
                near = False
                for ln in flines:
                    if gt_line and abs(ln - gt_line) <= 40:
                        near = True
                    if decl and 0 <= (ln - decl) <= 200:
                        near = True
                if near and (not best or best[0] < 1):
                    best = (1, f, "file_line", ffn)

        if best:
            _, f, mtype, fn = best
            vm.located = True
            vm.match_type = mtype
            vm.matching_finding_id = f.get("id")
            vm.matching_finding_function = fn
            if f.get("id"):
                matched_finding_ids.add(f.get("id"))
        res.vuln_matches.append(vm)

    res.located_count = sum(1 for vm in res.vuln_matches if vm.located)

    for f in findings:
        if f.get("id") not in matched_finding_ids:
            res.unmatched_findings.append({
                "finding_id": f.get("id"),
                "vulnerable_function": f.get("vulnerable_function"),
                "file": f.get("file"),
                "lines": f.get("lines"),
                "bug_class": f.get("bug_class"),
                "confidence": f.get("confidence"),
                "flag": "manual_validation_required",
            })
    return res
