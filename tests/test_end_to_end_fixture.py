"""End-to-end over the illustrative fixtures: judge (deterministic) -> report."""
import json
import shutil
from pathlib import Path

import pytest

import common
import judge as judge_mod
import make_report

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "results" / "fixtures"


def _all_fixture_runs():
    return [p for p in FIXTURES.glob("*/*.json") if not p.name.endswith(".judge.json")]


def test_deterministic_judge_on_fixtures(tmp_path):
    for rf in _all_fixture_runs():
        rec = json.loads(rf.read_text())
        jr = judge_mod.judge_run(rec, model="gpt-5.4", force_deterministic=True)
        assert jr["run_id"] == rec["run_id"]
        assert jr["sample_id"] == rec["sample_id"]
        assert jr["judge_mode"] == "deterministic"
        # linkage back to ground truth exists
        assert jr["ground_truth_ref"].endswith("ground_truth.json")
        # every per-vuln entry carries reasoning (the justification log)
        for pv in jr["per_vuln"]:
            assert pv["reasoning"]
            assert pv["verdict"] in ("identified", "partially_identified", "missed")


def test_hinted_beats_zero_shot_on_p09a():
    """On the libredwg fixtures, CVE-hinted locates htmlescape; zero-shot misses."""
    runs = {p.name: json.loads(p.read_text()) for p in _all_fixture_runs()}
    zs = next(r for r in runs.values()
              if r["sample_id"] == "P09a_libredwg_5f99814" and r["configuration"] == "zero_shot")
    ch = next(r for r in runs.values()
              if r["sample_id"] == "P09a_libredwg_5f99814" and r["configuration"] == "cve_hinted")
    jzs = judge_mod.judge_run(zs, "gpt-5.4", force_deterministic=True)
    jch = judge_mod.judge_run(ch, "gpt-5.4", force_deterministic=True)
    assert jzs["overall"]["located_count"] == 0
    assert jch["overall"]["located_count"] == 1


def test_report_generation(tmp_path):
    # stage fixtures into a temp results dir, judge them, then build reports
    results = tmp_path / "results"
    results.mkdir()
    for rf in _all_fixture_runs():
        shutil.copy(rf, results / rf.name)
    for rf in list(results.glob("*.json")):
        rec = json.loads(rf.read_text())
        jr = judge_mod.judge_run(rec, "gpt-5.4", force_deterministic=True)
        common.dump_json(jr, rf.with_suffix(".judge.json"))

    runs, judges = make_report.load_records(results)
    assert runs and judges
    agg = make_report.aggregate_md(runs, judges)
    assert "aggregate comparison" in agg
    assert "Located known vulnerable function" in agg
    # per-sample report for P08 renders both configs
    md = make_report.per_sample_md("P08_ezxml_dcb1748", runs, judges)
    assert "Zero-shot" in md and "CVE-hinted" in md
