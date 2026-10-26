"""Validate benchmark data and fixtures against the JSON schemas."""
import json
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmark"


def _load(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def _validate(instance, schema_path):
    schema = _load(schema_path)
    jsonschema.validate(instance=instance, schema=schema)


def test_every_sample_matches_sample_schema():
    schema = BENCH / "schema" / "sample.schema.json"
    samples = sorted((BENCH / "samples").glob("*/sample.json"))
    assert samples, "no samples found"
    for s in samples:
        _validate(_load(s), schema)


def test_every_ground_truth_matches_schema():
    schema = BENCH / "schema" / "ground_truth.schema.json"
    gts = sorted((BENCH / "samples").glob("*/ground_truth.json"))
    assert gts
    for g in gts:
        _validate(_load(g), schema)


def test_benchmark_index_consistent_with_samples():
    index = _load(BENCH / "benchmark.json")
    listed = {s["sample_id"] for s in index["samples"]}
    on_disk = {p.parent.name for p in (BENCH / "samples").glob("*/sample.json")}
    assert listed == on_disk


def test_num_vuln_matches_ground_truth_length():
    for s in sorted((BENCH / "samples").glob("*/sample.json")):
        meta = _load(s)
        gt = _load(s.parent / meta["ground_truth_ref"])
        assert meta["num_vuln"] == len(gt["vulnerabilities"]), s.parent.name


def test_fixture_run_records_match_schema():
    schema = ROOT / "harness" / "schemas" / "run_record.schema.json"
    recs = sorted((ROOT / "results" / "fixtures").glob("*/*.json"))
    assert recs
    for r in recs:
        if r.name.endswith(".judge.json"):
            continue
        _validate(_load(r), schema)


def test_fixture_judge_records_match_schema():
    schema = ROOT / "judge" / "judge_record.schema.json"
    recs = sorted((ROOT / "results" / "fixtures").glob("*/*.judge.json"))
    assert recs, "no fixture judge records; run judge.py on the fixtures first"
    for r in recs:
        _validate(_load(r), schema)
