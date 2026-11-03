"""Offline checks for the whole pipeline: no Codex, no network.

Run with `python -m pytest` or just `python test_pipeline.py`.
"""
import re

import audit
import common
import judge
import report

SAMPLES = common.load_samples()
CFG = common.load_config()


def finding(fid, function, file="x.c", lines=(1,), evidence_type="code-reasoning"):
    return {"id": fid, "vulnerable_function": function, "file": file, "lines": list(lines),
            "bug_class": "out-of-bounds write", "cwe": "CWE-787", "source": "", "sink": "",
            "data_flow": "", "safety_condition": "", "evidence": "", "evidence_type": evidence_type,
            "confidence": "high", "maps_to_hinted_cve": None}


def fake_run(sample, configuration, findings, status="ok"):
    """A run record shaped like the ones audit.py writes."""
    system, task, hint = audit.build_prompts(sample, configuration)
    return {"run_id": f"{sample['sample_id']}__{configuration}__20260101-000000",
            "sample_id": sample["sample_id"], "configuration": configuration,
            "model": CFG["model"], "reasoning_effort": CFG["reasoning_effort"], "sandbox": CFG["sandbox"],
            "time_budget_seconds": CFG["time_budget_seconds"], "codex_version": "codex-cli test",
            "hint": hint, "prompt_system": system, "prompt_task": task,
            "runtime_seconds": 42.0, "status": status, "error": None if status == "ok" else "boom",
            "findings": findings}


def test_samples_are_complete():
    for sid, s in SAMPLES.items():
        assert re.fullmatch(r"[0-9a-f]{40}", s["commit"]), sid
        assert s["veritas_stats"]["vuln"] == len(s["vulnerabilities"]), sid
        for v in s["vulnerabilities"]:
            assert re.fullmatch(r"CVE-\d{4}-\d{4,}", v["cve"]), v["vuln_id"]
            assert v["vulnerable_function"] and v["file"] and v["evidence"], v["vuln_id"]


def test_build_script_covers_every_sample():
    build = (common.ROOT / "benchmark" / "build.sh").read_text(encoding="utf-8")
    for sid, s in SAMPLES.items():
        assert sid in build and s["commit"] in build, sid


def test_prompts_do_not_leak_the_answer():
    for s in SAMPLES.values():
        secrets = set()
        for v in s["vulnerabilities"]:
            secrets |= {v["vulnerable_function"], v["file"].split("/")[-1], *v.get("match_aliases", [])}
        for configuration in audit.CONFIGS:
            system, task, _ = audit.build_prompts(s, configuration)
            for secret in secrets:
                assert secret.lower() not in (system + task).lower(), (s["sample_id"], configuration, secret)
        assert "CVE-" not in audit.build_prompts(s, "zero_shot")[1]
        hinted = audit.build_prompts(s, "cve_hinted")[1]
        assert all(v["cve"] in hinted for v in s["vulnerabilities"])


def test_output_schemas_are_strict():
    """codex --output-schema uses strict structured output: every object must list all
    of its properties as required and forbid extra properties."""
    def walk(node):
        if isinstance(node, dict):
            if node.get("type") == "object":
                assert node["additionalProperties"] is False
                assert set(node["required"]) == set(node["properties"])
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)
    for name in ("findings.schema.json", "judge.schema.json"):
        walk(common.load_json(common.PROMPTS / name))


def test_matcher():
    v = SAMPLES["P09a_libredwg_5f99814"]["vulnerabilities"][0]
    assert judge.match(v, [finding("F1", "htmlescape()")]) == ("exact", "F1")
    assert judge.match(v, [finding("F1", "programs/escape.c:htmlescape")]) == ("exact", "F1")
    assert judge.match(v, [finding("F1", "output_TEXT"), finding("F2", "htmlescape")]) == ("exact", "F2")
    assert judge.match(v, [finding("F1", "output_TEXT")]) == ("alias", "F1")
    assert judge.match(v, [finding("F1", "htmlescape_utf8")]) == ("none", None)


def test_definition_line():
    src = "int stszin(int size);\n\nstatic int stszin(int size)\n{\n  x = stszin(1);\n}\n"
    assert audit.definition_line(src, "stszin") == 3


def test_end_to_end_offline():
    s = SAMPLES["P10_faad2_1073aee"]
    zs = fake_run(s, "zero_shot", [finding("F1", "mp4read_open", "frontend/mp4read.c", (1005,)),
                                   finding("F2", "stringin", "frontend/mp4read.c", (120,))])
    ch = fake_run(s, "cve_hinted", [finding("F1", "stszin", "frontend/mp4read.c", (348, 355), "asan-report")])
    pairs = {}
    for run in (zs, ch):
        j = judge.judge_run(run, s, CFG, offline=True)
        assert j["links"]["run_record"] == f"results/runs/{run['run_id']}.json"
        assert j["links"]["ground_truth"] == ["benchmark/samples.json#P10_faad2_1073aee/P10-V1"]
        assert all(p["reasoning"] for p in j["per_vuln"])
        assert all(o["flag"] == "manual_validation_required" for o in j["other_findings"])
        pairs[(s["sample_id"], run["configuration"])] = (run, j)

    jzs, jch = pairs[(s["sample_id"], "zero_shot")][1], pairs[(s["sample_id"], "cve_hinted")][1]
    assert jzs["per_vuln"][0]["verdict"] == "missed" and len(jzs["other_findings"]) == 2
    assert jch["per_vuln"][0]["verdict"] == "identified" and jch["other_findings"] == []

    per_sample = report.sample_report(s, pairs)
    assert "stszin" in per_sample and "Zero-shot" in per_sample and "CVE-hinted" in per_sample
    comparison = report.comparison_report(SAMPLES, pairs)
    assert "Located (exact)" in comparison and "+1 known vulnerable functions" in comparison
    assert "Missed known vulnerable functions (1)" in comparison


def test_failed_run_is_reported_as_failure():
    s = SAMPLES["P08_ezxml_dcb1748"]
    run = fake_run(s, "zero_shot", [], status="timeout")
    j = judge.judge_run(run, s, CFG)  # no findings -> no LLM call even without --offline
    assert j["judge_mode"] == "matcher" and j["judge_prompt"] is None
    comparison = report.comparison_report(SAMPLES, {(s["sample_id"], "zero_shot"): (run, j)})
    assert "Execution or input failures (1)" in comparison
    assert "Missed known vulnerable functions (0)" in comparison


if __name__ == "__main__":
    tests = [(name, fn) for name, fn in globals().items() if name.startswith("test_")]
    for name, fn in tests:
        fn()
        print(f"ok  {name}")
    print(f"{len(tests)} tests passed")
