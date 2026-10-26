import common
import matcher


def test_normalize_fn():
    assert matcher.normalize_fn("ezxml_internal_dtd(root, s, len)") == "ezxml_internal_dtd"
    assert matcher.normalize_fn("  *htmlescape ") == "htmlescape"
    assert matcher.normalize_fn("Dwg::bit_read_RC") == "bit_read_rc"


def test_same_fn_prefix_variant():
    assert matcher._same_fn("ezxml_internal_dtd", "internal_dtd")
    assert not matcher._same_fn("htmlescape", "htmlwescape")


def _run(sample_id, findings, status="ok"):
    return {
        "run_id": f"{sample_id}__t", "sample_id": sample_id,
        "configuration": "zero_shot", "status": status,
        "parsed_findings": {"findings": findings},
    }


def test_exact_match_locates():
    s = common.load_sample("P08_ezxml_dcb1748")
    run = _run("P08_ezxml_dcb1748", [
        {"id": "F1", "vulnerable_function": "ezxml_internal_dtd", "file": "ezxml.c", "lines": [333]},
    ])
    mr = matcher.match_run(run, s.ground_truth)
    located = {vm.vuln_id: vm for vm in mr.vuln_matches}
    assert located["P08-V1"].located and located["P08-V1"].match_type == "exact"
    assert not located["P08-V2"].located
    assert mr.located_count == 1


def test_alias_match_for_libredwg():
    s = common.load_sample("P09a_libredwg_5f99814")
    run = _run("P09a_libredwg_5f99814", [
        {"id": "F1", "vulnerable_function": "output_TEXT", "file": "programs/dwg2SVG.c", "lines": [135]},
    ])
    mr = matcher.match_run(run, s.ground_truth)
    assert mr.located_count == 1
    assert mr.vuln_matches[0].match_type == "alias"


def test_unmatched_findings_flagged():
    s = common.load_sample("P08_ezxml_dcb1748")
    run = _run("P08_ezxml_dcb1748", [
        {"id": "F1", "vulnerable_function": "ezxml_internal_dtd", "file": "ezxml.c", "lines": [333]},
        {"id": "F9", "vulnerable_function": "totally_unrelated", "file": "ezxml.c", "lines": [10]},
    ])
    mr = matcher.match_run(run, s.ground_truth)
    ids = [u["finding_id"] for u in mr.unmatched_findings]
    assert ids == ["F9"]
    assert all(u["flag"] == "manual_validation_required" for u in mr.unmatched_findings)


def test_file_line_fallback_match():
    s = common.load_sample("P10_faad2_1073aee")
    # wrong function name, but right file and a line inside stszin's span
    run = _run("P10_faad2_1073aee", [
        {"id": "F1", "vulnerable_function": "", "file": "frontend/mp4read.c", "lines": [355]},
    ])
    mr = matcher.match_run(run, s.ground_truth)
    assert mr.located_count == 1
    assert mr.vuln_matches[0].match_type == "file_line"
