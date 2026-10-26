import common


def test_zero_shot_prompt_has_no_cve_or_function():
    s = common.load_sample("P08_ezxml_dcb1748")
    p = common.render_task_prompt(s, "zero_shot")
    assert "CVE-" not in p
    assert "ezxml_internal_dtd" not in p  # no function name leak
    assert s.binary in p


def test_cve_hinted_prompt_has_cve_but_not_function():
    s = common.load_sample("P08_ezxml_dcb1748")
    p = common.render_task_prompt(s, "cve_hinted", cve_id="CVE-2021-31229")
    assert "CVE-2021-31229" in p
    # the vulnerable function name must NOT be disclosed in the hint
    assert "ezxml_internal_dtd" not in p
    assert "ezxml_parse_str" not in p


def test_extract_findings_json_from_fenced_block():
    text = "prose...\n```json\n{\"findings\": [{\"id\": \"F1\", \"vulnerable_function\": \"x\", \"file\": \"a.c\", \"bug_class\": \"oob\", \"confidence\": \"high\"}]}\n```\nmore prose"
    obj, err = common.extract_findings_json(text)
    assert err is None
    assert obj["findings"][0]["id"] == "F1"


def test_extract_findings_json_handles_garbage():
    obj, err = common.extract_findings_json("no json here")
    assert obj is None and err


def test_sample_cve_and_function_helpers():
    s = common.load_sample("P09a_libredwg_5f99814")
    assert "CVE-2020-21818" in s.cve_ids
    assert "htmlescape" in s.vulnerable_functions


def test_no_prompt_leaks_vulnerable_function_name():
    """Neither configuration's prompt may disclose a ground-truth function name."""
    for s in common.load_all_samples():
        for cfg in ("zero_shot", "cve_hinted"):
            p = common.render_task_prompt(s, cfg).lower()
            for fn in s.vulnerable_functions:
                assert fn.lower() not in p, f"{s.sample_id}/{cfg} leaks {fn}"


def test_cve_hinted_prompt_uses_primary_cve():
    s = common.load_sample("P09a_libredwg_5f99814")
    p = common.render_task_prompt(s, "cve_hinted")
    assert "CVE-2020-21818" in p  # cve_primary, not the first "/"-listed id
