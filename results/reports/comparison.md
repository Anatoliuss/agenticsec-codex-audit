# Codex zero-shot vs CVE-hinted: aggregate comparison

Benchmark: VERITAS P8-P10, 4 samples, 5 known out-of-bounds vulnerabilities.
Settings (identical for both configurations): model `gpt-6.1-sol`, reasoning effort `medium`, sandbox `workspace-write`, time budget 540s, codex-cli 0.164.0.

## Did each configuration locate the known vulnerable function?

| Sample | Configuration | Status | Runtime (s) | Findings | Located (exact) | Located (incl. related fn) | Judge: identified | Other findings flagged |
|---|---|---|---|---|---|---|---|---|
| P08_ezxml_dcb1748 | Zero-shot | error | 76.9 | 0 | 0/2 | 0/2 | 0/2 | 0 |
| P08_ezxml_dcb1748 | CVE-hinted | error | 69.8 | 0 | 0/2 | 0/2 | 0/2 | 0 |
| P09a_libredwg_5f99814 | Zero-shot | not run |  |  |  |  |  |  |
| P09a_libredwg_5f99814 | CVE-hinted | not run |  |  |  |  |  |  |
| P09b_libredwg_93c2512 | Zero-shot | not run |  |  |  |  |  |  |
| P09b_libredwg_93c2512 | CVE-hinted | not run |  |  |  |  |  |  |
| P10_faad2_1073aee | Zero-shot | error | 64.0 | 0 | 0/1 | 0/1 | 0/1 | 0 |
| P10_faad2_1073aee | CVE-hinted | error | 49.4 | 0 | 0/1 | 0/1 | 0/1 | 0 |

## Totals per configuration

| Configuration | Located (exact) | Located (incl. related fn) | Judge: identified | Mean runtime (s) | Findings | Other findings flagged |
|---|---|---|---|---|---|---|
| Zero-shot | 0/3 (0%) | 0/3 (0%) | 0/3 (0%) | 70.5 | 0 | 0 |
| CVE-hinted | 0/3 (0%) | 0/3 (0%) | 0/3 (0%) | 59.6 | 0 | 0 |

Difference (CVE-hinted minus zero-shot): +0 known vulnerable functions located (exact).

## Overlap: which known vulnerabilities each configuration located (incl. related fn)

| Sample | Both | Zero-shot only | CVE-hinted only | Neither |
|---|---|---|---|---|
| P08_ezxml_dcb1748 | – | – | – | `ezxml_internal_dtd`, `ezxml_parse_str` |
| P09a_libredwg_5f99814 | – | – | – | `htmlescape` |
| P09b_libredwg_93c2512 | – | – | – | `bit_read_RC` |
| P10_faad2_1073aee | – | – | – | `stszin` |

## Evidence quality

| Configuration | Judge: explanation quality of located vulns | Evidence type (all findings) | Confidence (all findings) |
|---|---|---|---|
| Zero-shot | – | – | – |
| CVE-hinted | – | – | – |

## Representative cases

### Missed known vulnerable functions (0)

- none

### Incorrect or imprecise functions (0)

- none

### Insufficient evidence (0)

- none

### Malformed or missing responses (0)

- none

### Execution or input failures (4)

- `P08_ezxml_dcb1748` / CVE-hinted: error: This content was flagged for possible cybersecurity risk. If this seems wrong, try rephrasing your request. If you’re doing authorized security work that requires more cyber permissive safeguards, apply for Daybreak access via https://platform.openai.com/settings/organization/status-and-access before retrying.
- `P08_ezxml_dcb1748` / Zero-shot: error: This content was flagged for possible cybersecurity risk. If this seems wrong, try rephrasing your request. If you’re doing authorized security work that requires more cyber permissive safeguards, apply for Daybreak access via https://platform.openai.com/settings/organization/status-and-access before retrying.
- `P10_faad2_1073aee` / CVE-hinted: error: This content was flagged for possible cybersecurity risk. If this seems wrong, try rephrasing your request. If you’re doing authorized security work that requires more cyber permissive safeguards, apply for Daybreak access via https://platform.openai.com/settings/organization/status-and-access before retrying.
- `P10_faad2_1073aee` / Zero-shot: error: This content was flagged for possible cybersecurity risk. If this seems wrong, try rephrasing your request. If you’re doing authorized security work that requires more cyber permissive safeguards, apply for Daybreak access via https://platform.openai.com/settings/organization/status-and-access before retrying.

## Limitations

- One run per (sample, configuration): agent runs are nondeterministic, so a difference of one vulnerability is not meaningful on its own. Re-running audit.py adds runs; reports use the newest.
- Only 5 known vulnerabilities across 4 samples, so recall percentages are coarse.
- 'Located' is name matching on the reported function. 'incl. related fn' also counts the callers / sibling functions listed in `match_aliases`.
- The LLM judge sees the ground-truth description and the findings, not the code. Its labels for other findings are triage hints: each one still needs manual validation.
- P09b's ground truth (CVE-2023-25222 / `bit_read_RC`) is medium confidence; see benchmark/samples.json.
- Codex may build and run the target only if the host has the toolchain (gcc, autotools). Run on Linux or in a container so both configurations get the same build ability.
