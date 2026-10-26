# Codex zero-shot vs CVE-hinted — aggregate comparison

Benchmark subset: VERITAS P8–P10 (ezxml, libredwg ×2, faad2), out-of-bounds vulnerabilities.

## Located known vulnerable function (per sample)

| Sample | Binary | GT vulns | Zero-shot located | CVE-hinted located | Zero-shot runtime | CVE-hinted runtime |
|---|---|---|---|---|---|---|
| P08_ezxml_dcb1748 | `ezxml` | 2 | 1/2 | 1/2 | 2460.0s | 1320.0s |
| P09a_libredwg_5f99814 | `dwg2SVG` | 1 | 0/1 | 1/1 | 7200.0s | 2100.0s |
| P09b_libredwg_93c2512 | `dwg2dxf` | 1 | – | – | – | – |
| P10_faad2_1073aee | `faad` | 1 | – | – | – | – |

**Overall recall of the known vulnerable function:** zero-shot 1/3 (33%), CVE-hinted 2/3 (67%).

## Overlap between configurations

| Sample | Located by zero-shot only | Located by CVE-hinted only | Located by both | Located by neither |
|---|---|---|---|---|
| P08_ezxml_dcb1748 | 0 | 0 | 1 | 1 |
| P09a_libredwg_5f99814 | 0 | 1 | 0 | 0 |
| P09b_libredwg_93c2512 | 0 | 0 | 0 | 1 |
| P10_faad2_1073aee | 0 | 0 | 0 | 1 |

## Qualitative analysis

### Missed known vulnerable functions (3)
- `P08_ezxml_dcb1748` / CVE-hinted (run `P08_ezxml_dcb1748__cve_hinted__r0__fixture01`): ezxml_parse_str
- `P08_ezxml_dcb1748` / Zero-shot (run `P08_ezxml_dcb1748__zero_shot__r0__fixture01`): ezxml_parse_str
- `P09a_libredwg_5f99814` / Zero-shot (run `P09a_libredwg_5f99814__zero_shot__r0__fixture01`): htmlescape

### Incorrect / likely-false-positive findings (0)
- none observed.

### Insufficient evidence (0)
- none observed.

### Malformed or missing responses (0)
- none observed.

### Execution or input failures (1)
- `P09a_libredwg_5f99814` / Zero-shot (run `P09a_libredwg_5f99814__zero_shot__r0__fixture01`): status=timeout

## Notes

- "Located" = the deterministic matcher mapped a reported finding to the ground-truth vulnerable function (exact/alias) or to its file+line span.
- Every non-matching finding is flagged `manual_validation_required`; the false-positive rate is only final after that manual pass.
- Runtimes are wall-clock per run under the shared time budget in `harness/config.yaml`.
