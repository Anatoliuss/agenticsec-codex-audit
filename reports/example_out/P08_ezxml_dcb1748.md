# P08_ezxml_dcb1748 — ezxml @ dcb1748

- **Binary:** `ezxml`
- **Commit:** `dcb17484da2591e42c739598729fe5bdf687cca6`
- **Ground-truth vulnerabilities (2):**
  - `ezxml_internal_dtd` — CVE-2021-31229 — out-of-bounds write (ezxml.c)
  - `ezxml_parse_str` — CVE-2021-31348 — out-of-bounds read (ezxml.c)

## Result summary

| Configuration | Status | Runtime (s) | Located / Total | #Findings | #Flagged other |
|---|---|---|---|---|---|
| Zero-shot | ok | 2460.0 | 1/2 | 2 | 1 |
| CVE-hinted | ok | 1320.0 | 1/2 | 1 | 0 |

### Zero-shot — run `P08_ezxml_dcb1748__zero_shot__r0__fixture01`

- ✅ **ezxml_internal_dtd** (CVE-2021-31229): *identified*, explanation: *correct* (match: exact)
  - judge: Matcher located the vulnerable function via exact match (finding F1 -> ezxml_internal_dtd).
- ❌ **ezxml_parse_str** (CVE-2021-31348): *missed*, explanation: *n/a* (match: none)
  - judge: No reported finding named the vulnerable function 'ezxml_parse_str' or an alias, and none fell within its known line span.

  Other findings flagged for manual validation:
  - `ezxml_decode` (ezxml.c) — possible_true_positive_unknown: Does not match the ground-truth vulnerable function; requires manual validation to classify as TP or FP.

### CVE-hinted — run `P08_ezxml_dcb1748__cve_hinted__r0__fixture01`
*Hint given:* CVE-2021-31229 (withheld: vulnerable_function_name)

- ✅ **ezxml_internal_dtd** (CVE-2021-31229): *identified*, explanation: *correct* (match: exact)
  - judge: Matcher located the vulnerable function via exact match (finding F1 -> ezxml_internal_dtd).
- ❌ **ezxml_parse_str** (CVE-2021-31348): *missed*, explanation: *n/a* (match: none)
  - judge: No reported finding named the vulnerable function 'ezxml_parse_str' or an alias, and none fell within its known line span.

