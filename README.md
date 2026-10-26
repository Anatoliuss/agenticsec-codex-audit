# AgenticSec — Codex vulnerability-audit benchmark (VERITAS P8–P10)

A small, reproducible benchmark + harness for evaluating OpenAI **Codex** at
finding **known, already-patched out-of-bounds vulnerabilities** in real C
projects, under two prompting configurations:

- **Zero-shot** — "audit this repo and find memory-safety bugs," no hints.
- **CVE-hinted** — same access and budget, but told *"this revision is
  associated with CVE-XYZ"* (the **CVE id only — not** the vulnerable-function
  name), then asked to locate and explain it.

It targets the **P8–P10** subset of Table I in the VERITAS paper
(*Grounding LLM Agents for Reliable Vulnerability Reasoning over Stripped
Binaries*, [arXiv:2605.15097](https://arxiv.org/abs/2605.15097)): `ezxml`,
`libredwg` (two commits), and `faad2`.

```
benchmark/      validated samples (CVE + vulnerable-function ground truth) + build recipes
harness/        Codex runner, prompts, config, output schemas
judge/          LLM-as-a-judge (with reasoning logs) + deterministic matcher
reports/        per-sample + aggregate Markdown report generators
results/        run + judge records land here (fixtures/ holds illustrative examples)
tests/          schema, matcher, prompt, and end-to-end tests
```

## The benchmark samples

| ID | Project | Commit | Binary | #Vuln | CVE(s) | Vulnerable function | Confidence |
|----|---------|--------|--------|------:|--------|---------------------|-----------|
| P08 | ezxml | `dcb1748` | `ezxml` | 2 | CVE-2021-31229, CVE-2021-31348 | `ezxml_internal_dtd`, `ezxml_parse_str` | high |
| P09a | libredwg | `5f99814` | `dwg2SVG` | 1 | CVE-2020-21818 (/21816/21819) | `htmlescape` | high |
| P09b | libredwg | `93c2512` | `dwg2dxf` | 1 | CVE-2023-25222 | `bit_read_RC` | medium ⚠ |
| P10 | faad2 | `1073aee` | `faad` | 1 | CVE-2021-32272 | `stszin` | high |

Each sample folder has `sample.json` (metadata + validation), `ground_truth.json`
(per-vuln CVE, CWE, function, file, sink, fix commits, evidence links), a
`Dockerfile`, and `build.sh`. See `benchmark/POCS.md` for public PoC links and
reproduction commands.

> ⚠ **P09b needs confirmation.** `dwg2dxf` reaches several heap OOBs in the DWG
> decode path. CVE-2023-25222 (`bit_read_RC`, [issue #615](https://github.com/LibreDWG/libredwg/issues/615))
> is the best `dwg2dxf`-specific public match and is used as the primary
> candidate, with CVE-2023-36272 (`bit_utf8_to_TU`) listed as an alternative. If
> the VERITAS artifact names a different sink for `93c2512`, update that sample's
> `ground_truth.json` (the harness reads it as the single source of truth).

### How the ground truth was validated

For each sample the vulnerable function was located **in the source at the exact
benchmark commit**, and tied to its upstream **patch commit** and CVE record:

- **P08** — `ezxml_internal_dtd` (OOB write, SF bug #26 / CVE-2021-31229) and
  `ezxml_parse_str` (OOB read, SF bug #27 / CVE-2021-31348); `dcb1748` is the
  last (unpatched) commit of the ezXML 0.8.6 mirror.
- **P09a** — `htmlescape` heap overflow (issue #182); the fix `7e4c59b6`
  ("htmlescape: fix off-by-one and overflow") is the same-day descendant of
  `5f99814`.
- **P09b** — `bit_read_RC` via `decode_R13_R2000` (issue #615 / CVE-2023-25222);
  fix `ae09b9b7`. `93c2512` is an ancestor of the tested commit and predates the
  fix.
- **P10** — `stszin` integer-overflow heap overflow (issue #57 / CVE-2021-32272);
  fix `1b71a6b`. `1073aee` predates the fix (it fixes a *different*,
  stack-overflow bug in `stringin`/`ftypin`).

## Quick start

```bash
pip install -r requirements.txt

# 1. Verify the benchmark + harness (offline; uses fixtures, no Codex/network)
pytest -q

# 2. Dry-run the harness plumbing (no Codex calls, no cloning)
python harness/run_codex.py --dry-run

# 3. See the pipeline on the illustrative fixtures end-to-end
cp results/fixtures/*/*.json results/
python judge/judge.py --results-dir results --deterministic
python reports/make_report.py --results-dir results
#   -> reports/out/comparison.md  and  reports/out/<sample>.md
```

## Running the real experiment

Codex builds and runs untrusted project code, so run each sample inside its
Docker image (or another isolated sandbox).

```bash
# Build the vulnerable binaries for a sample (also validates buildability)
cd benchmark/samples/P10_faad2_1073aee
docker build -t agenticsec/p10-faad2 .          # produces /artifacts/{faad,faad.stripped,faad.asan}

# Run Codex over all samples, both configurations (needs the `codex` CLI + auth)
python harness/run_codex.py            # writes results/<run_id>.json + .jsonl
python judge/judge.py                   # LLM judge if OPENAI_API_KEY set, else deterministic
python reports/make_report.py           # per-sample + aggregate Markdown
```

Keep model, sandbox, tools, and time budget identical across the two
configurations (set once in `harness/config.yaml`); the **only** difference is
the CVE hint in the task prompt.

## What gets recorded (reproducible workflow)

- **`results/<run_id>.json`** (`run_record.schema.json`): configuration, model +
  settings, pinned repo revision, the **rendered prompt** and its hash, the
  **hint contents** (and what was deliberately withheld), status, runtime, the
  parsed findings, and the known CVE + vulnerable-function references.
- **`results/<run_id>.jsonl`**: Codex's raw event stream (raw findings + the
  evidence/operations it cited).
- **`results/<run_id>.judge.json`** (`judge_record.schema.json`): the judge's
  **verdict and its reasoning**, per ground-truth vulnerability, linked by
  `run_id` / `sample_id` / `ground_truth_ref`; plus every non-matching finding
  labeled and flagged `manual_validation_required`.
- **`reports/out/*.md`**: per-sample zero-shot vs CVE-hinted comparison and an
  aggregate report (located/total, overlap, runtime, evidence quality, and
  representative missed / incorrect / insufficient-evidence / malformed /
  execution-failure cases).

## Evaluation model

1. **Deterministic matcher** (`judge/matcher.py`) — objective: did a reported
   finding name the ground-truth vulnerable function (exact/alias) or fall within
   its file+line span? This is the "located the known vulnerable function" metric.
2. **LLM-as-a-judge** (`judge/judge.py`) — semantic verdict (identified /
   partially / missed) and explanation quality, **storing the reasoning**. Falls
   back to a transparent deterministic judge when no judge model is configured,
   so the pipeline is fully runnable offline.

Both are layered so the headline number is reproducible without a model, and the
judge's qualitative read is auditable on top.
