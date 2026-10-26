# Runbook — producing deliverables #3 and #4 with a ChatGPT subscription

This runs the two remaining deliverables:
- **#3** exploratory zero-shot vs CVE-hinted Codex audit results
- **#4** the structured JSON outputs + Markdown comparison report

You need: Docker, Python 3.10+, and the Codex CLI signed in with your ChatGPT
Plus/Pro account (no API key required).

## 0. Install + sign in to Codex

```bash
npm install -g @openai/codex        # or: brew install --cask codex
codex login                          # opens a browser -> "Sign in with ChatGPT"
codex exec --json -m gpt-5.4-codex "print hello"   # smoke test; confirm the model name
```

If `gpt-5.4-codex` isn't offered on your plan, run `codex exec --help` and
`codex models` (or check the Codex docs) and put the model you *do* have into
`harness/config.yaml` (`codex.model`). Also skim `codex exec --help` once and
confirm the flags the runner uses: `--json`, `-m`, `--full-auto`
(or `--sandbox`). Add any version-specific flag via `codex.extra_args`.

## 1. Build the vulnerable binaries (also validates buildability)

```bash
cd benchmark/samples/P08_ezxml_dcb1748 && docker build -t agenticsec/p08 .
cd ../P09a_libredwg_5f99814          && docker build -t agenticsec/p09a .
cd ../P09b_libredwg_93c2512          && docker build -t agenticsec/p09b .
cd ../P10_faad2_1073aee              && docker build -t agenticsec/p10 .
# extract artifacts if you want them locally:
#   docker run --rm -v "$PWD/out:/out" agenticsec/p10 cp -r /artifacts/. /out
```

## 2. (Recommended) reproduce the PoCs to back the ground truth

Grab each public PoC from the issue links in `benchmark/POCS.md`, then run the
`*.asan` binary from the image. Record the observed crash (function, file:line)
into the sample's `ground_truth.json` under `evidence.reproduced`. This is also
where you confirm the **P09b** candidate (CVE-2023-25222 / `bit_read_RC`) or
correct it to whatever sink actually fires for `dwg2dxf`.

## 3. Run the Codex audit — both configurations (deliverable #3)

The simplest correct setup is to run the harness *inside* the sample's Docker
image so Codex builds/runs the target in an isolated sandbox. One sample:

```bash
docker run --rm -it -v "$PWD:/bench" -w /bench \
  --entrypoint bash agenticsec/p10 -c '
    pip install -r requirements.txt &&
    codex login &&                      # or mount an existing ~/.codex auth
    python harness/run_codex.py --sample P10_faad2_1073aee
'
```

Or, if you prefer to run on the host (Codex still sandboxes with `--full-auto`):

```bash
pip install -r requirements.txt
python harness/run_codex.py            # all samples x {zero_shot, cve_hinted}
# or scope it: python harness/run_codex.py --sample P08_ezxml_dcb1748
```

Each run writes `results/<run_id>.json` (run record) and
`results/<run_id>.jsonl` (raw Codex event stream). The only difference between
the two configurations is the CVE hint in the prompt.

> Tip: do a free rehearsal first with `--dry-run` (no Codex, no cloning) to
> confirm the plumbing, then drop the flag for the real pass.

## 4. Judge + report (deliverable #4)

```bash
# LLM-as-a-judge: uses an API-key judge model if OPENAI_API_KEY is set,
# otherwise the deterministic matcher-based judge (fully offline).
python judge/judge.py                  # add --deterministic to force offline
python reports/make_report.py          # -> reports/out/comparison.md + per-sample
```

`reports/out/comparison.md` is the Markdown comparison report;
`results/*.json` + `*.judge.json` are the structured JSON outputs.

## Notes / gotchas

- **Codex event shape:** `run_codex.py:_event_text()` extracts the final agent
  message from the JSONL stream defensively, but event keys vary by Codex
  version. If `parsed_findings` comes back null with status `malformed_output`,
  open a `results/*.jsonl`, see what the final-message event looks like, and
  adjust `_event_text()` once.
- **Judge model:** the paper judged with a frontier model. With only a ChatGPT
  sub (no API key), use `--deterministic` — the located/total metric is
  identical; you lose only the free-text semantic verdict, which you can add
  later if you get API access.
- **Budget:** `time_budget_seconds` in `config.yaml` is the per-run wall clock
  (default 7200s = the paper's 2h). Lower it while iterating.
- **Repetitions:** set `run.repetitions > 1` in `config.yaml` to measure
  run-to-run variance.
