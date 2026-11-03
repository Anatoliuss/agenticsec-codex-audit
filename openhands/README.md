# OpenHands binary evaluation in agenticsec-codex-audit

This is an **additional workflow**. The project's original Codex identity,
`audit.py`, `config.json`, prompts, samples, judge and results remain in place.
Use the root README for Codex source auditing. Use this guide for the attached
OpenHands task: jq at `f58787c`, task-provided `CVE-2026-44777`, `CWE-674`,
annotation row 4. These task identifiers have not been independently validated.

## What is implemented

- OpenHands Software Agent SDK **1.59.0** (MIT), calling a self-hosted,
  OpenAI-compatible vLLM or SGLang endpoint. No Codex invocation in this workflow.
- A custom OpenHands `sandbox_shell` tool. Model-selected commands execute only
  through `docker exec` in a fresh Linux container. The agent also gets OpenHands'
  non-executing `think` and `finish` tools. No browser, MCP, host shell or editor.
- A stripped, non-PIE jq binary; a separate builder exports its full commit,
  hashes, flags, compiler and package versions, symbols, and upstream license.
- The sandbox mounts **only the stripped binary**, read-only at `/target/jq`.
  No source tree, unstripped copy, ground truth, old results or Docker socket.
  It has no network, no capabilities, a read-only root and bounded writable tmpfs.
  The host controller can reach the model; the analysis container cannot.
- The fixed tool image includes file, strings, readelf, objdump, nm, checksec,
  gdb, Python and angr. Ghidra/radare2/Valgrind are not part of this selected tool
  set. Dynamic analysis uses bounded commands; no PoC is bundled.
- Independent zero-shot and CVE-hinted conversations, using identical binary,
  tools, permissions, system prompt, sampling, time budget and iteration cap.
- Raw events, persisted SDK trajectory, full command outputs, final findings,
  metrics and JSON provenance, followed by Markdown and JSON comparisons.

## Prerequisites

Use Python **3.12+**, Docker with Linux containers/build output support, and
access to a GPU/model host sized for the open-weight coding model you select.
On a host without Docker (e.g. many HPC clusters) set `BINARY_EVAL_CONTAINER=podman`
to use Podman instead; every `build`/`preflight`/`run` command then uses it. The
runtime used is recorded in each run's provenance. Apptainer/Singularity are not
command-compatible and would need separate changes.
Linux or WSL with Docker integration is the intended execution environment.
The controller can also run on Windows when Docker is configured correctly.
No GPU is needed for offline tests. Native Windows/WSL evaluation has not been
verified on this machine; Docker and a model server were unavailable during editing.

From the project root (the inner `agenticsec-codex-audit` directory):

```bash
python -m venv .venv-openhands
# Linux/WSL:
source .venv-openhands/bin/activate
# PowerShell alternative: .\.venv-openhands\Scripts\Activate.ps1
python -m pip install -r openhands/requirements.txt
python -m unittest test_binary_eval test_openhands_sdk -v
python test_pipeline.py
```

An isolated Windows `.venv-openhands` was created for integration checks in this
workspace. It is ignored by Git; do not reuse it as a Linux virtual environment.

## 1. Build the target and fixed tools

```bash
python -m binary_eval.build
```

This command downloads upstream sources and dependencies **only in the build**.
It resolves the base image to a digest, builds linux/amd64 artifacts into
`artifacts/openhands-jq`, and records the analysis image's immutable ID in
`build.json`. It refuses a nonempty output directory. Do not mix artifacts from
different builds. The build resolves the task's short commit and fails if it
does not resolve to a full commit with prefix `f58787c`.

APT dependencies are resolved at image-build time and inventoried. Retain the
built images for exact reuse; rebuilding later can resolve different packages.
Before moving to another machine, save/load the image or push it to your own
registry and record its digest. The runner uses the resolved image ID for both
runs and rejects an image that differs from the build manifest.

The build outputs `jq.unstripped` and `symbols.txt` for the evaluator only.
The runner never passes them to OpenHands.

## 2. Configure and serve a pinned model

Copy `openhands/config.example.json` to `openhands/config.local.json` and fill:

| Field | Required value |
|---|---|
| `model.id` | Exact ID advertised by the server's `/v1/models` |
| `model.revision` | Full immutable model repository commit |
| `model.license` | Actual license from that model revision |
| `model.base_url` | Your self-hosted vLLM/SGLang endpoint, ending in `/v1` |
| `serving.engine` | `vllm` or `sglang` |
| `serving.image` | Exact serving image with `@sha256:...` digest |
| `serving.command` | Actual argument list used to launch the server, including the model revision |
| `serving.notes` | Hardware, dtype/quantization, tensor parallelism, context size and tool-call parser |

For example, a vLLM serving invocation **inside your pinned server image** has
this form; choose a parser supported by your model and that vLLM version:

```bash
vllm serve YOUR_MODEL_ID --revision YOUR_FULL_MODEL_COMMIT \
  --served-model-name YOUR_MODEL_ID --host 0.0.0.0 --port 8000 \
  --enable-auto-tool-choice --tool-call-parser YOUR_MODEL_TOOL_PARSER
```

Record this exact argument list and all additional flags in `serving.command`.
An SGLang server may be used instead with its OpenAI-compatible endpoint and
appropriate model revision/tool parser. Model downloads and GPU server launch
are explicit operator steps; the harness does not allocate cloud resources.
Use an environment variable for the API key (`OPENHANDS_LLM_API_KEY` by default),
never the JSON configuration. For an unauthenticated local server no key is needed.
Archive server launch logs with the experiment to substantiate the declared
revision: `/models` verifies the ID but cannot attest the weight hash/license.

## 3. Verify the ground truth

Obtain **row 4 of the referenced Ground Truth Annotations**. Verify the CVE,
commit and known vulnerable function; do not guess the function from the CWE.
Fill `openhands/ground_truth.json` with its reference, exact built binary SHA-256,
and `vulnerable_functions`, e.g. the following shape (values are illustrative):

```json
{
  "status": "verified",
  "reference": "annotation URL/document and row 4",
  "cve": "CVE-2026-44777",
  "binary_sha256": "THE_SHA256_FROM_BUILD_JSON",
  "vulnerable_functions": [
    {"name": "NAME_FROM_VERIFIED_ANNOTATION", "addresses": ["0x401000"]}
  ]
}
```

Use the matching unstripped binary/symbol map to obtain addresses. Addresses
are ELF virtual addresses, not file offsets. Exact name/address matches are
candidate localization matches; inspect the explanation before declaring a
correct vulnerability identification. Unverified or hash-mismatched ground truth
is reported as `unverified_ground_truth`, never as a miss. Exploratory runs may
be collected first; `report` reevaluates saved findings against the current
annotation without changing original run records.

## 4. Preview, check, then run

```bash
# No SDK import, model calls, Docker activity or writes:
python -m binary_eval dry-run

# Validates settings, hashes and SDK; inspects Docker, queries /models,
# and reads the image's tool inventory. Does not start an agent:
python -m binary_eval preflight --config openhands/config.local.json

# Explicitly starts both independent evaluations:
python -m binary_eval run --config openhands/config.local.json

# Offline regeneration (also updates report-side ground-truth assessments):
python -m binary_eval report --config openhands/config.local.json
```

`--configuration zero_shot` or `--configuration cve_hinted` selects one run.
Use the default paired invocation for comparisons: independent invocations get
different batch IDs and are not silently paired. Runs return a nonzero status
when any execution fails or its final output is invalid. Missing model settings
fail before Docker/model activity. The wall-clock deadline covers the worker;
container setup and cleanup are included in total runtime but recorded separately
from agent runtime where available. Each shell command has its own timeout too.

## Outputs and review

```text
results/openhands/runs/<batch>__<configuration>/
  run.json          status, findings, prompts, settings, hashes, versions, assessment
  config.json       exact configuration (no API key)
  prompts.json      exact evaluation instructions and hint contents
  events.jsonl      complete SDK event stream, including effective system prompt
  trajectory/       SDK-persisted conversation and events
  tools.jsonl       commands, exit codes, runtimes and output references
  tool-0001.txt     full tool output (context copy may be truncated)
  final.txt         raw final response
  metrics.json      SDK token/cost/latency metrics, including partial-run snapshots
  worker.log        SDK diagnostics and execution errors
results/openhands/reports/
  comparison.json   machine-readable pairing and assessments
  comparison.md     aggregate comparison and qualitative per-run sections
  jq_f58787c.md      per-sample report
  <run>.md          per-run findings and limitations
```

Reports keep incompatible/missing pairs, timeouts, malformed responses, absent
metrics, evidence gaps, missed known functions and other-function candidates
visible. Every additional finding is marked for manual validation. Overlap is
by reported address/name, not semantic proof that two findings are the same bug.
Evidence quality is described by evidence type, localization and reference
availability; it is not an automated scientific validity score. Do not claim
precision/recall from one target or infer that an unconfirmed finding is false.

The repo files, configuration, prompts, JSON and Markdown outputs are uploadable
artifacts. Review logs before publishing, include model/server provenance and
annotation references, and preserve relevant target/tool/model licenses. Large
binary/image artifacts are ignored by Git and should be archived separately.
Keep the existing Codex results distinct: they use source access and different
models, so they are not a controlled comparison against these binary runs.

## Integration references

The adapter uses the pinned OpenHands SDK's custom-tool, conversation and metrics
APIs. References checked during implementation:

- [OpenHands SDK v1.59.0 source](https://github.com/OpenHands/software-agent-sdk/tree/v1.59.0)
- [OpenHands custom tools](https://docs.openhands.dev/sdk/guides/custom-tools)
- [OpenHands metrics](https://docs.openhands.dev/sdk/guides/metrics)
- [vLLM serving flags](https://docs.vllm.ai/en/latest/cli/serve/)
- [SGLang request/serving guide](https://docs.sglang.io/docs/basic_usage/send_request)
