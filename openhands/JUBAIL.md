# Running the jq/OpenHands evaluation on an HPC with Singularity (NYU Jubail)

This cluster has **Singularity only** (no Docker/Podman) and **no fakeroot**, so:
- the analysis **tools image is built once by GitHub Actions** and you `singularity pull` it;
- the **jq binary is compiled natively** on a node (no container);
- the sandbox runs with `singularity exec --net --network none`.

The Docker/Podman path is unchanged; this file is only for the Singularity case.

> **Network isolation caveat.** True `--net --network none` needs setuid Singularity
> (your check did not error, so it should work). If your node still has outbound
> internet from inside the sandbox, isolation is softer and rests on the prompt +
> node policy. Each run records `provenance.network_isolation` so this is explicit.

## 0. One-time: build the tools image via GitHub Actions

1. Push this repo to GitHub (you already did).
2. Run the **build-tools-image** workflow: GitHub → Actions → *build-tools-image* → *Run workflow* (or it runs on push to `main`/`master`).
3. Make the resulting package **public**: GitHub → your profile → Packages → `agenticsec-codex-audit-tools` → Package settings → Change visibility → Public.

The image is then at `ghcr.io/anatoliuss/agenticsec-codex-audit-tools:latest`. (If your repo path differs, use that; set `BINARY_EVAL_TOOLS_IMAGE` to override.)

## 1. Get a GPU node (one 80 GB H100 fits Qwen3.6-35B-A3B-FP8)

The evaluation model is **`Qwen/Qwen3.6-35B-A3B`** (MoE, 35B total / ~3B active,
Apache-2.0) — the same model as the Mini-SWE-Agent run. Its bf16 weights are ~71 GB
(borderline on one 80 GB card at 32k context), so serve the **FP8** variant
`Qwen/Qwen3.6-35B-A3B-FP8` (~35 GB, native on Hopper). Request an H100:

```bash
srun --partition=nvidia --gres=gpu:h100:1 --cpus-per-task=8 --mem=96G --time=04:00:00 --pty bash
```

> **Match your friend's run.** Deliverable 4 compares the two agents under an
> *identical* model id, revision and serving config. Confirm with whoever runs
> Mini-SWE-Agent that you both use the same repo (FP8 vs bf16), the same resolved
> revision, and the same thinking-mode setting before the scored run.

## 2. Environment + runtime + build tools

```bash
cd ~/agenticsec-codex-audit && git pull
conda activate openhands
export BINARY_EVAL_CONTAINER=singularity
export HF_HOME=/scratch/$USER/hf-cache
# Keep the multi-GB image caches off your (small) home quota, or pulls fail with "unexpected EOF":
export SINGULARITY_CACHEDIR=/scratch/$USER/.singularity-cache
export SINGULARITY_TMPDIR=/scratch/$USER/.singularity-tmp
mkdir -p "$SINGULARITY_CACHEDIR" "$SINGULARITY_TMPDIR"
module load gcc autoconf automake libtool bison flex git || true   # names vary; load what jq needs
```

## 3. Build the target (native jq + pull tools image)

```bash
module load gcc autoconf automake libtool bison flex git || true  # re-load if you ran `module purge` to serve
rm -rf artifacts/openhands-jq        # build refuses a non-empty output dir; skip on a first run
python -m binary_eval.build
```

This compiles jq at `f58787c` natively and pulls the tools image into
`artifacts/openhands-jq/tools.sif`. Re-run it after the CI image rebuild so the
new `.sif` (now with Ghidra/radare2/valgrind) matches `build.json`'s `tools_image_id`.
The native jq build needs the gcc modules; if you already ran Step 4's `module
purge` to serve vLLM, re-load them first (the running server is unaffected). If the native build fails, it's a missing
build tool — `module avail` to find the right module names and re-`module load`.

## 4. Serve Qwen with vLLM (Singularity, in the background)

`module purge` first: the build loaded a gcc module, and Singularity leaks host
env (`GCC_EXEC_PREFIX`/`CPATH`) into the container, which breaks vLLM's in-container
compiler (`fatal error: stddef.h: No such file`). Clearing modules fixes it; the
jq build is already done, so you no longer need them.

Qwen3.6 needs **two** parsers, unlike Qwen2.5-Coder. It writes tool calls as XML
(`<function=name><parameter=key>value</parameter></function>`), so the tool-call
parser must be **`qwen3_coder`** — `hermes` (which expects JSON) cannot read that
format and silently leaves the call as plain text with no `tool_calls` array. It
also emits `<think>` reasoning by default, so add **`--reasoning-parser qwen3`** to
split that out. FP8 is auto-detected from the checkpoint (no `--quantization` flag).
(If your vLLM build rejects `qwen3_coder`, the equivalent name is `qwen3_xml`.)

```bash
module purge
REVISION=$(python -c "from huggingface_hub import HfApi;print(HfApi().model_info('Qwen/Qwen3.6-35B-A3B-FP8').sha)")
echo "revision=$REVISION"
singularity run --nv docker://vllm/vllm-openai:latest \
  --model Qwen/Qwen3.6-35B-A3B-FP8 --revision $REVISION \
  --served-model-name Qwen/Qwen3.6-35B-A3B-FP8 \
  --enable-auto-tool-choice --tool-call-parser qwen3_coder --reasoning-parser qwen3 \
  --max-model-len 32768 --enforce-eager \
  > vllm.log 2>&1 &
```

Watch startup, waiting for `Uvicorn running on http://0.0.0.0:8000`:

```bash
tail -f vllm.log
```

Then confirm the model is up **and that tool-calling actually parses** (Ctrl-C the
tail first). The second curl must return a populated `tool_calls` array:

```bash
curl http://127.0.0.1:8000/v1/models
curl -s http://127.0.0.1:8000/v1/chat/completions -H "Content-Type: application/json" -d '{"model":"Qwen/Qwen3.6-35B-A3B-FP8","messages":[{"role":"user","content":"List the files in /work using the shell tool."}],"tools":[{"type":"function","function":{"name":"run_shell","description":"Run a bash command","parameters":{"type":"object","properties":{"command":{"type":"string"}},"required":["command"]}}}],"tool_choice":"auto","temperature":0}' | python -m json.tool
```

> **bf16 instead of FP8:** if your friend's Mini-SWE run uses full precision, serve
> `--model Qwen/Qwen3.6-35B-A3B` (its own revision, drop nothing else) and add
> `--max-model-len 16384 --gpu-memory-utilization 0.95` so the ~71 GB weights fit
> the 80 GB card. Both agents must use the *same* variant for the comparison.

## 5. Fill the config (Qwen + the .sif sandbox image)

```bash
cp openhands/config.example.json openhands/config.local.json
# Get the exact vLLM image digest for provenance (anonymous registry query):
IMAGE_DIGEST=$(python - <<'PY'
import json,urllib.request
repo,tag="vllm/vllm-openai","latest"
tok=json.load(urllib.request.urlopen(f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"))["token"]
req=urllib.request.Request(f"https://registry-1.docker.io/v2/{repo}/manifests/{tag}",headers={"Authorization":f"Bearer {tok}","Accept":"application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.docker.distribution.manifest.v2+json"})
print(f"{repo}@"+urllib.request.urlopen(req).headers["Docker-Content-Digest"])
PY
)
echo "serving image = $IMAGE_DIGEST"
python - <<PY
import json
f="openhands/config.local.json"; c=json.load(open(f))
c["model"].update(id="Qwen/Qwen3.6-35B-A3B-FP8", revision="$REVISION",
                  license="Apache-2.0", base_url="http://127.0.0.1:8000/v1")
c["serving"].update(engine="vllm", image="$IMAGE_DIGEST",
    notes="Qwen3.6-35B-A3B MoE (35B total / ~3B active), FP8 on one 80GB H100, dtype auto, TP=1, 32k ctx, --tool-call-parser qwen3_coder + --reasoning-parser qwen3",
    command="--model Qwen/Qwen3.6-35B-A3B-FP8 --revision $REVISION --enable-auto-tool-choice --tool-call-parser qwen3_coder --reasoning-parser qwen3 --max-model-len 32768 --enforce-eager".split())
c["sandbox"]["image"]="artifacts/openhands-jq/tools.sif"   # the pulled .sif
json.dump(c, open(f,"w"), indent=2); print("patched config.local.json")
PY
```

## 6. Run → the deliverables

```bash
export OPENHANDS_LLM_API_KEY=local-dummy
python -m binary_eval preflight --config openhands/config.local.json
python -m binary_eval run --config openhands/config.local.json
python -m binary_eval report --config openhands/config.local.json
```

## 7. Check

```bash
cat results/openhands/runs/*/tools.jsonl | head     # non-empty = the agent drove the binary
cat results/openhands/reports/comparison.md
```

## Notes / likely iteration points

- **`module load` names** differ per cluster. If `python -m binary_eval.build` fails
  on `autoreconf`/`bison`/`flex`/`gcc`, find the modules with `module avail` and load them.
- **Tool-calling (Qwen3.6):** serve with `--tool-call-parser qwen3_coder` **and**
  `--reasoning-parser qwen3`. If `tools.jsonl` is empty, the model never called the
  sandbox tool — confirm the tool-call curl in Step 4 returns a populated
  `tool_calls` array with `finish_reason: "tool_calls"`. If the call instead shows
  up as raw `<function=...>` text in `content`, the tool-call parser is wrong
  (`hermes` cannot read Qwen3.6's XML — use `qwen3_coder`).
- **Thinking mode** is on by default for Qwen3 and eats the token/time budget. If
  runs stall or repeat under greedy sampling (temp 0), coordinate with the Mini-SWE
  side on disabling it (`enable_thinking=False`) or raising temperature, and keep
  both agents identical.
- **Tools image is larger now** (headless Ghidra + JDK ≈ 0.5 GB on top of radare2/
  valgrind/angr); the first `singularity pull` of `tools.sif` takes longer. The
  build downloads a pinned Ghidra 11.0.3 release and verifies its sha256.
- **Ground truth:** runs work without it; you still need row 4 to score a confirmed
  hit. Fill `openhands/ground_truth.json`, then re-run `report` (it re-scores saved runs).
- **Singularity version** here is 3.6.4; if `--net` is rejected at run time, tell me and
  we'll drop hard network isolation and record it as prompt-enforced.
