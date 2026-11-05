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

## 1. Get a GPU node (one 80 GB card fits Qwen-32B)

```bash
srun --partition=YOUR_GPU_PARTITION --gres=gpu:a100:1 --cpus-per-task=8 --mem=64G --time=04:00:00 --pty bash
```

## 2. Environment + runtime + build tools

```bash
cd ~/agenticsec-codex-audit && git pull
conda activate openhands
export BINARY_EVAL_CONTAINER=singularity
export HF_HOME=/scratch/$USER/hf-cache
module load gcc autoconf automake libtool bison flex git || true   # names vary; load what jq needs
```

## 3. Build the target (native jq + pull tools image)

```bash
python -m binary_eval.build
```

This compiles jq at `f58787c` natively and pulls the tools image into
`artifacts/openhands-jq/tools.sif`. If the native build fails, it's a missing
build tool — `module avail` to find the right module names and re-`module load`.

## 4. Serve Qwen with vLLM (Singularity, in the background)

```bash
REVISION=$(python -c "from huggingface_hub import HfApi;print(HfApi().model_info('Qwen/Qwen2.5-Coder-32B-Instruct').sha)")
echo "revision=$REVISION"
singularity run --nv docker://vllm/vllm-openai:latest \
  --model Qwen/Qwen2.5-Coder-32B-Instruct --revision $REVISION \
  --served-model-name Qwen/Qwen2.5-Coder-32B-Instruct \
  --enable-auto-tool-choice --tool-call-parser hermes --max-model-len 32768 &
```

Wait for it to load, then confirm:

```bash
curl http://127.0.0.1:8000/v1/models
```

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
c["model"].update(id="Qwen/Qwen2.5-Coder-32B-Instruct", revision="$REVISION",
                  license="Apache-2.0", base_url="http://127.0.0.1:8000/v1")
c["serving"].update(engine="vllm", image="$IMAGE_DIGEST",
    command="--model Qwen/Qwen2.5-Coder-32B-Instruct --revision $REVISION --enable-auto-tool-choice --tool-call-parser hermes --max-model-len 32768".split())
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
- **`--tool-call-parser hermes`** is correct for Qwen2.5-Coder. If `tools.jsonl` is
  empty, the model never called the sandbox tool — check the vLLM log.
- **Ground truth:** runs work without it; you still need row 4 to score a confirmed
  hit. Fill `openhands/ground_truth.json`, then re-run `report` (it re-scores saved runs).
- **Singularity version** here is 3.6.4; if `--net` is rejected at run time, tell me and
  we'll drop hard network isolation and record it as prompt-enforced.
