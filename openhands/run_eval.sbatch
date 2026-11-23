#!/bin/bash
# Unattended OpenHands binary-eval run on Jubail (Singularity + vLLM on one H100).
# Usage:  sbatch openhands/run_eval.sbatch [path/to/config.local.json]
# Serves the model named in the config, waits for it, runs preflight+run+report,
# then stops the server. Survives SSH disconnects (that is why we use sbatch).
#SBATCH --job-name=oh-bineval
#SBATCH --partition=nvidia
#SBATCH --gres=gpu:h100:1
#SBATCH --cpus-per-task=8
#SBATCH --mem=96G
#SBATCH --time=08:00:00
#SBATCH --output=oh-bineval-%j.log
set -uo pipefail

CONFIG="${1:-openhands/config.local.json}"
cd "$HOME/agenticsec-codex-audit" || exit 1

# --- environment (same as the interactive runbook) ---
source "$(conda info --base)/etc/profile.d/conda.sh"
conda activate openhands
export BINARY_EVAL_CONTAINER=singularity
export HF_HOME=/scratch/$USER/hf-cache
export SINGULARITY_CACHEDIR=/scratch/$USER/.singularity-cache
export SINGULARITY_TMPDIR=/scratch/$USER/.singularity-tmp
export OPENHANDS_LLM_API_KEY=local-dummy
mkdir -p "$HF_HOME" "$SINGULARITY_CACHEDIR" "$SINGULARITY_TMPDIR"
module purge 2>/dev/null || true   # clearing modules keeps the vLLM container compiler clean

# --- read model id/revision FROM the config so the server matches it exactly ---
MODEL_ID=$(python -c "import json;print(json.load(open('$CONFIG'))['model']['id'])")
REVISION=$(python -c "import json;print(json.load(open('$CONFIG'))['model']['revision'])")
echo "Config:   $CONFIG"
echo "Serving:  $MODEL_ID @ $REVISION"

VLLM_PID=""
cleanup() { [ -n "$VLLM_PID" ] && kill "$VLLM_PID" 2>/dev/null || true; }
trap cleanup EXIT

# --- start vLLM only if it is not already up on this node ---
if ! curl -sf http://127.0.0.1:8000/v1/models >/dev/null 2>&1; then
  singularity run --nv docker://vllm/vllm-openai:latest \
    --model "$MODEL_ID" --revision "$REVISION" --served-model-name "$MODEL_ID" \
    --enable-auto-tool-choice --tool-call-parser qwen3_coder \
    --reasoning-parser qwen3 --max-model-len 32768 --enforce-eager \
    > "vllm-${SLURM_JOB_ID}.log" 2>&1 &
  VLLM_PID=$!
  echo "vLLM starting (pid $VLLM_PID); waiting for readiness (first run downloads weights)..."
  for i in $(seq 1 180); do           # up to ~30 min
    if curl -sf http://127.0.0.1:8000/v1/models >/dev/null 2>&1; then echo "vLLM ready after ~$((i*10))s"; break; fi
    if ! kill -0 "$VLLM_PID" 2>/dev/null; then echo "vLLM exited early; see vllm-${SLURM_JOB_ID}.log"; exit 1; fi
    sleep 10
  done
  curl -sf http://127.0.0.1:8000/v1/models >/dev/null 2>&1 || { echo "vLLM not ready in time"; exit 1; }
fi

# --- run the evaluation (report runs even if a run fails, so partial results are written) ---
python -m binary_eval preflight --config "$CONFIG" || { echo "preflight failed"; exit 1; }
python -m binary_eval run       --config "$CONFIG" || echo "run returned nonzero (a run failed/timed out); continuing to report"
python -m binary_eval report    --config "$CONFIG"
echo "DONE. Reports in results/openhands/reports/"
