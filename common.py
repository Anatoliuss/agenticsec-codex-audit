"""Small helpers shared by audit.py, judge.py and report.py (standard library only)."""
from __future__ import annotations

import datetime as dt
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PROMPTS = ROOT / "prompts"
RUNS = ROOT / "results" / "runs"
JUDGMENTS = ROOT / "results" / "judgments"
REPORTS = ROOT / "results" / "reports"


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def save_json(obj, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def load_config() -> dict:
    return load_json(ROOT / "config.json")


def load_samples() -> dict[str, dict]:
    """All benchmark samples from benchmark/samples.json, keyed by sample_id."""
    return {s["sample_id"]: s for s in load_json(ROOT / "benchmark" / "samples.json")["samples"]}


def fill(template: str, **values) -> str:
    """Read prompts/<template> and replace every {{key}} with its value."""
    text = (PROMPTS / template).read_text(encoding="utf-8")
    for key, val in values.items():
        text = text.replace("{{" + key + "}}", str(val))
    return text


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def codex_command(cfg: dict, *, model: str, sandbox: str, schema: Path, last_message: Path) -> list[str]:
    """The `codex exec` command line. The prompt itself is sent on stdin ("-")."""
    return [cfg["codex_bin"], "exec", "--json",
            "--skip-git-repo-check",   # the source snapshot has no .git
            "--ephemeral",             # don't save the session under ~/.codex
            "--ignore-user-config",    # same tools every run: no personal plugins / MCP servers
            "-m", model, "-c", f'model_reasoning_effort="{cfg["reasoning_effort"]}"',
            "--sandbox", sandbox,
            "--output-schema", str(schema),         # final answer must be this JSON shape
            "--output-last-message", str(last_message),
            *cfg.get("codex_extra_args", []), "-"]


def run_codex(cmd: list[str], prompt: str, *, cwd, transcript: Path, timeout: int) -> int:
    """Run a codex command with the prompt on stdin, saving its JSONL event
    stream to `transcript`. Returns the exit code; raises TimeoutExpired."""
    exe = shutil.which(cmd[0]) or cmd[0]  # also finds codex.cmd on Windows
    with open(transcript, "w", encoding="utf-8") as out:
        proc = subprocess.run([exe, *cmd[1:]], input=prompt, text=True, encoding="utf-8",
                              cwd=cwd, stdout=out, stderr=subprocess.STDOUT, timeout=timeout)
    return proc.returncode


def codex_version(cfg: dict) -> str | None:
    exe = shutil.which(cfg["codex_bin"])
    if not exe:
        return None
    out = subprocess.run([exe, "--version"], capture_output=True, text=True)
    return out.stdout.strip() or None
