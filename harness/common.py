"""Shared helpers for the AgenticSec Codex audit harness.

No third-party dependencies beyond PyYAML (and jsonschema for validation, used
only in tests). Everything here is pure-Python and import-safe.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
BENCH_DIR = REPO_ROOT / "benchmark"
SAMPLES_DIR = BENCH_DIR / "samples"
PROMPTS_DIR = REPO_ROOT / "harness" / "prompts"


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_json(path: str | Path) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def dump_json(obj: Any, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


@dataclass
class Sample:
    sample_id: str
    meta: dict
    ground_truth: dict
    dir: Path

    @property
    def project(self) -> str:
        return self.meta["project"]

    @property
    def commit(self) -> str:
        return self.meta["commit"]

    @property
    def binary(self) -> str:
        return self.meta["binary"]

    @property
    def repo_url(self) -> str:
        return self.meta["repo_url"]

    @property
    def cve_ids(self) -> list[str]:
        ids: list[str] = []
        for v in self.ground_truth.get("vulnerabilities", []):
            # prefer an explicit primary CVE so the hint uses it first
            primary = v.get("cve_primary")
            if primary and primary.startswith("CVE-"):
                ids.append(primary)
            # a vuln may list several alternate CVEs in one string "A / B / C"
            for part in re.split(r"[\s/]+", v.get("cve", "")):
                if part.startswith("CVE-"):
                    ids.append(part)
        # de-dup, preserve order
        seen: set[str] = set()
        out: list[str] = []
        for i in ids:
            if i not in seen:
                seen.add(i)
                out.append(i)
        return out

    @property
    def vulnerable_functions(self) -> list[str]:
        fns: list[str] = []
        for v in self.ground_truth.get("vulnerabilities", []):
            fns.append(v["vulnerable_function"])
            fns.extend(v.get("match_aliases", []))
        # de-dup, preserve order
        seen: set[str] = set()
        out: list[str] = []
        for f in fns:
            if f not in seen:
                seen.add(f)
                out.append(f)
        return out


def load_sample(sample_id: str) -> Sample:
    sdir = SAMPLES_DIR / sample_id
    meta = load_json(sdir / "sample.json")
    gt = load_json(sdir / meta.get("ground_truth_ref", "ground_truth.json"))
    return Sample(sample_id=sample_id, meta=meta, ground_truth=gt, dir=sdir)


def load_all_samples() -> list[Sample]:
    index = load_json(BENCH_DIR / "benchmark.json")
    return [load_sample(s["sample_id"]) for s in index["samples"]]


def _fill(template: str, mapping: dict[str, str]) -> str:
    out = template
    for key, val in mapping.items():
        out = out.replace("{{" + key + "}}", str(val))
    return out


def render_task_prompt(sample: Sample, configuration: str,
                       cve_id: str | None = None) -> str:
    """Render the task prompt for a given configuration.

    zero_shot gives no CVE hint; cve_hinted injects exactly the CVE id (and
    nothing about the vulnerable function name)."""
    base = {
        "project": sample.project,
        "commit": sample.commit,
        "binary": sample.binary,
        "entrypoint": sample.meta.get("entrypoint", ""),
        "trigger_input": sample.meta.get("trigger_input", ""),
    }
    if configuration == "zero_shot":
        tmpl = (PROMPTS_DIR / "zero_shot.md").read_text(encoding="utf-8")
        return _fill(tmpl, base)
    if configuration == "cve_hinted":
        if not cve_id:
            cve_id = sample.cve_ids[0]
        base["cve_id"] = cve_id
        tmpl = (PROMPTS_DIR / "cve_hinted.md").read_text(encoding="utf-8")
        return _fill(tmpl, base)
    raise ValueError(f"unknown configuration: {configuration}")


def system_prompt() -> str:
    return (PROMPTS_DIR / "system.md").read_text(encoding="utf-8")


def extract_findings_json(text: str) -> tuple[dict | None, str | None]:
    """Pull the last ```json fenced block out of Codex's final message and parse
    it. Returns (obj, error). Tolerant of prose around the block."""
    if not text:
        return None, "empty output"
    blocks = re.findall(r"```json\s*(.*?)```", text, flags=re.DOTALL | re.IGNORECASE)
    candidates = blocks if blocks else []
    # fall back to the largest {...} span if no fence
    if not candidates:
        m = re.findall(r"(\{.*\})", text, flags=re.DOTALL)
        candidates = m[-1:] if m else []
    for raw in reversed(candidates):
        try:
            obj = json.loads(raw.strip())
            if isinstance(obj, dict) and "findings" in obj:
                return obj, None
        except json.JSONDecodeError:
            continue
    return None, "no valid findings JSON object found"
