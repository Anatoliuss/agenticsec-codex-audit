# Notice / provenance

This repository is an **evaluation harness and benchmark metadata set** for
AgenticSec. It contains:

- **Benchmark metadata** (CVE IDs, vulnerable-function ground truth, build
  recipes) for a subset (P8–P10) of the projects in the VERITAS paper's Table I.
  The P1–P7 rows and the VERITAS framework itself are not included.
- **Harness / judge / report code** authored for this repository.

It does **not** contain:

- Copies of the audited projects' source (they are cloned at build time from
  their upstream repositories at the pinned commits).
- Weaponized proof-of-concept inputs. The bugs are already-patched, publicly
  disclosed vulnerabilities; `benchmark/POCS.md` links to the upstream issue
  trackers where the public PoCs live.

## Audited projects (cloned at build time, their own licenses apply)

| Project | Upstream | License |
|---|---|---|
| ezxml | https://github.com/lxfontes/ezxml | MIT |
| LibreDWG | https://github.com/LibreDWG/libredwg | GPL-3.0 |
| faad2 | https://github.com/knik0/faad2 | GPL-2.0 (with the FAAD2 license terms) |

## Source paper

Veritas: *Grounding LLM Agents for Reliable Vulnerability Reasoning over
Stripped Binaries* — https://arxiv.org/abs/2605.15097 (Table I).
Benchmark statistics (#IR Inst., #Func, #Vuln_files, #Vuln) are reproduced from
that table for the P8–P10 subset.

CVE and patch details were cross-referenced against upstream issue trackers,
project git history, and the CVE/OSV/NVD records cited inline in each sample's
`ground_truth.json`.
