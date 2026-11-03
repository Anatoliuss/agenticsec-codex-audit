# Add OpenHands binary evaluation alongside Codex

## Design and constraints

The user requests additive support for the attached jq binary evaluation while
retaining the Codex identity and existing commands. Work in this folder, preserve
the pre-existing staged deletions and local changes, and do not run an evaluation.

Use a separate `binary_eval` Python package and `openhands/` configuration,
prompts, and build context. The existing source-based Codex pipeline stays intact.
An OpenHands SDK controller on the host exposes only a custom Docker shell tool;
the shell executes in a fresh, network-disabled container with only the binary.
The model server is reached by the controller, not the analysis container.
Store complete SDK events, command outputs, prompts, metrics, provenance, and
strictly validated findings. Ground truth never enters the analysis environment.

This separation is preferred over rewriting the current runner because its
source-oriented findings, samples, and judge are still useful for Codex runs.
The SDK is pinned; tool images are resolved to immutable IDs before either run.
Model revision, license and serving provenance must be provided before execution.
The screenshot's CVE/function association remains unverified until the referenced
annotation is supplied; reports must not turn missing ground truth into a miss.

## Implementation plan

- [x] Add failing offline tests for prompt isolation, immutable provenance,
  Docker boundary, malformed output, address matching, failures and pairing.
- [x] Add binary configuration, prompts/schema, jq build and analysis image.
- [x] Add OpenHands custom tool and worker, supervised runs with deadlines,
  preflight/dry-run commands, persistent evidence and metrics.
- [x] Add per-run/per-sample/aggregate reporting with honest unavailable metrics
  and manual-validation flags; never combine incompatible experiments.
- [x] Document both workflows and verify old/new offline tests, CLI behavior,
  SDK construction and syntax. Actual Docker/model runs require configured
  infrastructure and are outside this edit request.

## Review focus

No source/ground-truth mounts; no accidental host shell execution; no success
on malformed or timed-out runs; no function matches without verified annotation;
no comparison of mismatched binary/model/settings. Review SDK integration against
the pinned package. No commits or resets of the user's existing work.

## Verification and review ledger

- Original Codex pipeline: 8 offline checks pass.
- Binary pipeline: 16 offline behavior checks pass.
- Pinned SDK: construction/tool-boundary/persistence and synthetic model-response
  capture checks pass (2 tests); no real model inference or Docker execution.
- Independent review found truncated metrics could erase timeout classification;
  fixed with atomic snapshots and defensive reading, covered by regression test.
- Independent review found optional SDK detection confused the asset directory
  with the installed SDK; fixed and verified with site-packages disabled.
- Corrected login-shell PATH reset so the analysis Python/angr remain available.
- Syntax compilation and tracked-diff whitespace checks pass.
- Docker build/evaluation remain unexecuted. A model ID/revision/license, pinned
  serving deployment and verified annotation are operator inputs, not invented
  defaults. Source task identifiers are retained as unverified metadata.
- Existing staged deletions were left untouched. No commit or push performed.
