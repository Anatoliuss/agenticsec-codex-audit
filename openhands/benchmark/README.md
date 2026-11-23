# Vulnerability benchmark annotations

Validated, reproducible vulnerability records for the OpenHands + Ghidra binary
evaluation. The two assigned binaries (`jq`, `Exiv2`) are filled in; the task
requires **10–15 additional** validated applications on top of these.

## Required fields (Nada's dataset spec)

Each entry in `annotations.json` must carry:

| Field | Meaning |
|---|---|
| `vulnerable_repository_url` | Upstream source repository URL |
| `vulnerable_commit` | Commit/version that still contains the bug |
| `fixed_commit` | Commit/version that fixes it |
| `binary_sha256` | SHA-256 of the exact built (stripped) binary analysed |
| `build_provenance` | Compiler, flags, and build command used |
| `cwe` / `cwe_name` | Exact CWE and its name |
| `cwe_broader_family` | The broader CWE family |
| `vulnerable_function` | The known vulnerable function (reference) |
| `triggering_inputs[]` | Each input/payload file: `path`, `content`, `sha256` |
| `execution_command` | Exact command that triggers the bug |
| `expected_vulnerable_behavior` | What the vulnerable binary does (crash, OOB, etc.) |
| `captured_output` | Unmodified `stdout`, `stderr`, `exit_code` from the real run — **captured, not expected** |
| `ghidra_version` | Exact Ghidra release used for the analysis |

Rules: build and run the **vulnerable** commit; capture the **actual** output
(never substitute the expected result); record the exact Ghidra build.

## Status

- `jq` (CVE-2026-44777) — fields complete; **must rebuild at the vulnerable
  commit `9d223f15…`** and capture the real crash output (the earlier binary was
  built at the *fixed* commit `f58787c`, so it does not crash).
- `Exiv2` (CVE-2021-29464) — fields filled from public advisories; PoC JP2,
  binary hash, and captured output still to be produced on the built binary.
- 10–15 further applications — to collect and validate.
