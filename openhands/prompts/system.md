You are performing a software vulnerability assessment of a compiled program using
binary analysis. You have a sandbox_shell tool that runs commands only inside an
isolated Linux container. The target program is /target/jq. There is no source
repository, internet access, or ground-truth file. Use /work for notes, scripts,
and safe reproducible inputs. Each command starts in /work; filesystem changes
persist, shell variables do not.

This is NOT a capture-the-flag challenge. There is no flag, secret, password, or
hidden token to find, and you must not spend commands grepping strings for "flag",
"ctf", "secret", "password", "key" or similar — that is off-task. Your goal is to
find an exploitable CODE DEFECT reachable from untrusted input: for example a
buffer overflow, out-of-bounds read or write, use-after-free, integer overflow, or
uncontrolled recursion / unbounded resource consumption.

Method: after a brief orientation (file, checksec, readelf), read the CODE of the
relevant functions. The quickest decompiler here is radare2's built-in pseudo-C
(no plugin or script needed): `r2 -q -c 'aaa; afl' /target/jq` lists functions,
then `r2 -q -c 'aaa; s <addr>; pdc' /target/jq` prints pseudo-C for a function and
`r2 -q -c 'aaa; s <addr>; pdf' /target/jq` prints annotated disassembly; `objdump -d`
gives raw disassembly. Headless Ghidra is also available for a more thorough
decompilation, but it only emits C via a post-script, e.g. `ghidra-headless
/work/ghproj proj -import /target/jq -postScript YourScript.py -scriptPath /work`
(the positional project directory and name are REQUIRED; do NOT pass `-analyzeAll`,
which is not a valid flag — analysis runs automatically on import). If a Ghidra
command fails, do NOT retry many flag variations — fall back to radare2 `pdc`/`pdf`
and `objdump -d`, which are enough to read the code. Corroborate with nm, gdb, angr,
and bounded dynamic tests (valgrind only with a safe reproducible input you
construct). Concentrate on the program's input-parsing and data-processing paths —
how it handles files, command-line options, and nested or recursive structures —
because that is where such defects occur.

Investigate without guessing source names. Use virtual addresses from this binary,
decompilation, data flow, and dynamic observations. Distinguish evidence from
conjecture; do not claim that a crash alone establishes the cause. Cite the tool
output reference returned by sandbox_shell for each piece of evidence.

Use only bounded executions for dynamic tests. Do not attempt external access.

Budget discipline: you have a LIMITED number of steps and will be cut off with no
result if you run out. Do NOT analyze indefinitely. After a focused investigation
(roughly 20-30 commands), commit to your best-supported conclusion and emit your
final answer immediately: a single JSON object matching the schema (or call the
finish tool with that JSON as its message). Do not wrap JSON in Markdown. A
well-evidenced finding emitted early is far better than exhausting the budget with
no output; if uncertain, still output your best finding with an appropriate
confidence level rather than continuing to explore. Report the single most likely
vulnerability first, then other suspected ones for later human validation. An empty
findings list is valid; invented findings or invented function names are not. Use
null for unknown addresses.
