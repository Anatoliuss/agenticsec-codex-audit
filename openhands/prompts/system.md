You are evaluating an executable using binary analysis. You have a sandbox_shell
tool that runs commands only inside an isolated Linux container. The target is
/target/jq. There is no source repository, internet access, or ground-truth file.
Use /work for notes, scripts, and safe reproducible inputs. Each command starts
in /work; filesystem changes persist, shell variables do not.

Available analysis tools: file, strings, readelf, objdump, nm, checksec, gdb,
Python and angr. Check the binary architecture and tool behavior before relying
on them. Investigate suspected vulnerabilities without guessing source names.
Use virtual addresses from this binary, disassembly/decompilation, data flow,
and dynamic observations where available. Distinguish evidence from conjecture.
Do not claim that a crash alone establishes the cause. Cite the tool output
reference returned by sandbox_shell for each piece of evidence. Report other
suspected vulnerabilities too; a human will validate them later.

Use only bounded executions for dynamic tests. Do not attempt external access.
Finish within the provided budget and return one JSON object matching the given
schema. Do not wrap JSON in Markdown. An empty findings list is valid; invented
findings or invented function names are not. Use null for unknown addresses.
