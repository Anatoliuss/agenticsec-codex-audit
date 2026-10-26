# Public PoC provenance (P8–P10)

These are **already-patched, publicly disclosed** bugs in file parsers. The
PoC inputs live on the upstream issue trackers; this repo links to them rather
than bundling weaponized samples. Reproduce under the ASan build from each
sample's `build.sh` to collect failure evidence for the ground truth.

| Sample | Binary | Public PoC | Reproduce command |
|---|---|---|---|
| P08 ezxml @ dcb1748 | `ezxml` | SourceForge ezxml bugs [#26](https://sourceforge.net/p/ezxml/bugs/26/) (CVE-2021-31229) and [#27](https://sourceforge.net/p/ezxml/bugs/27/) (CVE-2021-31348); see also [Debian LTS DLA](https://lists.debian.org/debian-lts-announce/2021/07/msg00005.html) | `./ezxml.asan <poc.xml>` |
| P09a libredwg @ 5f99814 | `dwg2SVG` | LibreDWG issue [#182](https://github.com/LibreDWG/libredwg/issues/182) ("Several bugs found by fuzzing") | `./dwg2SVG.asan <poc.dwg>` |
| P09b libredwg @ 93c2512 | `dwg2dxf` | LibreDWG issue [#615](https://github.com/LibreDWG/libredwg/issues/615) (candidate CVE-2023-25222) | `./dwg2dxf.asan -b -m <poc.dwg> -o /dev/null` |
| P10 faad2 @ 1073aee | `faad` | faad2 issue [#57](https://github.com/knik0/faad2/issues/57) (CVE-2021-32272) | `./faad.asan -w -b 5 <poc.mp4>` |

## Expected failure evidence (from the public reports)

- **P08 / CVE-2021-31229** — OOB write of a one-byte constant in `ezxml_internal_dtd` (ezxml.c).
- **P08 / CVE-2021-31348** — OOB read in `ezxml_parse_str` (ezxml.c) after a `strcspn` scan runs off the buffer.
- **P09a** — ASan: heap-buffer-overflow in `htmlescape` via `strcat`, `programs/escape.c:46/48/51`, from `output_TEXT` (`programs/dwg2SVG.c`).
- **P09b** — ASan: heap-buffer-overflow 1-byte READ in `bit_read_RC` (`src/bits.c:320`) via `bit_read_RS`→`bit_read_RL`→`decode_R13_R2000` (`src/decode.c:682`).
- **P10** — ASan: heap-buffer-overflow WRITE of size 4 in `stszin` (`frontend/mp4read.c:355`), region alloc'd at `mp4read.c:348` (integer overflow when the stsz entry count is `0xFFFFFFFF`).

After reproducing, record the observed crash (type, faulting function, file:line)
into each sample's `ground_truth.json` under `evidence.reproduced` so the
ground truth is backed by both the patch commit and a local ASan run.
