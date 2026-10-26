#!/usr/bin/env bash
# Build libredwg @ 5f99814 at -O0 and collect the dwg2SVG program.
# Artifacts under /artifacts: dwg2SVG, dwg2SVG.stripped, dwg2SVG.asan
# Bindings/docs are disabled to keep the build minimal; the vuln is in
# programs/escape.c (htmlescape) reached from programs/dwg2SVG.c.
set -euo pipefail
SRC="${SRC:-/src}"; OUT="${OUT:-/artifacts}"
mkdir -p "$OUT"; cd "$SRC"

sh ./autogen.sh
# --- unstripped -O0 ---
./configure --disable-bindings --disable-shared --disable-dependency-tracking CFLAGS="-O0 -g"
make -j"$(nproc)"
cp programs/dwg2SVG "$OUT/dwg2SVG"
cp "$OUT/dwg2SVG" "$OUT/dwg2SVG.stripped" && strip "$OUT/dwg2SVG.stripped"

# --- ASan variant (for PoC reproduction) ---
make distclean >/dev/null 2>&1 || true
./configure --disable-bindings --disable-shared --disable-dependency-tracking \
    CFLAGS="-O0 -g -fsanitize=address" LDFLAGS="-fsanitize=address"
make -j"$(nproc)"
cp programs/dwg2SVG "$OUT/dwg2SVG.asan"

echo "built:"; ls -la "$OUT"
file "$OUT"/dwg2SVG* 2>/dev/null || true
