#!/usr/bin/env bash
# Build libredwg @ 93c2512 at -O0 and collect the dwg2dxf program.
# Artifacts under /artifacts: dwg2dxf, dwg2dxf.stripped, dwg2dxf.asan
# Vuln (candidate CVE-2023-25222) is in the DWG decode path reached from
# programs/dwg2dxf.c (bit_read_RC in src/bits.c via decode_R13_R2000).
set -euo pipefail
SRC="${SRC:-/src}"; OUT="${OUT:-/artifacts}"
mkdir -p "$OUT"; cd "$SRC"

sh ./autogen.sh
./configure --disable-bindings --disable-shared --disable-dependency-tracking CFLAGS="-O0 -g"
make -j"$(nproc)"
cp programs/dwg2dxf "$OUT/dwg2dxf"
cp "$OUT/dwg2dxf" "$OUT/dwg2dxf.stripped" && strip "$OUT/dwg2dxf.stripped"

make distclean >/dev/null 2>&1 || true
# The public report built with --enable-release --enable-trace for this bug.
./configure --disable-bindings --disable-shared --disable-dependency-tracking \
    --enable-trace CFLAGS="-O0 -g -fsanitize=address" LDFLAGS="-fsanitize=address"
make -j"$(nproc)"
cp programs/dwg2dxf "$OUT/dwg2dxf.asan"

echo "built:"; ls -la "$OUT"
file "$OUT"/dwg2dxf* 2>/dev/null || true
