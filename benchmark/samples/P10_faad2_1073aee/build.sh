#!/usr/bin/env bash
# Build faad2 @ 1073aee at -O0 and collect the faad frontend.
# Artifacts under /artifacts: faad, faad.stripped, faad.asan
# Vuln (CVE-2021-32272) is the stszin() integer-overflow heap overflow in
# frontend/mp4read.c.
set -euo pipefail
SRC="${SRC:-/src}"; OUT="${OUT:-/artifacts}"
mkdir -p "$OUT"; cd "$SRC"

# faad2 ships a ./bootstrap that runs autoreconf.
[ -x ./bootstrap ] && sh ./bootstrap || autoreconf -fi

./configure --enable-shared=no CFLAGS="-O0 -g"
make -j"$(nproc)"
cp frontend/faad "$OUT/faad"
cp "$OUT/faad" "$OUT/faad.stripped" && strip "$OUT/faad.stripped"

make distclean >/dev/null 2>&1 || true
[ -x ./bootstrap ] && sh ./bootstrap || autoreconf -fi
./configure --enable-shared=no CFLAGS="-O0 -g -fsanitize=address" LDFLAGS="-fsanitize=address"
make -j"$(nproc)"
cp frontend/faad "$OUT/faad.asan"

echo "built:"; ls -la "$OUT"
file "$OUT"/faad* 2>/dev/null || true
