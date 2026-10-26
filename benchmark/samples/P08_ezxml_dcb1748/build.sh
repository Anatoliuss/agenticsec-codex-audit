#!/usr/bin/env bash
# Build ezxml @ dcb1748 at -O0: the `ezxml` test driver (EZXML_TEST main()).
# Produces three artifacts under /artifacts:
#   ezxml            unstripped, -O0 -g   (for ground-truth / symbol mapping)
#   ezxml.stripped   stripped             (for stripped-binary audit)
#   ezxml.asan       -O0 -g +ASan         (for PoC reproduction)
set -euo pipefail
SRC="${SRC:-/src}"; OUT="${OUT:-/artifacts}"
mkdir -p "$OUT"; cd "$SRC"

# EZXML_TEST builds a `main()` that parses argv[1] as an XML file.
make -s clean >/dev/null 2>&1 || true
gcc -O0 -g -D EZXML_TEST -D EZXML_NOMMAP -Wall -o "$OUT/ezxml" ezxml.c
cp "$OUT/ezxml" "$OUT/ezxml.stripped" && strip "$OUT/ezxml.stripped"
gcc -O0 -g -fsanitize=address -D EZXML_TEST -D EZXML_NOMMAP -Wall -o "$OUT/ezxml.asan" ezxml.c

echo "built:"; ls -la "$OUT"
file "$OUT/ezxml" "$OUT/ezxml.stripped" "$OUT/ezxml.asan" 2>/dev/null || true
