#!/usr/bin/env bash
# Build one benchmark sample at -O0 into $OUT (default /artifacts):
#   <bin>           unstripped -O0 -g   (ground-truth / symbol mapping)
#   <bin>.stripped  stripped copy       (binary-level audit)
#   <bin>.asan      -O0 -g + ASan       (PoC reproduction)
# and then checks that each known vulnerable function is in the unstripped binary.
#
# usage: build.sh <sample_id>        (normally run inside benchmark/Dockerfile)
set -euo pipefail
SAMPLE="${1:?usage: build.sh <sample_id>}"
SRC="${SRC:-/src}"; OUT="${OUT:-/artifacts}"
ASAN="-fsanitize=address"
ASAN_EXTRA=""   # extra ./configure args for the ASan build only

case "$SAMPLE" in
  P08_ezxml_dcb1748)
    REPO=https://github.com/lxfontes/ezxml COMMIT=dcb17484da2591e42c739598729fe5bdf687cca6
    BIN=ezxml FUNCS="ezxml_internal_dtd ezxml_parse_str" ;;
  P09a_libredwg_5f99814)
    REPO=https://github.com/LibreDWG/libredwg COMMIT=5f998146dd695a8b4bfdbd21c233e42fbb94e90d
    BIN=dwg2SVG FUNCS="htmlescape" ;;
  P09b_libredwg_93c2512)
    REPO=https://github.com/LibreDWG/libredwg COMMIT=93c25124c191987af168ace9fe4b5623061874bd
    BIN=dwg2dxf FUNCS="bit_read_RC"
    ASAN_EXTRA="--enable-trace" ;;  # the public report for this bug built with tracing
  P10_faad2_1073aee)
    REPO=https://github.com/knik0/faad2 COMMIT=1073aeef823cafd844704389e9a497c257768e2f
    BIN=faad FUNCS="stszin" ;;
  *) echo "unknown sample: $SAMPLE" >&2; exit 2 ;;
esac

git clone --quiet "$REPO" "$SRC"
cd "$SRC"
git checkout --quiet "$COMMIT"
mkdir -p "$OUT"

# build <extra CFLAGS/LDFLAGS> <output name> [extra ./configure args]
build() {
  local flags="$1" out="$2"; shift 2
  case "$SAMPLE" in
    P08_*)   # EZXML_TEST builds a main() that parses argv[1] as an XML file
      gcc -O0 -g $flags -D EZXML_TEST -D EZXML_NOMMAP -Wall -o "$OUT/$out" ezxml.c ;;
    P09*)
      make distclean >/dev/null 2>&1 || true
      [ -x ./configure ] || sh ./autogen.sh
      ./configure --disable-bindings --disable-shared --disable-dependency-tracking "$@" \
          CFLAGS="-O0 -g $flags" LDFLAGS="$flags"
      make -j"$(nproc)"
      cp "programs/$BIN" "$OUT/$out" ;;
    P10_*)
      make distclean >/dev/null 2>&1 || true
      [ -x ./bootstrap ] && sh ./bootstrap || autoreconf -fi
      ./configure --enable-shared=no CFLAGS="-O0 -g $flags" LDFLAGS="$flags"
      make -j"$(nproc)"
      cp frontend/faad "$OUT/$out" ;;
  esac
}

build "" "$BIN"
cp "$OUT/$BIN" "$OUT/$BIN.stripped" && strip "$OUT/$BIN.stripped"
build "$ASAN" "$BIN.asan" $ASAN_EXTRA

# Validate the artifact: the ground-truth function must be a symbol in the binary.
for fn in $FUNCS; do
  if nm "$OUT/$BIN" | grep -w "$fn" >/dev/null; then
    echo "OK   $fn found in $BIN"
  else
    echo "FAIL $fn not found in $BIN" >&2; exit 1
  fi
done
ls -la "$OUT"
