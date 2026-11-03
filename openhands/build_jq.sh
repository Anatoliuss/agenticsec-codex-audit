#!/usr/bin/env bash
set -euo pipefail
git clone https://github.com/jqlang/jq /build/jq
cd /build/jq
git checkout --detach f58787c
revision=$(git rev-parse HEAD)
[[ "$revision" == f58787c* ]]
autoreconf -fi
# A fixed, non-PIE build makes exported virtual addresses directly comparable.
./configure --disable-shared CFLAGS='-O0 -g -fno-pie' LDFLAGS='-no-pie'
make -j2
mkdir -p /export
cp jq /export/jq.unstripped
nm -n /export/jq.unstripped > /export/symbols.txt
cp jq /export/jq
strip --strip-all /export/jq
cp COPYING /export/jq.LICENSE
python3 - "$revision" <<'PY'
import hashlib, json, pathlib, subprocess, sys
p = pathlib.Path('/export')
manifest = {
    'repository': 'https://github.com/jqlang/jq',
    'requested_commit': 'f58787c', 'resolved_commit': sys.argv[1],
    'binary_sha256': hashlib.sha256((p / 'jq').read_bytes()).hexdigest(),
    'unstripped_sha256': hashlib.sha256((p / 'jq.unstripped').read_bytes()).hexdigest(),
    'flags': {'CFLAGS': '-O0 -g -fno-pie', 'LDFLAGS': '-no-pie'},
    'configure': ['./configure', '--disable-shared'],
    'compiler': subprocess.check_output(['gcc', '--version'], text=True),
    'packages': subprocess.check_output(['dpkg-query', '-W'], text=True),
    'platform': subprocess.check_output(['uname', '-m'], text=True),
    'symbol_map': 'symbols.txt', 'stripped': True,
}
(p / 'build.json').write_text(json.dumps(manifest, indent=2) + '\n')
PY
