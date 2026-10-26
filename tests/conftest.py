import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for p in (ROOT / "harness", ROOT / "judge", ROOT / "reports"):
    sys.path.insert(0, str(p))
