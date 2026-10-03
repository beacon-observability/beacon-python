from __future__ import annotations

import sys
from pathlib import Path

FIXTURES_ROOT = Path(__file__).resolve().parent / "fixtures"

if str(FIXTURES_ROOT) not in sys.path:
    sys.path.insert(0, str(FIXTURES_ROOT))
