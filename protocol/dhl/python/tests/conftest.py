from __future__ import annotations

import sys
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
HOST_PROTOCOL_ROOT = Path(__file__).resolve().parents[3] / "host_app" / "protocol" / "python"
for path in (PACKAGE_ROOT, HOST_PROTOCOL_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
