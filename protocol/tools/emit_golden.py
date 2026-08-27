from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
sys.path.insert(0, str(ROOT / "python" / "tests"))

from fixtures import golden_vectors

for name, data in golden_vectors().items():
    print(f"*** Add File: F:/poorsystem/Forge/host_app/protocol/golden/{name}.hex")
    hex_text = data.hex()
    for offset in range(0, len(hex_text), 96):
        print("+" + hex_text[offset:offset + 96])

