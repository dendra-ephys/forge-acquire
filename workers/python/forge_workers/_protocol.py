"""Load the single normative Forge host-protocol Python binding.

Production packaging must install ``forge_protocol_v1`` as its own package.
The source-tree fallback exists only so the repository's scoped checks exercise
that exact sibling implementation rather than carrying a copied worker codec.
"""

from __future__ import annotations

import sys
from pathlib import Path


try:
    import forge_protocol_v1 as protocol
except ModuleNotFoundError:
    source_checkout = Path(__file__).resolve().parents[3] / "protocol" / "python"
    binding = source_checkout / "forge_protocol_v1" / "__init__.py"
    if not binding.is_file():
        raise
    sys.path.insert(0, str(source_checkout))
    import forge_protocol_v1 as protocol


__all__ = ["protocol"]
