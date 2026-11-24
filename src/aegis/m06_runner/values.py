"""Scalar access for generated contract DTOs (G1.3a).

Several contract scalars (`Id`, `Sha256`, `CanonicalKey`, `ImageDigest`, `CapabilityId`,
`PolicyVersion`) are generated as Pydantic `RootModel[str]` wrappers. `str()` on such a value
renders `root='...'`, which silently breaks comparisons, container names and wire documents, so
every M06 module converts through `text()` instead of `str()`.
"""

from __future__ import annotations

import re
from typing import Any

#: Prefixes of `common/ids.v2` canonical keys (`dns:`, `ip:`, `url:`, `service:`, `app:`). A target
#: value handed to a tool has them stripped: they are platform notation, not part of the name.
TARGET_PREFIXES = re.compile(r"^(?:dns|ip|url|service|app):")


def text(value: Any) -> str:
    """The plain string of a scalar DTO (unwrapping nested `RootModel`s), else `str(value)`."""
    for _ in range(8):  # codegen nests RootModel in RootModel for `$defs` aliases
        root = getattr(value, "root", None)
        if root is None or root is value:
            break
        value = root
    return value if isinstance(value, str) else str(value)
