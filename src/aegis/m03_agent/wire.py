"""Small helpers for the generated DTOs, which wrap some contract shapes in `RootModel`s.

`model-message.v2` types a content block as `oneOf` of three blocks, so the generated `ContentBlock`
is a `RootModel` and `block.type` lives on `block.root`; `common/ids.v2#/$defs/Id` is a `RootModel`
over a string for the same reason. Reading through `plain()` keeps the rest of M03 free of that
detail instead of `getattr(block, "root", block)` in every node.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import BaseModel, RootModel

__all__ = ["blocks", "plain"]


def plain(value: Any) -> Any:
    """Unwrap generated models (recursively) into plain JSON values."""
    if isinstance(value, RootModel):
        return plain(value.root)
    if isinstance(value, BaseModel):
        return plain(value.model_dump(mode="json"))
    if isinstance(value, Mapping):
        return {str(key): plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(item) for item in value]
    return value


def blocks(message: Any) -> list[Any]:
    """The content blocks of a contract `Message`, unwrapped (`type`, `text`, `call`, `result`)."""
    content: Sequence[Any] = getattr(message, "content", None) or []
    return [plain(block) for block in content]
