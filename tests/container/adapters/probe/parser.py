# mypy: ignore-errors
"""Test-only shim so a test manifest can pin a contract-valid `adapters.*` parser entrypoint.

The parser child puts `tests/container` first on PYTHONPATH, so `adapters.probe.parser` resolves
here instead of the product `adapters` package; the real parser logic is `aegis_probe.parser`
(the name the parser-host tests use directly). Production code never passes that extra path.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def parse(output_dir: Path, task: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    from aegis_probe.parser import parse as real_parse

    return real_parse(output_dir, task, evidence)
