"""Fake M04 ModelClient: the first-class `aegis.m04_model.fake` driver (G1.2a).

Kept under `tests/fakes/` so the six-interface fake set (X-10) still imports one name; the
implementation moved into the M04 package, where it shares budget pre-check, contract validation
and `model_usage` recording with the real client.
"""

from __future__ import annotations

from aegis.m04_model.fake import FakeModelClient

__all__ = ["FakeModelClient"]
