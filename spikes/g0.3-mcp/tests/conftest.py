"""pytest fixtures for the spike."""

from __future__ import annotations

import pytest

from aegis_mcp.service import McpToolService

from .support import make_service


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def service() -> McpToolService:
    return make_service()
