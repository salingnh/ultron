"""The G1.6b demo's read queries really run against the contract schema (no stack needed).

`make demo-g16b` needs the whole local stack, which a test must not start. Its *queries* are the
part that silently rots when a column moves, so they are executed here against a migrated throwaway
database with an empty campaign: every statement must be valid SQL, and the empty result must have
the shape the checks read (lists, not missing keys). The Neo4j query and the HTTP flow read are
replaced by stubs - they are exercised by `make demo-g16b` itself and by the projector tests.
"""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import psycopg
import pytest
from psycopg.rows import dict_row

from aegis.migrations import apply_contract_migrations
from tests.pg import requires_postgres, throwaway_database

REPO = Path(__file__).resolve().parents[1]
DEMO = REPO / "scripts/demo/demo-g16b.py"
CAMPAIGN = "01900000-0000-7000-8000-0000000e0001"


def _demo_module() -> Any:
    if str(REPO / "scripts/demo") not in sys.path:
        sys.path.insert(0, str(REPO / "scripts/demo"))
    spec = importlib.util.spec_from_file_location("demo_g16b", DEMO)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def connection() -> Iterator[psycopg.Connection[Any]]:
    with throwaway_database() as dsn:
        with psycopg.connect(dsn, autocommit=True) as raw:
            apply_contract_migrations(raw)
        with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as typed:
            typed.execute("SET search_path = aegis, public")
            yield typed


@requires_postgres
def test_the_demo_queries_run_and_return_the_expected_shapes(
    connection: psycopg.Connection[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _demo_module()
    monkeypatch.setattr(
        module, "_neo4j", lambda campaign_id: {"nodes": [], "edge_types": [], "observations": []}
    )
    monkeypatch.setattr(
        module.support,
        "campaign_flow",
        lambda campaign_id: {"nodes": [], "edges": []},
    )

    document = module._collect(connection, CAMPAIGN)

    assert document["jobs"] == []
    assert document["services"] == []
    assert document["applications"] == []
    assert document["serves"] == []
    assert document["neo4j"] == {"nodes": [], "edge_types": [], "observations": []}
    assert set(document["flow"]) == {"nodes", "edges", "kinds"}
    assert document["duplicates"] == {"observation": [], "relationship": []}
