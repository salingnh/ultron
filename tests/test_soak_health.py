"""The soak report is a gate on the stack it measured (G2 P0).

`soak.py` once reported `errors: []` while m23 had been dead for hours, and a 24 h run on a full
host disk as one green report with 34 failed jobs. The conditions that make a run prove nothing are
decided in `_health` and in `_projection`; both are pure functions over one report's measurements,
so they are pinned here without a stack.

Two of these tests are the g1-final defects themselves: the old report read `max(last_seq)` over
every consumer (the SSE reader is always at the head), and a dead process was only a boolean in
`memory.processes`.
"""

from __future__ import annotations

import importlib.util
from functools import lru_cache
from pathlib import Path
from typing import Any

SOAK = Path(__file__).resolve().parents[1] / "scripts" / "demo" / "soak.py"
RUNNERS = ("api", "mcp", "m02-worker", "m02-dispatcher", "m23", "m06")


@lru_cache(maxsize=1)
def soak_module() -> Any:
    """Load `scripts/demo/soak.py` (its directory is not a package)."""
    spec = importlib.util.spec_from_file_location("soak_under_test", SOAK)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def components(dead: tuple[str, ...] = ()) -> list[Any]:
    return [
        module_component(name, f"pid {name} is gone" if name in dead else None) for name in RUNNERS
    ]


def module_component(name: str, problem: str | None) -> Any:
    state = soak_module().support.ComponentState
    return state(name, None if problem else 100, "", problem)


def projection(
    *, head: int = 100, cursor: int | None = 100, generation: str | None = "m23-projector#g1"
) -> dict[str, Any]:
    return {
        "outbox_head": head,
        "projector_generation": generation,
        "projector_cursor": cursor,
        "projector_lag": None if cursor is None else head - cursor,
        "consumers": {} if generation is None else {generation: cursor},
    }


def healthy_store() -> dict[str, Any]:
    return {
        "ok": True,
        "error": None,
        "path": "/home/x/.local/share/containers/storage",
        "free_percent": 42.0,
        "min_free_percent": 1.0,
    }


def graph(**overrides: int) -> dict[str, int]:
    values = {
        "postgres_assets": 7,
        "graph_assets": 7,
        "postgres_open_edges": 12,
        "graph_edges": 12,
        "asset_mismatch": 0,
        "edge_mismatch": 0,
    }
    values.update(overrides)
    return values


def health(module: Any, **overrides: Any) -> dict[str, Any]:
    arguments: dict[str, Any] = {
        "components": components(),
        "projection": projection(),
        "store": healthy_store(),
        "graph": graph(),
        "duplicates": {
            "jobs_by_fingerprint": [],
            "assets_by_canonical_key": [],
            "outbox_events": [],
            "ingestion_receipts": [],
        },
        "failures_by_code": {},
        "quarantined": 0,
        "previous": None,
    }
    arguments.update(overrides)
    result: dict[str, Any] = module._health(**arguments)
    return result


def test_a_healthy_report_passes() -> None:
    module = soak_module()
    result = health(module)
    assert result == {"status": "pass", "problems": []}


def test_a_dead_component_fails_the_report() -> None:
    """The 2026-11-24 report: m23 `alive: false` and `errors: []`, i.e. a green-looking soak."""
    module = soak_module()
    result = health(module, components=components(dead=("m23",)))
    assert result["status"] == "fail"
    assert any("component m23 is not running" in problem for problem in result["problems"])


def test_a_missing_component_fails_the_report_too() -> None:
    module = soak_module()
    missing = [item for item in components() if item.name != "m06"]
    missing.append(module.support.ComponentState("m06", None, "", "no pid file (was it started?)"))
    result = health(module, components=missing)
    assert result["status"] == "fail"
    assert any("component m06" in problem for problem in result["problems"])


def test_the_projection_cursor_ignores_other_consumers() -> None:
    """`max(last_seq)` over every consumer is the SSE reader's cursor, not the projector's."""
    module = soak_module()

    class FakeConnection:
        def execute(self, sql: str, params: list[Any] | None = None) -> Any:
            class Result:
                def __init__(self, rows: list[dict[str, Any]]) -> None:
                    self._rows = rows

                def fetchall(self) -> list[dict[str, Any]]:
                    return self._rows

            if "max(seq)" in sql:
                return Result([{"n": 100}])
            return Result(
                [
                    {"consumer": "m23-projector#g1", "last_seq": 90},
                    {"consumer": "m23-projector#g1#delta", "last_seq": 100},
                    {"consumer": "m26-sse#g1", "last_seq": 100},
                ]
            )

    result = module._projection(FakeConnection())
    assert result["projector_cursor"] == 90
    assert result["projector_lag"] == 10
    assert result["projector_generation"] == "m23-projector#g1"


def test_a_frozen_projector_cursor_fails_while_the_outbox_grows() -> None:
    """m23 died at 09:45 and the old report still said `projector_cursor == outbox_head`."""
    module = soak_module()
    result = health(
        module,
        projection=projection(head=200, cursor=100),
        previous={"lag": {"outbox_head": 150, "projector_cursor": 100}},
    )
    assert result["status"] == "fail"
    assert any("did not advance between two reports" in problem for problem in result["problems"])


def test_a_projector_behind_its_limit_fails() -> None:
    module = soak_module()
    result = health(module, projection=projection(head=5000, cursor=100))
    assert result["status"] == "fail"
    assert any("events behind" in problem for problem in result["problems"])


def test_no_projector_cursor_at_all_fails() -> None:
    module = soak_module()
    result = health(module, projection=projection(generation=None, cursor=None))
    assert result["status"] == "fail"
    assert any("never checkpointed" in problem for problem in result["problems"])


def test_a_store_that_rejects_a_write_names_the_full_disk() -> None:
    """The 34 EVIDENCE_INCOMPLETE jobs: SeaweedFS unwritable below 1% free, HTTP 500 to S3."""
    module = soak_module()
    store = {
        "ok": False,
        "error": "EvidenceStoreError: S3_PUT_FAILED: HTTP 500: b'<Error><Code>InternalError</Code>",
        "path": "/home/x/.local/share/containers/storage",
        "free_percent": 0.52,
        "min_free_percent": 1.0,
    }
    result = health(module, store=store)
    assert result["status"] == "fail"
    problem = next(item for item in result["problems"] if "evidence store" in item)
    assert "S3_PUT_FAILED" in problem
    assert "0.52% free" in problem
    assert "SeaweedFS" in problem


def test_jobs_graph_duplicates_and_quarantine_all_fail() -> None:
    module = soak_module()
    result = health(
        module,
        graph=graph(asset_mismatch=2),
        duplicates={
            "jobs_by_fingerprint": [{"job_fingerprint": "x", "n": 2}],
            "assets_by_canonical_key": [],
            "outbox_events": [],
            "ingestion_receipts": [],
        },
        failures_by_code={"EVIDENCE_INCOMPLETE": 34},
        quarantined=1,
    )
    assert result["status"] == "fail"
    text = "\n".join(result["problems"])
    assert "EVIDENCE_INCOMPLETE x34" in text
    assert "graph differs from PostgreSQL" in text
    assert "duplicates jobs_by_fingerprint" in text
    assert "quarantined 1" in text
