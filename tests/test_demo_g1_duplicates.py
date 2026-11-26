"""`make demo-g1` §10: record types of one DNS answer are distinct observations, not duplicates.

The dnsx adapter asks for A, AAAA and CNAME (`adapters/m08/dnsx/manifest.yaml` since 1.0.2), so one
response carries several `dns.record` observations for the same subject at the same `observed_at`.
They are different facts (`value_hash` differs) and the no-duplicate check must not report them.
A truly repeated fact - same subject, predicate, value and instant, from two envelopes - still is a
duplicate, so the check keeps its teeth.
"""

from __future__ import annotations

import importlib.util
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.m23_support import CAMPAIGN_ID, connect, ingest, pipeline_database, requires_pipeline
from tests.support_ingestion import observation

pytestmark = requires_pipeline

DEMO = Path(__file__).resolve().parents[1] / "scripts" / "demo" / "demo-g1.py"
SUBJECT = "dns:api.internal.test"


def demo_module() -> Any:
    """Load `scripts/demo/demo-g1.py` (its file name is not importable as a module name)."""
    spec = importlib.util.spec_from_file_location("demo_g1_under_test", DEMO)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def database() -> Iterator[tuple[str, list[str]]]:
    with pipeline_database(jobs=2) as value:
        yield value


def seed(dsn: str, job_id: str, observations: list[dict[str, Any]]) -> None:
    ingest(
        dsn,
        job_id,
        assets=[{"kind": "domain", "canonical_key": SUBJECT}],
        observations=observations,
    )


def record(value: dict[str, str]) -> dict[str, Any]:
    return observation(SUBJECT, "dns.record", value, evidence_refs=[{"local_ref": "raw"}])


def test_the_record_types_of_one_answer_are_not_duplicates(database: tuple[str, list[str]]) -> None:
    dsn, jobs = database
    seed(
        dsn,
        jobs[0],
        [
            record({"type": "A", "value": "192.0.2.10"}),
            record({"type": "AAAA", "value": "2001:db8::10"}),
            record({"type": "CNAME", "value": "www.internal.test"}),
        ],
    )

    with connect(dsn) as connection:
        duplicates = demo_module()._duplicates(connection, CAMPAIGN_ID)

    assert duplicates["observations"] == []


def test_a_repeated_fact_at_one_instant_is_still_a_duplicate(
    database: tuple[str, list[str]],
) -> None:
    dsn, jobs = database
    same = record({"type": "A", "value": "192.0.2.10"})
    for job_id in jobs:
        seed(dsn, job_id, [same])

    with connect(dsn) as connection:
        groups = demo_module()._duplicates(connection, CAMPAIGN_ID)["observations"]

    assert len(groups) == 1
    assert groups[0]["n"] == 2
