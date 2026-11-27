"""The production M05 builders wire the system target binder (item 61, internet-active-1).

M05 signs a target-bound internet job only after its guards resolve the target name: the wildcard
probe of the zone behind the address and the DNS provenance check run through a `TargetBinder`. Both
production factories used to build `PostgresJobService` without one, so the `_MissingBinder`
fallback refused **every** target-bound internet job with "target-bound provider needs a server-side
resolver". naabu, fingerprintx and httpx all declare `targetBinding: required`, so no internet
campaign could ever leave the passive step.

Nothing caught it: every other M05 test injects its own binder, so CI never built the production
factories. These tests build them (`aegis.m26_api.jobs.build_job_service` and
`aegis.m05_registry.mcp.main.build_service`) with **no binder argument**, substituting only the
resolver class the factory defaults to, and require a target-bound internet job to be signed. The
stub never reaches the network, so the suite's system-resolver guard stays untouched.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from typing import Any

import psycopg
import pytest
from psycopg.rows import dict_row

from aegis.contracts_gen.capability.job_submit_v2_schema import JobSubmit
from aegis.m01_campaign.campaigns import create_campaign
from aegis.m01_campaign.status import apply_workflow_action
from aegis.m05_registry.mcp.graph import UnavailableGraphQueries
from aegis.m26_api import jobs as jobs_module
from aegis.m27_ingestion.service import IngestionService
from tests.db_support import (
    OPERATOR,
    connect,
    migrated_database,
    policy_document,
    requires_postgres,
)
from tests.m06_support import INTERNET_RING
from tests.support_ingestion import build_envelope, observation

pytestmark = requires_postgres

DOMAIN = "api.icomm.vn"
TARGET_IP = "203.0.113.10"
TARGET_KEY = f"ip:{TARGET_IP}"


class StubBinder:
    """A deterministic resolver: no DNS, and it records what M05 asked it to resolve."""

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        self.calls: list[str] = []

    def addresses(self, value: str) -> tuple[str, ...]:
        self.calls.append(value)
        return (TARGET_IP,) if value == DOMAIN else ()


def _internet_policy() -> dict[str, Any]:
    return policy_document(
        network_profile="internet",
        authorization={
            "owner": "owner",
            "reference": "owner item 61 2026-11-27",
            "date": "2026-11-27",
            "authorized_suffixes": ["icomm.vn"],
        },
        rate_limits={
            "requests_per_second_per_host": 1.0,
            "max_concurrent_connections_per_host": 1,
            "jobs_per_minute": 100,
        },
    )


def _record_provenance(dsn: str, *, campaign_id: str, scope_id: str, policy_version: str) -> None:
    """Submit a `dns.resolve` job and ingest its envelope, as production records DNS.

    That task is signed without a binder (`targetBinding: none`), so this step does not depend on
    the wiring under test; the M27 envelope is what gives the ip asset its authorized provenance,
    the path that later consults the binder.
    """
    resolved = jobs_module.build_job_service(dsn, key_ring=INTERNET_RING).submit(
        JobSubmit.model_validate(
            {
                "campaign_id": campaign_id,
                "capability": "dns.resolve",
                "input": {"targets": [DOMAIN]},
                "rationale": "record the DNS provenance of the address under test",
            }
        ),
        requested_by=OPERATOR,
        idempotency_key="resolve-provenance",
    )
    job_id = str(resolved.job["job_id"])
    with psycopg.connect(dsn) as conn:
        row = conn.execute(
            "SELECT target_refs FROM scan_job WHERE job_id = %s", (job_id,)
        ).fetchone()
    assert row is not None
    target_refs = row[0]
    raw = b'{"A": "203.0.113.10"}\n'
    sha = hashlib.sha256(raw).hexdigest()
    uri = f"s3://evidence/{campaign_id}/{job_id}/{sha}"
    with psycopg.connect(dsn) as conn, conn.transaction():
        conn.execute(
            "INSERT INTO evidence (evidence_id, sha256, storage_uri, campaign_id, job_id,"
            " size_bytes, media_type, kind, classification, source_tool)"
            " VALUES (gen_random_uuid(), %s, %s, %s, %s, %s, 'application/json',"
            " 'raw_output', 'INTERNAL', 'dnsx')",
            (sha, uri, campaign_id, job_id, len(raw)),
        )
    envelope = build_envelope(
        job_id,
        campaign_id=campaign_id,
        scope_id=scope_id,
        policy_version=policy_version,
        seed_targets=target_refs,
        assets=[
            {"kind": "domain", "canonical_key": f"dns:{DOMAIN}"},
            {"kind": "ip", "canonical_key": TARGET_KEY},
        ],
        observations=[
            observation(f"dns:{DOMAIN}", "dns.record", {"type": "A", "value": TARGET_IP})
        ],
        evidence=[
            {
                "local_ref": "raw",
                "sha256": sha,
                "uri": uri,
                "size_bytes": len(raw),
                "media_type": "application/json",
                "classification": "INTERNAL",
                "kind": "raw_output",
            }
        ],
    )
    # `build_envelope`'s capability/provider constants are Subfinder's; the job pins dns.resolve.
    envelope["capability"] = "dns.resolve"
    envelope["provider"]["name"] = "dnsx"
    envelope["provider"]["version"] = "v1.2.2"
    receipt = IngestionService.from_dsn(dsn).submit_payload(envelope)
    assert receipt.accepted and not receipt.quarantined, receipt


@pytest.fixture
def internet_campaign() -> Iterator[tuple[str, str]]:
    """A running internet campaign whose ip asset has authorized DNS provenance in the DB.

    The address is deliberately **not** a seed: a seed IP/CIDR is active-eligible without any
    lookup, while an address learned from DNS is the path that consults the binder — the one the
    first active run hit.
    """
    with migrated_database() as dsn:
        with psycopg.connect(dsn, row_factory=dict_row) as dict_conn, dict_conn.transaction():
            created = create_campaign(
                dict_conn,
                body={
                    "name": "internet production binder",
                    "objective": "sign a target-bound internet job",
                    "targets": {"domains": [DOMAIN]},
                    "policy": _internet_policy(),
                },
                actor=OPERATOR,
                trace_id="b" * 32,
            )
            apply_workflow_action(
                dict_conn,
                campaign_id=created.campaign_id,
                action="start",
                reason="test",
                actor={"kind": "module", "id": "M02"},
                trace_id="b" * 32,
            )
        _record_provenance(
            dsn,
            campaign_id=created.campaign_id,
            scope_id=created.scope_id,
            policy_version=created.policy_version,
        )
        yield dsn, created.campaign_id


def _submit_and_read_task(jobs: Any, dsn: str, campaign_id: str, *, key: str) -> dict[str, Any]:
    outcome = jobs.submit(
        JobSubmit.model_validate(
            {
                "campaign_id": campaign_id,
                "capability": "network.discover_services",
                "input": {"targets": [TARGET_KEY], "ports": [443]},
                "rationale": "sign a target-bound internet job through the production builder",
            }
        ),
        requested_by=OPERATOR,
        idempotency_key=key,
    )
    job = dict(outcome.job)
    assert job["status"] == "QUEUED"
    with connect(dsn) as conn:
        row = conn.execute(
            "SELECT approved_task FROM scan_job WHERE job_id = %s", (job["job_id"],)
        ).fetchone()
    assert row is not None and row[0] is not None
    return dict(row[0])


def _check_binding(task: dict[str, Any]) -> None:
    binding = dict(task["egress_binding"])
    assert binding["mode"] == "broker"
    assert binding["target_binding"] == "required"
    assert binding["entries"] == [f"{TARGET_IP}:443"]
    assert binding["target_addresses"] == [TARGET_IP]


def test_the_api_factory_signs_a_target_bound_internet_job(
    monkeypatch: pytest.MonkeyPatch,
    internet_campaign: tuple[str, str],
) -> None:
    dsn, campaign_id = internet_campaign
    monkeypatch.setattr(jobs_module, "SystemTargetBinder", StubBinder)
    # The production builder is called exactly as the API calls it: no binder argument.
    built = jobs_module.build_job_service(dsn, key_ring=INTERNET_RING)
    assert isinstance(built._binder, StubBinder), (
        "the production API factory built M05 without a target binder; an internet target-bound "
        "job would be refused with 'target-bound provider needs a server-side resolver'"
    )
    task = _submit_and_read_task(built, dsn, campaign_id, key="api-factory-naabu")
    _check_binding(task)
    assert INTERNET_RING.verify(task) == "g16-test-1"
    # The guard consulted the binder for the provenance zone, not a constant.
    assert any(
        call.startswith("aegis-wildcard-") and call.endswith(".icomm.vn")
        for call in built._binder.calls
    ), built._binder.calls


def test_the_mcp_factory_signs_a_target_bound_internet_job(
    monkeypatch: pytest.MonkeyPatch,
    internet_campaign: tuple[str, str],
) -> None:
    import importlib
    import sys

    dsn, campaign_id = internet_campaign
    monkeypatch.setenv(
        "AEGIS_TASK_SIGNING_KEYS",
        "g16-test-1:" + INTERNET_RING.keys["g16-test-1"].hex(),
    )
    monkeypatch.setenv("AEGIS_TASK_SIGNING_ACTIVE_KEY", "g16-test-1")
    # The module builds its ASGI app at import time from the environment (the production entrypoint
    # is the module itself), so the environment must name this test database and a syntactically
    # valid Neo4j; the driver is never dialled here.
    monkeypatch.setenv("AEGIS_PG_DSN", dsn)
    monkeypatch.setenv("AEGIS_NEO4J_URI", "bolt://127.0.0.1:7687")
    monkeypatch.setenv("AEGIS_NEO4J_PASSWORD", "test-password")
    monkeypatch.delenv("AEGIS_S3_ENDPOINT", raising=False)
    monkeypatch.delenv("AEGIS_S3_BUCKET", raising=False)
    sys.modules.pop("aegis.m05_registry.mcp.main", None)
    mcp_main = importlib.import_module("aegis.m05_registry.mcp.main")
    try:
        monkeypatch.setattr(mcp_main, "SystemTargetBinder", StubBinder)
        # The production MCP builder is called as `create_production_app` calls it: no binder.
        service = mcp_main.build_service(dsn, graph=UnavailableGraphQueries())
        binder = getattr(service.jobs, "_binder", None)
        assert isinstance(binder, StubBinder), (
            "the production MCP factory built M05 without a target binder; the agent's "
            "target-bound internet proposals would all be refused"
        )
        task = _submit_and_read_task(service.jobs, dsn, campaign_id, key="mcp-factory-naabu")
        _check_binding(task)
        assert INTERNET_RING.verify(task) == "g16-test-1"
    finally:
        # The module's app opened a driver at import; close it before dropping the module.
        app = getattr(mcp_main, "app", None)
        if app is not None and getattr(app.state, "graph_driver", None) is not None:
            app.state.graph_driver.close()
        sys.modules.pop("aegis.m05_registry.mcp.main", None)
