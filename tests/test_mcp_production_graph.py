"""Production MCP context graph regression tests against PostgreSQL 16 and Neo4j 5.26.

Verifies the production MCP entrypoint (`aegis.m05_registry.mcp.main:create_production_app`) wires
`M23GraphQueries` and a Neo4j driver from env, closes the driver on shutdown, serves live
`graph.*` calls over Streamable HTTP, and runs an M03 agent session without recording a
`DEPENDENCY_MISSING` blocker for the `context graph`.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from typing import Any

import pytest
import uvicorn

from aegis.m03_agent.config import SessionConfig
from aegis.m03_agent.mcp import CallMeta, McpToolClient
from aegis.m03_agent.session import build_deps, run_session
from aegis.m04_model.fake import FakeModelClient
from tests import graph_support
from tests.m03_support import decision_response, run, session_request
from tests.m23_support import (
    CAMPAIGN_ID,
    connect,
    graph_driver,
    ingest,
    pipeline_database,
    project_all,
    requires_pipeline,
)
from tests.support_ingestion import observation

pytestmark = requires_pipeline


@pytest.fixture
def pipeline() -> Iterator[tuple[str, list[str]]]:
    with pipeline_database(jobs=1) as value:
        yield value


@asynccontextmanager
async def _serve_asgi(app: Any) -> AsyncIterator[str]:
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=0,
        log_level="warning",
        lifespan="on",
    )
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    try:
        for _ in range(1000):
            if server.started:
                break
            if task.done():
                await task
                raise RuntimeError("uvicorn exited before startup")
            await asyncio.sleep(0.01)
        else:  # pragma: no cover - startup guard
            raise RuntimeError("uvicorn did not start")
        port = server.servers[0].sockets[0].getsockname()[1]
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        server.should_exit = True
        await task


def test_agent_session_on_production_mcp_with_neo4j_records_no_context_graph_blocker(
    monkeypatch: pytest.MonkeyPatch,
    pipeline: tuple[str, list[str]],
) -> None:
    import importlib
    import sys

    dsn, jobs = pipeline
    with graph_driver() as driver:
        ingest(
            dsn,
            jobs[0],
            assets=[{"kind": "domain", "canonical_key": "dns:api.internal.test"}],
            observations=[
                observation(
                    "dns:api.internal.test",
                    "dns.record",
                    {"type": "A", "address": "192.0.2.10"},
                    evidence_refs=[{"local_ref": "raw"}],
                )
            ],
        )
        project_all(dsn, driver, consumer="m23-projector#g1")
        with connect(dsn) as conn, conn.transaction():
            conn.execute(
                "UPDATE campaign SET status = 'RUNNING', started_at = now() WHERE campaign_id = %s",
                (CAMPAIGN_ID,),
            )
        uri, password = graph_support.ensure_test_graph()

        monkeypatch.setenv("AEGIS_PG_DSN", dsn)
        monkeypatch.setenv("AEGIS_ALLOW_DEV_SIGNING_KEY", "1")
        monkeypatch.setenv("AEGIS_NEO4J_URI", uri)
        monkeypatch.setenv("AEGIS_NEO4J_USER", "neo4j")
        monkeypatch.setenv("AEGIS_NEO4J_PASSWORD", password)
        monkeypatch.delenv("AEGIS_S3_ENDPOINT", raising=False)
        monkeypatch.delenv("AEGIS_S3_BUCKET", raising=False)

        sys.modules.pop("aegis.m05_registry.mcp.main", None)
        mcp_main = importlib.import_module("aegis.m05_registry.mcp.main")
        try:
            app = mcp_main.app
            assert app.state.graph_driver is not None
            closed_calls: list[bool] = []
            original_close = app.state.graph_driver.close

            def tracked_close() -> None:
                closed_calls.append(True)
                original_close()

            monkeypatch.setattr(app.state.graph_driver, "close", tracked_close)

            observed_bundles: list[Any] = []

            class ObservingModel(FakeModelClient):
                def observe_context(self, bundle: Any) -> None:
                    observed_bundles.append(bundle)

            model = ObservingModel(
                responses=[decision_response("wait", "context graph observations loaded via m23")]
            )

            async def _exercise() -> tuple[Any, Any]:
                async with _serve_asgi(app) as url:

                    @asynccontextmanager
                    async def _client_factory() -> AsyncIterator[McpToolClient]:
                        client = McpToolClient(url)
                        await client.connect()
                        try:
                            yield client
                        finally:
                            await client.aclose()

                    deps = build_deps(
                        config=SessionConfig(
                            model="scripted-test", max_steps=4, in_session_idle_rounds=2
                        ),
                        dsn=dsn,
                        tools=_client_factory,
                        model=model,
                    )
                    outcome = await run_session(session_request(campaign_id=CAMPAIGN_ID), deps)

                    # Also exercise the Neo4j-backed query through the same production MCP server.
                    with connect(dsn) as conn, conn.transaction():
                        conn.execute(
                            "INSERT INTO agent_session "
                            "(session_id, campaign_id, policy_version, revision_from, status) "
                            "VALUES (%s, %s, 'roe-1', 0, 'RUNNING')",
                            ("01934f6a-0000-7000-8000-0000000000f9", CAMPAIGN_ID),
                        )
                    async with _client_factory() as client:
                        neighbors = await client.query_graph(
                            "get_asset_neighbors",
                            {
                                "campaign_id": CAMPAIGN_ID,
                                "canonical_key": "dns:api.internal.test",
                                "limit": 20,
                            },
                            meta=CallMeta(
                                trace_id="0123456789abcdef0123456789abcdef",
                                campaign_id=CAMPAIGN_ID,
                                session_id="01934f6a-0000-7000-8000-0000000000f9",
                                idempotency_key="01934f6a-0000-7000-8000-0000000000f9:neighbors:1",
                            ),
                        )
                    return outcome, neighbors

            session_run, neighbors_outcome = run(_exercise())

            assert closed_calls == [True]
            assert app.state.graph_driver._closed is True
            assert session_run.outcome.idle is True

            assert neighbors_outcome.ok, neighbors_outcome.detail
            assert neighbors_outcome.response is not None
            assert any(
                node["canonical_key"] == "dns:api.internal.test"
                for node in neighbors_outcome.response["nodes"]
            )

            assert len(observed_bundles) == 1
            bundle = observed_bundles[0]
            assert bundle.ledger is not None
            assert bundle.ledger.blockers == []
            assert any(obs.ref == "dns:api.internal.test" for obs in bundle.observations)

            with connect(dsn) as conn:
                rows = conn.execute(
                    "SELECT kind, payload FROM campaign_ledger WHERE campaign_id = %s ORDER BY seq",
                    (CAMPAIGN_ID,),
                ).fetchall()
            blockers = [
                row
                for row in rows
                if row["kind"] == "blocker" and row["payload"].get("context") == "context graph"
            ]
            assert blockers == []
            cursors = [row["payload"] for row in rows if row["kind"] == "cursor"]
            assert cursors and cursors[-1]["graph_source"] == "m23"
            assert cursors[-1]["graph_revision"] >= 1

            # Partial Neo4j config must fail loudly at startup.
            monkeypatch.delenv("AEGIS_NEO4J_PASSWORD")
            with pytest.raises(RuntimeError, match="AEGIS_NEO4J_PASSWORD"):
                mcp_main.create_production_app()
        finally:
            sys.modules.pop("aegis.m05_registry.mcp.main", None)
