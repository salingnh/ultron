"""The destructive-test guards: a graph (or a database) only the harness may wipe.

The incident: a gate run pointed `AEGIS_TEST_NEO4J_URI` at the dev stack's Neo4j and the M23
projector tests wiped the shared graph (`graph.wipe`). Two guards now stand in the way, and these
tests prove both refuse instead of trusting the environment:

* a destructive test may only touch a Neo4j container this harness owns (`aegis.test.graph=1`), and
  an env URI pointing anywhere else fails before any connection is opened - including the exact
  dev-stack case, reproduced here without a running dev stack;
* `graph.wipe` needs an explicit rebuild context, so a plain run cannot reach it;
* dropping a database is refused outside the harness's throwaway namespace.
"""

from __future__ import annotations

import inspect
from typing import Any

import pytest

from aegis.m23_graph import cli, graph
from aegis.m23_graph.projector import Projector
from tests import graph_support
from tests import pg as pg_support
from tests.graph_support import SharedGraphRefused, ensure_test_graph

DEV_URI = "bolt://127.0.0.1:17687"
DEV_CONTAINER = "aegis-dev-neo4j"


def test_the_dev_stack_neighbourhood_is_refused_before_any_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The incident, reproduced: the env points at the dev container and the guard says no.

    `podman` is not consulted for a real container here: the lookups are replaced with the dev
    stack's answer (`aegis-dev-neo4j` publishing 17687, labelled with its compose project), which is
    exactly what the host had when the graph was wiped.
    """
    monkeypatch.setattr(graph_support, "_containers_publishing", lambda port: [DEV_CONTAINER])
    monkeypatch.setattr(
        graph_support,
        "_labels",
        lambda name: ["io.podman.compose.project=aegis-dev", "io.podman.compose.service=neo4j"],
    )
    with pytest.raises(SharedGraphRefused) as refused:
        ensure_test_graph(
            {
                graph_support.NEO4J_URI_ENV: DEV_URI,
                graph_support.NEO4J_PASSWORD_ENV: "dev-password",
            }
        )
    message = str(refused.value)
    assert DEV_CONTAINER in message and "shared" in message
    assert "aegis.test.graph=1" in message


def test_an_unowned_container_is_refused_too(monkeypatch: pytest.MonkeyPatch) -> None:
    """A hand-started Neo4j is not a test resource either: only the label makes one disposable."""
    monkeypatch.setattr(graph_support, "_containers_publishing", lambda port: ["my-own-neo4j"])
    monkeypatch.setattr(graph_support, "_labels", lambda name: ["purpose=experiments"])
    with pytest.raises(SharedGraphRefused, match="not a test resource"):
        ensure_test_graph(
            {
                graph_support.NEO4J_URI_ENV: "bolt://127.0.0.1:37687",
                graph_support.NEO4J_PASSWORD_ENV: "secret",
            }
        )


def test_an_address_with_no_container_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nothing publishes the port, so ownership cannot be proved: refuse, never assume."""
    monkeypatch.setattr(graph_support, "_containers_publishing", lambda port: [])
    with pytest.raises(SharedGraphRefused, match="cannot be proved"):
        ensure_test_graph(
            {
                graph_support.NEO4J_URI_ENV: "bolt://127.0.0.1:9999",
                graph_support.NEO4J_PASSWORD_ENV: "secret",
            }
        )


def test_a_labelled_container_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    """The positive control: the harness's own (or CI's) labelled container is used as-is."""
    monkeypatch.setattr(
        graph_support, "_containers_publishing", lambda port: ["aegis-test-graph-ab"]
    )
    monkeypatch.setattr(graph_support, "_labels", lambda name: [graph_support.CONTAINER_LABEL])
    uri, password = ensure_test_graph(
        {
            graph_support.NEO4J_URI_ENV: "bolt://127.0.0.1:35432",
            graph_support.NEO4J_PASSWORD_ENV: "secret",
        }
    )
    assert uri == "bolt://127.0.0.1:35432"
    assert password == "secret"


def test_a_uri_without_a_password_is_refused() -> None:
    with pytest.raises(SharedGraphRefused, match="refusing to guess"):
        ensure_test_graph({graph_support.NEO4J_URI_ENV: "bolt://127.0.0.1:7687"})


class _RecordingDriver:
    def __init__(self) -> None:
        self.sessions = 0

    def session(self) -> Any:
        self.sessions += 1
        raise AssertionError("the driver must not be touched when the wipe is refused")


def test_the_wipe_needs_a_rebuild_context() -> None:
    """`graph.wipe(driver)` alone is a TypeError: the destructive step belongs to a rebuild."""
    driver = _RecordingDriver()
    with pytest.raises(TypeError):
        graph.wipe(driver)  # type: ignore[call-arg,arg-type]  # context is required
    assert driver.sessions == 0


def test_the_wipe_needs_a_non_empty_generation() -> None:
    with pytest.raises(ValueError, match="consumer generation"):
        graph.RebuildContext("  ")
    with pytest.raises(TypeError):
        # The runtime check: a plain value instead of the rebuild context is refused.
        graph.wipe(_RecordingDriver(), context="m23-projector#g2")  # type: ignore[arg-type]


def test_the_projector_and_the_plain_run_never_call_the_wipe() -> None:
    """The production paths that could reach a shared graph by accident do not wipe at all."""
    for target in (cli.run, cli.status, Projector.run, Projector.round, Projector.start):
        source = inspect.getsource(target)
        assert "wipe" not in source, f"{target.__qualname__} must not delete the graph"


class _Admin:
    def __init__(self) -> None:
        self.statements: list[str] = []

    def execute(self, statement: str, params: Any = None) -> None:
        del params
        self.statements.append(statement)


def test_dropping_a_database_outside_the_throwaway_namespace_is_refused() -> None:
    admin = _Admin()
    for name in ("aegis", "postgres", "aegis_dev", "tmp"):
        with pytest.raises(pg_support.SharedDatabaseRefused, match="throwaway"):
            pg_support.drop_throwaway_database(admin, name)
    assert admin.statements == [], "a refused drop must not have run anything"


def test_dropping_a_throwaway_database_is_allowed() -> None:
    admin = _Admin()
    pg_support.drop_throwaway_database(admin, "aegis_g15c_0123456789ab")
    assert admin.statements == ['DROP DATABASE IF EXISTS "aegis_g15c_0123456789ab" WITH (FORCE)']
