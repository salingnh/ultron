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


def test_start_container_mounts_tmpfs_and_stop_removes_volumes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Throwaway Neo4j never creates anonymous volumes and tears down with `rm -f -v`."""
    import atexit
    import subprocess

    calls: list[tuple[str, ...]] = []
    registered: list[object] = []

    def fake_podman(*args: str) -> str:
        calls.append(args)
        if args[0] == "run":
            return "cid-123"
        if args[0] == "port":
            return "127.0.0.1:47687"
        return ""

    def fake_register(fn: object) -> object:
        registered.append(fn)
        return fn

    monkeypatch.setattr(graph_support, "_podman", fake_podman)
    monkeypatch.setattr(graph_support, "_pinned_image", lambda: "neo4j:test")
    monkeypatch.setattr(atexit, "register", fake_register)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(args=[], returncode=0, stdout="1\n"),
    )
    monkeypatch.setattr(graph_support, "_STARTED", [])

    uri, _password = graph_support._start_container()
    assert uri == "bolt://127.0.0.1:47687"
    run_args = calls[0]
    tmpfs_targets = [run_args[i + 1] for i, arg in enumerate(run_args) if arg == "--tmpfs"]
    assert any(target.startswith("/data:") for target in tmpfs_targets), tmpfs_targets
    assert any(target.startswith("/logs:") for target in tmpfs_targets), tmpfs_targets
    assert registered == [graph_support.stop_test_graph]

    graph_support.stop_test_graph()
    assert any(call[:3] == ("rm", "-f", "-v") for call in calls), calls
    assert graph_support._STARTED == []


def test_start_container_cleans_up_on_interrupt(monkeypatch: pytest.MonkeyPatch) -> None:
    """An interrupt while waiting for Neo4j readiness still removes the container and volumes."""
    import atexit
    import subprocess

    calls: list[tuple[str, ...]] = []

    def fake_podman(*args: str) -> str:
        calls.append(args)
        if args[0] == "run":
            return "cid-456"
        if args[0] == "port":
            return "127.0.0.1:47688"
        return ""

    def raise_interrupt(*_args: object, **_kwargs: object) -> object:
        raise KeyboardInterrupt

    monkeypatch.setattr(graph_support, "_podman", fake_podman)
    monkeypatch.setattr(graph_support, "_pinned_image", lambda: "neo4j:test")
    monkeypatch.setattr(atexit, "register", lambda fn: fn)
    monkeypatch.setattr(subprocess, "run", raise_interrupt)
    monkeypatch.setattr(graph_support, "_STARTED", [])

    with pytest.raises(KeyboardInterrupt):
        graph_support._start_container()

    assert any(call[:3] == ("rm", "-f", "-v") for call in calls), calls
    assert graph_support._STARTED == []
