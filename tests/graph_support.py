"""A Neo4j graph that only this test harness owns, and the only one a destructive test may touch.

The incident this module exists for: a python gate run pointed `AEGIS_TEST_NEO4J_URI` at the dev
stack's Neo4j (`bolt://127.0.0.1:17687`, the graph the running soak stack was projecting into), the
M23 projector tests wiped it (`graph.wipe`), and a shared graph was emptied. "Neo4j is only a
projection, a rebuild restores it" was true in theory and wrong in practice: nobody rebuilt it
afterwards.

So a test that deletes graph data now needs a graph the harness can *prove* it owns:

* `AEGIS_TEST_NEO4J_URI` is accepted only when the container publishing that bolt port carries the
  `aegis.test.graph=1` label. The CI python gate starts its Neo4j with that label
  (`scripts/ci/python-gate.sh`); a dev-stack or manually started Neo4j never has it, so pointing the
  variable at one fails **before any connection is opened**.
* With no `AEGIS_TEST_NEO4J_URI` at all, the harness starts its own container: a unique name
  (`aegis-test-graph-<hex>`), a random loopback port and the same label, from the pinned Neo4j image
  in `deploy/dev/images.env`. It is removed when the process exits.
* The refusal is an error, not a skip: with `AEGIS_NO_SKIPS=1` a skipped check is not evidence, and
  a guard that quietly skips is a guard that is not tested (`tests/test_graph_guard.py`).

Destructive *PostgreSQL* tests follow the same rule for the one operation that can lose shared data,
dropping a database: `tests/pg.drop_throwaway_database` refuses any database name outside the
harness's throwaway namespace, so a wrong DSN cannot make a test drop a real database.
"""

from __future__ import annotations

import atexit
import json
import os
import re
import secrets
import subprocess
import time
from collections.abc import Mapping

__all__ = [
    "CONTAINER_LABEL",
    "NEO4J_PASSWORD_ENV",
    "NEO4J_URI_ENV",
    "SharedGraphRefused",
    "ensure_test_graph",
    "stop_test_graph",
]

NEO4J_URI_ENV = "AEGIS_TEST_NEO4J_URI"
NEO4J_PASSWORD_ENV = "AEGIS_TEST_NEO4J_PASSWORD"
#: The label that makes a Neo4j container disposable: the harness started it (or CI did for it).
CONTAINER_LABEL = "aegis.test.graph=1"
CONTAINER_PREFIX = "aegis-test-graph-"
#: Compose projects whose containers are a *shared* environment, never a test resource.
SHARED_PROJECT_LABELS = (
    "io.podman.compose.project=aegis-dev",
    "io.podman.compose.project=aegis-lab",
)
IMAGES_FILE = "deploy/dev/images.env"
READY_TIMEOUT_SECONDS = 180
POLL_SECONDS = 2.0
BOLT_PORT = 7687


class SharedGraphRefused(RuntimeError):
    """The configured Neo4j is not owned by this harness; a destructive test must not touch it."""


#: The graph this process started (one container per test run, shared by every test).
_STARTED_GRAPH: tuple[str, str] | None = None


def ensure_test_graph(env: Mapping[str, str] | None = None) -> tuple[str, str]:
    """The `(uri, password)` of a Neo4j this harness owns; raises when it cannot prove ownership."""
    global _STARTED_GRAPH
    source = os.environ if env is None else env
    uri = source.get(NEO4J_URI_ENV, "").strip()
    if uri:
        password = source.get(NEO4J_PASSWORD_ENV, "").strip()
        if not password:
            raise SharedGraphRefused(
                f"{NEO4J_URI_ENV} is set but {NEO4J_PASSWORD_ENV} is not: refusing to guess"
            )
        _require_harness_owned(uri)
        return uri, password
    if _STARTED_GRAPH is None:
        _STARTED_GRAPH = _start_container()
    return _STARTED_GRAPH


def _require_harness_owned(uri: str) -> None:
    """Fail unless the container publishing this bolt port carries the harness label."""
    port = _port_of(uri)
    names = _containers_publishing(port)
    if not names:
        raise SharedGraphRefused(
            f"{NEO4J_URI_ENV}={uri!r}: no container on this host publishes bolt port {port}, so "
            f"the graph at that address cannot be proved to be a test resource. A destructive "
            f"test only runs against a Neo4j the harness owns (label {CONTAINER_LABEL}); leave "
            f"{NEO4J_URI_ENV} unset to let it start one."
        )
    for name in names:
        labels = _labels(name)
        if _is_shared(labels):
            projects = ", ".join(label for label in labels if label.startswith("io.podman.compose"))
            raise SharedGraphRefused(
                f"{NEO4J_URI_ENV}={uri!r} points at the shared container {name!r} ({projects}); "
                f"a destructive test must not wipe a shared graph. Leave {NEO4J_URI_ENV} unset to "
                f"let the harness start one, or point it at a container labelled "
                f"{CONTAINER_LABEL}."
            )
        if CONTAINER_LABEL not in labels:
            raise SharedGraphRefused(
                f"{NEO4J_URI_ENV}={uri!r} points at {name!r}, which is not a test resource (no "
                f"{CONTAINER_LABEL} label). A destructive test only wipes a graph the harness owns."
            )


def _is_shared(labels: list[str]) -> bool:
    return any(label in labels for label in SHARED_PROJECT_LABELS)


def _port_of(uri: str) -> int:
    match = re.search(r":(\d+)/?$", uri.strip())
    if match is None:
        raise SharedGraphRefused(f"{NEO4J_URI_ENV}={uri!r} does not name a bolt port")
    return int(match.group(1))


def _containers_publishing(port: int) -> list[str]:
    """Container names on this host whose published ports include `port` (the host port)."""
    listed = _podman("ps", "--format", "{{.Names}}|{{.Ports}}")
    found: list[str] = []
    for line in listed.splitlines():
        name, _, ports = line.partition("|")
        if not name:
            continue
        for published in ports.split(","):
            match = re.match(r"^[\d.\[\]]*:(\d+)->", published.strip())
            if match is not None and int(match.group(1)) == port:
                found.append(name.strip())
                break
    return found


def _labels(name: str) -> list[str]:
    raw = _podman("inspect", "--format", "{{json .Config.Labels}}", name)
    try:
        labels = json.loads(raw) if raw else {}
    except json.JSONDecodeError:  # pragma: no cover - a broken container report is a refusal
        return []
    if not isinstance(labels, dict):
        return []
    return [f"{key}={value}" for key, value in labels.items()]


def _podman(*args: str) -> str:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed podman queries
            ["podman", *args], capture_output=True, text=True, check=False, timeout=120
        )
    except (OSError, subprocess.TimeoutExpired) as error:  # pragma: no cover - host without podman
        raise SharedGraphRefused(f"cannot inspect containers with podman: {error}") from error
    return completed.stdout.strip()


def _ci_job_label_args() -> list[str]:
    job = os.environ.get("AEGIS_CI_JOB", "").strip()
    return ["--label", f"aegis.ci-job={job}"] if job else []


def _record_container_volumes(name: str) -> None:
    log_path = os.environ.get("AEGIS_CI_VOLUME_LOG", "").strip()
    if not log_path:
        return
    mounts = _podman(
        "container",
        "inspect",
        name,
        "--format",
        '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}{{"\\n"}}{{end}}{{end}}',
    )
    names = [line.strip() for line in mounts.splitlines() if line.strip()]
    if names:
        with open(log_path, "a", encoding="utf-8") as handle:
            for volume in names:
                handle.write(f"{volume}\n")


def _start_container() -> tuple[str, str]:
    """Start a labelled, throwaway Neo4j from the pinned image; removed when this process exits."""
    password = secrets.token_urlsafe(18)
    name = f"{CONTAINER_PREFIX}{secrets.token_hex(6)}"
    image = _pinned_image()
    started = _podman(
        "run",
        "-d",
        "--name",
        name,
        "--label",
        CONTAINER_LABEL,
        *_ci_job_label_args(),
        "--tmpfs",
        "/data:rw,size=1g,mode=1777",
        "--tmpfs",
        "/logs:rw,size=64m,mode=1777",
        "-e",
        f"NEO4J_AUTH=neo4j/{password}",
        "-e",
        "NEO4J_server_memory_heap_initial__size=512m",
        "-e",
        "NEO4J_server_memory_heap_max__size=1g",
        "-e",
        "NEO4J_server_memory_pagecache_size=512m",
        "-p",
        f"127.0.0.1::{BOLT_PORT}",
        image,
    )
    if not started:
        raise SharedGraphRefused(
            f"podman could not start the harness Neo4j ({name}); see podman run"
        )
    _register_stop(name)
    try:
        published = _podman("port", name, f"{BOLT_PORT}/tcp")
        port = published.rsplit(":", 1)[-1].strip() if published else ""
        if not port.isdigit():
            raise SharedGraphRefused(
                f"the harness Neo4j {name} published no bolt port ({published!r})"
            )
        deadline = time.monotonic() + READY_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            ready = subprocess.run(  # noqa: S603 - fixed podman exec
                ["podman", "exec", name, "cypher-shell", "-u", "neo4j", "-p", password, "RETURN 1"],
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
            if ready.returncode == 0:
                return f"bolt://127.0.0.1:{port}", password
            time.sleep(POLL_SECONDS)
        raise SharedGraphRefused(
            f"the harness Neo4j {name} did not become ready within {READY_TIMEOUT_SECONDS}s"
        )
    except BaseException:
        _stop(name)
        if name in _STARTED:
            _STARTED.remove(name)
        raise


def _pinned_image() -> str:
    from aegis.common.repo import repository_root

    pins = (repository_root() / IMAGES_FILE).read_text(encoding="utf-8")
    for line in pins.splitlines():
        if line.startswith("AEGIS_NEO4J_IMAGE="):
            return line.partition("=")[2].strip()
    raise SharedGraphRefused(f"{IMAGES_FILE} has no AEGIS_NEO4J_IMAGE pin")


_STARTED: list[str] = []


def _register_stop(name: str) -> None:
    if not _STARTED:
        atexit.register(stop_test_graph)
    _STARTED.append(name)


def stop_test_graph() -> None:
    """Remove the containers this process started (registered with `atexit`)."""
    while _STARTED:
        _stop(_STARTED.pop())


def _stop(name: str) -> None:
    _record_container_volumes(name)
    _podman("rm", "-f", "-v", name)
