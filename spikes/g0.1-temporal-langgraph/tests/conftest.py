"""Shared fixtures: throwaway Postgres (contract migrations), Temporal dev server, worker process."""

from __future__ import annotations

import asyncio
import os
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import AsyncIterator, Callable

import psycopg
import pytest
from temporalio.client import Client

from aegis_spike import config
from aegis_spike.spike_types import CampaignInput
from aegis_spike.workflows import CampaignWorkflow

ROOT = Path(__file__).resolve().parents[1]


def _kill_with_parent() -> None:
    """PR_SET_PDEATHSIG: the worker dies if the test process is killed (e.g. timeout)."""
    import ctypes

    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.prctl(1, signal.SIGKILL)


class WorkerProc:
    """The spike worker as a real process, so a test can SIGKILL it mid-activity."""

    def __init__(self) -> None:
        self.proc: subprocess.Popen[str] | None = None
        self.lines: list[str] = []
        self._ready = threading.Event()

    def start(self) -> "WorkerProc":
        env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "aegis_spike.worker"],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
            preexec_fn=_kill_with_parent,
        )
        threading.Thread(target=self._read, daemon=True).start()
        if not self._ready.wait(60):
            self.kill()
            raise RuntimeError(f"worker did not become ready:\n{self.output}")
        return self

    def _read(self) -> None:
        assert self.proc is not None and self.proc.stdout is not None
        for line in self.proc.stdout:
            self.lines.append(line.rstrip())
            if line.startswith("WORKER_READY"):
                self._ready.set()

    def kill(self) -> None:
        """SIGKILL the whole process group: no graceful shutdown, like a dead host."""
        if self.proc is not None and self.proc.poll() is None:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
            self.proc.wait(timeout=30)

    @property
    def output(self) -> str:
        return "\n".join(self.lines[-40:])


@pytest.fixture
async def db() -> AsyncIterator[psycopg.AsyncConnection]:
    try:
        conn = await psycopg.AsyncConnection.connect(config.DSN, autocommit=True)
    except psycopg.OperationalError as exc:  # pragma: no cover - env problem
        pytest.skip(f"spike Postgres not reachable ({exc}); run scripts/dev-up.sh")
    try:
        yield conn
    finally:
        await conn.close()


@pytest.fixture
async def temporal() -> AsyncIterator[Client]:
    try:
        client = await Client.connect(config.TEMPORAL_ADDRESS, namespace=config.TEMPORAL_NAMESPACE)
    except Exception as exc:  # pragma: no cover - env problem
        pytest.skip(f"Temporal dev server not reachable ({exc}); run scripts/temporal-server.sh start")
    yield client


@pytest.fixture
def worker_factory() -> AsyncIterator[Callable[[], WorkerProc]]:
    procs: list[WorkerProc] = []

    def make() -> WorkerProc:
        proc = WorkerProc().start()
        procs.append(proc)
        return proc

    yield make
    for proc in procs:
        proc.kill()


@pytest.fixture
def campaign_id() -> str:
    return f"g01-{uuid.uuid4()}"


async def start_campaign(client: Client, campaign_id: str, **kwargs: object) -> tuple[object, CampaignInput]:
    inp = CampaignInput(campaign_id=campaign_id, **kwargs)
    handle = await client.start_workflow(
        CampaignWorkflow.run,
        inp,
        id=f"campaign-{campaign_id}",
        task_queue=config.ORCHESTRATOR_QUEUE,
    )
    return handle, inp


async def wait_until(check: Callable[[], object], *, timeout: float = 30.0, interval: float = 0.2, what: str = "") -> None:
    deadline = time.monotonic() + timeout
    last: object = None
    while time.monotonic() < deadline:
        last = check()
        if asyncio.iscoroutine(last):
            last = await last
        if last:
            return
        await asyncio.sleep(interval)
    raise AssertionError(f"timed out after {timeout}s waiting for {what or 'condition'}; last={last!r}")
