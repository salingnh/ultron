"""Fake M06 ContainerRunner: an in-memory state machine, no podman and no real containers."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from aegis.common.ports import ContainerRunner, ContainerSpec, RunHandle, RunState


@dataclass
class _Run:
    handle: RunHandle
    output: Path
    status: Literal["created", "running", "exited"] = "running"
    exit_code: int | None = None


@dataclass
class FakeContainerRunner(ContainerRunner):
    """Keeps run state per job id under `base_dir`, so tests can inspect output paths.

    `run` is idempotent by `spec.job_id` (the contract names the container after the job), `stop`
    moves the run to `exited`, and `remove` makes it `missing` while keeping its output directory -
    exactly what M06 must do after uploading evidence.
    """

    base_dir: Path
    _runs: dict[str, _Run] = field(default_factory=dict, init=False)
    _specs: dict[str, ContainerSpec] = field(default_factory=dict, init=False)

    def run(self, spec: ContainerSpec) -> RunHandle:
        existing = self._runs.get(spec.job_id)
        if existing is not None:
            return existing.handle
        output = self.base_dir / spec.job_id
        output.mkdir(parents=True, exist_ok=True)
        handle = RunHandle(job_id=spec.job_id, container_id=f"fake-container-{spec.job_id}")
        self._runs[spec.job_id] = _Run(handle=handle, output=output)
        self._specs[spec.job_id] = spec
        return handle

    def inspect(self, handle: RunHandle) -> RunState:
        run = self._runs.get(handle.job_id)
        if run is None:
            return RunState(status="missing")
        return RunState(status=run.status, exit_code=run.exit_code)

    def stop(self, handle: RunHandle, grace_seconds: int = 10) -> None:
        run = self._runs.get(handle.job_id)
        if run is None or run.status == "exited":
            return
        run.status = "exited"
        run.exit_code = 0

    def output_dir(self, handle: RunHandle) -> Path:
        run = self._runs.get(handle.job_id)
        if run is None:
            raise RuntimeError(f"unknown run {handle.job_id}")
        return run.output

    def remove(self, handle: RunHandle) -> None:
        self._runs.pop(handle.job_id, None)

    def spec(self, job_id: str) -> ContainerSpec:
        """Test helper: the spec a job was started with (not part of the interface)."""
        return self._specs[job_id]

    def finish(self, handle: RunHandle, exit_code: int) -> None:
        """Test helper: simulate the container exiting with `exit_code`."""
        run = self._runs.get(handle.job_id)
        if run is None:
            raise RuntimeError(f"unknown run {handle.job_id}")
        run.status = "exited"
        run.exit_code = exit_code
