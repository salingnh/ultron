"""The output-cap monitor of `PodmanRunner.wait`, on a controlled clock.

How far a tool overshoots its cap on a real host is its write rate times the latency of
`podman kill`, which a loaded runner does not bound. What the runner controls is the order and the
spacing of its own steps, so those are checked here without containers or wall-clock time; the
real-container test (`tests/test_podman_isolation.py`) checks that the monitor stops the job.
"""

from __future__ import annotations

from itertools import pairwise
from pathlib import Path

import pytest

from aegis.common.ports import RunHandle, RunState
from aegis.m06_runner import podman as podman_module
from aegis.m06_runner.podman import PodmanRunner

CAP = 1000
#: The tool writes this many bytes per second of the controlled clock.
BYTES_PER_SECOND = 1000.0
#: The cap is crossed just after this moment.
CROSSED_AT = CAP / BYTES_PER_SECOND
SIZE_POLL = 0.05


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def test_the_monitor_kills_within_one_size_poll_of_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = Clock()
    events: list[tuple[str, float]] = []
    runner = PodmanRunner(base_dir=tmp_path, poll_seconds=0.2)
    runner.layout("job-1").create()

    def inspect(handle: RunHandle) -> RunState:
        killed = any(name == "kill" for name, _ in events)
        events.append(("inspect", clock.now))
        return RunState(status="exited", exit_code=137) if killed else RunState(status="running")

    def output_bytes(job_id: str, *, limit: int | None = None) -> int:
        written = int(clock.now * BYTES_PER_SECOND)
        events.append(("over" if written > CAP else "under", clock.now))
        return written

    def stop(handle: RunHandle, grace_seconds: int = 10, *, force: bool = False) -> None:
        assert force, "the cap kills at once: a grace period is more unbounded writing"
        events.append(("kill", clock.now))

    monkeypatch.setattr(podman_module, "time", clock)
    monkeypatch.setattr(runner, "inspect", inspect)
    monkeypatch.setattr(runner, "output_bytes", output_bytes)
    monkeypatch.setattr(runner, "stop", stop)

    wait = runner.wait(RunHandle(job_id="job-1", container_id="c"), 60, max_output_bytes=CAP)

    assert wait.capped is True and wait.timed_out is False
    names = [name for name, _ in events]
    first_over = names.index("over")
    # Nothing slow happens between seeing the cap crossed and the kill, and nothing else kills.
    assert names[first_over:] == ["over", "kill", "inspect"]
    assert events[first_over][1] - CROSSED_AT <= SIZE_POLL + 1e-9
    # The size is watched between the state polls, not only once per state poll.
    sizes = [at for name, at in events if name in {"under", "over"}]
    assert max(later - earlier for earlier, later in pairwise(sizes)) <= SIZE_POLL + 1e-9
