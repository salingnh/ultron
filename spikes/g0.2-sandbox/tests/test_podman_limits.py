"""Resource and privilege limits under rootless Podman (cgroup v2 delegation).

Every assertion is on observed container state: cgroup files, kernel counters,
OOM kill, exit codes. Nothing here assumes a limit "should" apply.
"""

from __future__ import annotations

import pytest

from aegis_g02.podman_runner import ContainerSpec, run_job

from .images import ALPINE

pytestmark = pytest.mark.integration


def spec(args: list[str], **kwargs) -> ContainerSpec:
    base = dict(
        job_id="limits",
        image_digest=ALPINE,
        args=args,
        cpu=1.0,
        memory_mb=128,
        timeout_seconds=60,
        max_output_bytes=1024 * 1024,
        network="none",
    )
    base.update(kwargs)
    return ContainerSpec(**base)


def test_cgroup_v2_is_the_controller():
    import subprocess

    fs = subprocess.run(
        ["stat", "-fc", "%T", "/sys/fs/cgroup"], capture_output=True, text=True
    ).stdout.strip()
    assert fs == "cgroup2fs"
    import json as _json

    host = _json.loads(
        subprocess.run(
            ["podman", "info", "--format", "{{json .Host}}"],
            capture_output=True,
            text=True,
        ).stdout
    )
    assert host["cgroupVersion"] == "v2"
    assert host["cgroupManager"] == "systemd"
    assert {"cpu", "memory", "pids"} <= set(host["cgroupControllers"])


def test_memory_limit_kills_the_container():
    run = run_job(
        spec(["sh", "-c", 'a=$(head -c 100000000 /dev/zero | tr "\\0" "a"); echo SURVIVED']),
        network=None,
    )
    assert run.state == "oom"
    assert run.oom_killed is True
    assert run.exit_code in (137, 139)
    assert "SURVIVED" not in run.stdout


def test_pids_limit_blocks_forks():
    run = run_job(
        spec(
            [
                "sh",
                "-c",
                "for i in $(seq 1 80); do (sleep 5 &) ; done; sleep 1; "
                "cat /sys/fs/cgroup/pids.max /sys/fs/cgroup/pids.events",
            ],
            pids_limit=32,
        ),
        network=None,
    )
    assert "32" in run.stdout
    assert "max " in run.stdout
    hit = int(run.stdout.split("max ")[-1].split()[0])
    assert hit > 0


def test_cpu_quota_throttles():
    run = run_job(
        spec(
            [
                "sh",
                "-c",
                "busybox timeout 3 sh -c 'while :; do :; done'; cat /sys/fs/cgroup/cpu.stat",
            ],
            cpu=0.1,
        ),
        network=None,
    )
    assert "nr_periods" in run.stdout
    stats = dict(
        line.split() for line in run.stdout.splitlines() if len(line.split()) == 2
    )
    assert int(stats["nr_throttled"]) > 0


def test_wall_clock_timeout_kills_and_still_reports():
    run = run_job(spec(["sleep", "60"], timeout_seconds=2), network=None)
    assert run.timed_out is True
    assert run.state == "timeout"
    assert run.duration_seconds < 20


def test_read_only_rootfs_and_output_quota():
    run = run_job(
        spec(
            [
                "sh",
                "-c",
                "(touch /etc/escape && echo WRITE-OK) || echo READONLY-OK; "
                "head -c 2000000 /dev/zero > /out/big 2>/dev/null; echo rc=$?",
            ],
        ),
        network=None,
        extra=["--tmpfs", "/out:rw,size=1m,mode=1777"],
    )
    assert "READONLY-OK" in run.stdout
    assert "rc=1" in run.stdout


def test_all_capabilities_dropped_and_no_new_privileges():
    run = run_job(
        spec(["sh", "-c", "grep -E 'Cap(Eff|Bnd)|NoNewPrivs' /proc/self/status"]),
        network=None,
    )
    values = dict(line.split(":", 1) for line in run.stdout.splitlines())
    assert values["CapEff"].strip() == "0" * 16
    assert values["CapBnd"].strip() == "0" * 16
    assert values["NoNewPrivs"].strip() == "1"


def test_raw_socket_denied_without_capability_and_allowed_with_it():
    denied = run_job(
        spec(["sh", "-c", "ping -c1 -W1 127.0.0.1; echo rc=$?"]),
        network=None,
    )
    assert "Operation not permitted" in (denied.stdout + denied.stderr) or "rc=1" in denied.stdout
    allowed = run_job(
        spec(["sh", "-c", "ping -c1 -W1 127.0.0.1; echo rc=$?"], raw_socket=True),
        network=None,
    )
    assert "rc=0" in allowed.stdout


def test_job_runs_as_unprivileged_user():
    run = run_job(
        spec(["sh", "-c", "id -u; id -g; cat /proc/self/status | grep CapEff"]),
        network=None,
    )
    assert run.stdout.splitlines()[0].strip() == "65534"
    assert run.stdout.splitlines()[1].strip() == "65534"


def test_network_none_and_no_host_socket():
    run = run_job(
        spec(
            [
                "sh",
                "-c",
                "cat /proc/net/dev | tail -n +3 | cut -d: -f1 | tr -d ' '; "
                "test -e /run/podman/podman.sock && echo SOCKET-PRESENT || echo NO-SOCKET",
            ]
        ),
        network=None,
    )
    assert run.stdout.splitlines()[0].strip() == "lo"
    assert "NO-SOCKET" in run.stdout
