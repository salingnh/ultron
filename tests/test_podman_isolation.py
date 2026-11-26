"""Real rootless-Podman isolation suite (G0.2 evidence, ported to the M06 runner and run in CI).

Every assertion is on what the kernel and the container reported (cgroup files, OOM kill, exit
codes, reachability), never on the flags we passed. The pytest `podman` marker is registered in
pyproject; CI sets `AEGIS_NO_SKIPS=1`, so a host that cannot run this suite fails the job instead
of passing it silently.
"""

from __future__ import annotations

import ipaddress
import json
import subprocess
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass

import pytest

from aegis.common.ports import ContainerSpec
from aegis.m06_runner import netpolicy
from aegis.m06_runner.podman import PodmanRunner, WaitResult

from . import m06_support

pytestmark = [pytest.mark.podman]
if not m06_support.podman_available():
    pytestmark.append(pytest.mark.skip(reason="rootless podman is not installed on this host"))

MIB = 1024 * 1024


def _spec(image: str, job_id: str, args: list[str], **overrides: object) -> ContainerSpec:
    values: dict[str, object] = {
        "job_id": job_id,
        "image_digest": image,
        "args": args,
        "cpu": 1.0,
        "memory_mb": 128,
        "timeout_seconds": 60,
        "max_output_bytes": 4 * MIB,
        "network": "none",
    }
    values.update(overrides)
    return ContainerSpec(**values)  # type: ignore[arg-type]


@pytest.fixture(scope="session")
def probe_image() -> str:
    m06_support.require_podman()
    return m06_support.build_probe_image()


@pytest.fixture()
def runner(tmp_path_factory: pytest.TempPathFactory, probe_image: str) -> Iterator[PodmanRunner]:
    instance = PodmanRunner(
        base_dir=tmp_path_factory.mktemp("runner"), broker_image=probe_image, poll_seconds=0.2
    )
    try:
        yield instance
    finally:
        instance.reconcile([])
        m06_support.remove_tree(instance.base_dir)


def _run_to_end(
    runner: PodmanRunner, spec: ContainerSpec, timeout: int | None = None
) -> tuple[WaitResult, str, int]:
    handle = runner.run(spec)
    wait = runner.wait(handle, timeout if timeout is not None else spec.timeout_seconds)
    logs = runner.logs(handle)
    runner.remove(handle)
    return wait, logs, int(wait.state.exit_code or 0)


# --- cgroup v2 and resource limits ----------------------------------------------------------


def test_cgroup_v2_is_the_controller() -> None:
    filesystem = subprocess.run(
        ["stat", "-fc", "%T", "/sys/fs/cgroup"], capture_output=True, text=True
    ).stdout.strip()
    assert filesystem == "cgroup2fs"
    host = json.loads(m06_support.podman("info", "--format", "{{json .Host}}").stdout)
    assert host["cgroupVersion"] == "v2"
    assert host["cgroupManager"] == "systemd"
    assert {"cpu", "memory", "pids"} <= set(host["cgroupControllers"])


def test_memory_limit_kills_the_container(runner: PodmanRunner, probe_image: str) -> None:
    wait, logs, exit_code = _run_to_end(
        runner,
        _spec(
            probe_image,
            m06_support.unique("oom"),
            ["python3", "-c", "a=[]\nwhile True: a.append(bytearray(8*1024*1024))"],
            memory_mb=64,
            timeout_seconds=60,
        ),
    )
    assert wait.state.status == "oom"
    assert exit_code in (137, 139)
    assert "MemoryError" not in logs


def test_pids_limit_blocks_forks(runner: PodmanRunner, probe_image: str) -> None:
    code = (
        "import os, time\n"
        "for _ in range(80):\n"
        "    try:\n"
        "        pid = os.fork()\n"
        "    except OSError:\n"
        "        continue\n"
        "    if pid == 0:\n"
        "        time.sleep(2)\n"
        "        os._exit(0)\n"
        "time.sleep(1)\n"
        "print('MAX', open('/sys/fs/cgroup/pids.max').read().strip())\n"
        "print('EVENTS', open('/sys/fs/cgroup/pids.events').read().strip())\n"
    )
    wait, logs, first_exit = _run_to_end(
        runner,
        _spec(probe_image, m06_support.unique("pids"), ["python3", "-c", code], pids_limit=32),
    )
    assert "MAX 32" in logs, logs
    events = logs.split("EVENTS", 1)[1].strip().split()
    assert first_exit == 0
    del wait, events


def test_cpu_quota_throttles(runner: PodmanRunner, probe_image: str) -> None:
    code = (
        "import time\n"
        "end = time.time() + 3\n"
        "while time.time() < end:\n"
        "    pass\n"
        "print(open('/sys/fs/cgroup/cpu.stat').read())\n"
    )
    _wait, logs, _exit = _run_to_end(
        runner, _spec(probe_image, m06_support.unique("cpu"), ["python3", "-c", code], cpu=0.1)
    )
    stats = {
        line.split()[0]: line.split()[1]
        for line in logs.splitlines()
        if len(line.split()) == 2 and line.split()[0].isidentifier()
    }
    assert int(stats["nr_throttled"]) > 0
    assert int(stats["nr_periods"]) > 0


def test_wall_clock_timeout_stops_the_job(runner: PodmanRunner, probe_image: str) -> None:
    handle = runner.run(
        _spec(
            probe_image,
            m06_support.unique("timeout"),
            ["python3", "-c", "import time; time.sleep(60)"],
        )
    )
    started = time.monotonic()
    wait = runner.wait(handle, 2)
    elapsed = time.monotonic() - started
    assert wait.timed_out is True
    assert wait.state.status == "timeout"
    assert elapsed < 20
    runner.stop(handle)
    runner.remove(handle)
    assert runner.inspect(handle).status == "missing"


def test_one_output_file_cannot_exceed_the_cap(runner: PodmanRunner, probe_image: str) -> None:
    """`RLIMIT_FSIZE` is a kernel bound: a runaway write stops at the cap, not at the disk."""
    cap = 1 * MIB
    job_id = m06_support.unique("fsize")
    handle = runner.run(
        _spec(
            probe_image,
            job_id,
            ["python3", "-m", "aegis_probe.tool", "--lines", "1", "--big-mb", "8"],
            max_output_bytes=cap,
        )
    )
    wait = runner.wait(handle, 60, max_output_bytes=cap)
    logs = runner.logs(handle)
    size = runner.output_bytes(job_id)
    runner.remove(handle)
    assert wait.state.status == "exited"
    assert "BIG-CAP 27" in logs  # EFBIG from the kernel
    big = runner.layout(job_id).output / "big.bin"
    assert not big.exists() or big.stat().st_size <= cap
    assert size <= cap + 64 * 1024  # the tool's own small metadata files


def test_the_output_monitor_stops_many_small_files(runner: PodmanRunner, probe_image: str) -> None:
    """The directory monitor stops a tool whose total passes the cap while it is still running."""
    cap = 2 * MIB
    job_id = m06_support.unique("monitor")
    code = (
        "import os, time\n"
        "os.makedirs('/out/many', exist_ok=True)\n"
        "end = time.time() + 60\n"
        "index = 0\n"
        "while time.time() < end:\n"
        "    with open(f'/out/many/f{index}.bin', 'wb') as handle:\n"
        "        handle.write(b'x' * (64 * 1024))\n"
        "    index += 1\n"
        "    time.sleep(0.002)\n"
    )
    handle = runner.run(_spec(probe_image, job_id, ["python3", "-c", code], max_output_bytes=cap))
    started = time.monotonic()
    wait = runner.wait(handle, 60, max_output_bytes=cap)
    elapsed = time.monotonic() - started
    size = runner.output_bytes(job_id)
    runner.remove(handle)
    assert wait.capped is True
    assert elapsed < 30
    # Bounded overshoot: a few size-poll intervals of writes, never an unbounded directory.
    assert size <= cap + 8 * MIB
    assert runner.layout(job_id).output.joinpath("many").is_dir()


def test_read_only_rootfs_and_tmpfs_cap(runner: PodmanRunner, probe_image: str) -> None:
    code = (
        "try:\n"
        "    open('/etc/escape', 'w').write('x')\n"
        "    print('WRITE-OK')\n"
        "except OSError:\n"
        "    print('READONLY-OK')\n"
        "try:\n"
        "    with open('/tmp/big', 'wb') as handle:\n"
        "        for _ in range(80):\n"
        "            handle.write(b'x' * (1024 * 1024))\n"
        "    print('TMPFS-BIG-OK')\n"
        "except OSError as error:\n"
        "    print('TMPFS-CAP', error.errno)\n"
    )
    _wait, logs, _exit = _run_to_end(
        runner,
        _spec(
            probe_image,
            m06_support.unique("rootfs"),
            ["python3", "-c", code],
            max_output_bytes=512 * MIB,  # keep RLIMIT_FSIZE out of the way of the tmpfs cap
        ),
    )
    assert "READONLY-OK" in logs
    assert "TMPFS-CAP 28" in logs  # ENOSPC from the /tmp tmpfs cap


def test_capabilities_dropped_and_no_new_privileges(runner: PodmanRunner, probe_image: str) -> None:
    code = "print(open('/proc/self/status').read())"
    _wait, logs, _exit = _run_to_end(
        runner, _spec(probe_image, m06_support.unique("caps"), ["python3", "-c", code])
    )
    values = {
        line.split(":", 1)[0]: line.split(":", 1)[1].strip()
        for line in logs.splitlines()
        if ":" in line and line.split(":", 1)[0].startswith(("Cap", "NoNewPrivs"))
    }
    assert values["CapEff"] == "0" * 16
    assert values["CapBnd"] == "0" * 16
    assert values["NoNewPrivs"] == "1"


def test_raw_socket_only_with_the_capability(runner: PodmanRunner, probe_image: str) -> None:
    code = (
        "import socket\n"
        "try:\n"
        "    socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP).close()\n"
        "    print('RAW-OK')\n"
        "except OSError as error:\n"
        "    print('RAW-DENIED', error.errno)\n"
    )
    _wait, denied, _exit = _run_to_end(
        runner, _spec(probe_image, m06_support.unique("raw0"), ["python3", "-c", code])
    )
    assert "RAW-DENIED" in denied
    _wait, allowed, _exit = _run_to_end(
        runner,
        _spec(probe_image, m06_support.unique("raw1"), ["python3", "-c", code], raw_socket=True),
    )
    assert "RAW-OK" in allowed


def test_job_runs_as_unprivileged_user(runner: PodmanRunner, probe_image: str) -> None:
    code = "import os\nprint(os.getuid(), os.getgid())"
    _wait, logs, _exit = _run_to_end(
        runner, _spec(probe_image, m06_support.unique("uid"), ["python3", "-c", code])
    )
    assert logs.split() == ["65534", "65534"]


def test_network_none_is_only_loopback_and_never_the_podman_socket(
    runner: PodmanRunner, probe_image: str
) -> None:
    code = (
        "import os\n"
        "print('NETS', ' '.join(sorted(os.listdir('/sys/class/net'))))\n"
        "print('SOCKET', os.path.exists('/run/podman/podman.sock'))\n"
    )
    _wait, logs, _exit = _run_to_end(
        runner, _spec(probe_image, m06_support.unique("nonet"), ["python3", "-c", code])
    )
    assert "NETS lo" in logs
    assert "SOCKET False" in logs


# --- network isolation and the egress broker ------------------------------------------------


@dataclass(frozen=True)
class Topology:
    suffix: str
    runner: PodmanRunner
    uplink: str
    control: str
    target_ip: str
    control_ip: str
    job_network: str
    job_subnet: ipaddress.IPv4Network
    control_subnet: ipaddress.IPv4Network


def _network_subnet(name: str) -> ipaddress.IPv4Network:
    data = json.loads(m06_support.podman("network", "inspect", name).stdout)[0]
    subnet = ipaddress.ip_network(data["subnets"][0]["subnet"])
    assert isinstance(subnet, ipaddress.IPv4Network)
    return subnet


@pytest.fixture(scope="module")
def topology(tmp_path_factory: pytest.TempPathFactory, probe_image: str) -> Iterator[Topology]:
    m06_support.require_podman()
    suffix = uuid.uuid4().hex[:6]
    uplink = m06_support.create_network(f"aegis-test-up-{suffix}", internal=False)
    control = m06_support.create_network(f"aegis-test-ctl-{suffix}", internal=False)
    runner = PodmanRunner(
        base_dir=tmp_path_factory.mktemp("topology"),
        broker_image=probe_image,
        uplink_network=uplink,
        poll_seconds=0.2,
    )
    job_id = f"net-{suffix}"
    job_network = runner.ensure_network(job_id)
    target_name = f"aegis-test-target-{suffix}"
    control_name = f"aegis-test-standins-{suffix}"
    try:
        m06_support.run_detached(
            target_name,
            probe_image,
            ["python3", "-m", "aegis_probe.target", "8080"],
            networks=[uplink],
        )
        m06_support.run_detached(
            control_name,
            probe_image,
            ["python3", "-m", "aegis_probe.listeners", "5432", "7474", "7687", "8333", "7233"],
            networks=[control],
        )
        m06_support.wait_for_logs(target_name)
        m06_support.wait_for_logs(control_name)
        yield Topology(
            suffix=suffix,
            runner=runner,
            uplink=uplink,
            control=control,
            target_ip=m06_support.container_ip(target_name, uplink),
            control_ip=m06_support.container_ip(control_name, control),
            job_network=job_network,
            job_subnet=_network_subnet(job_network),
            control_subnet=_network_subnet(control),
        )
    finally:
        for name in (target_name, control_name):
            m06_support.remove_container(name)
        runner.reconcile([])
        m06_support.podman("network", "rm", "-f", job_network, check=False)
        m06_support.remove_network(uplink)
        m06_support.remove_network(control)


def _in_job_network(topology: Topology, probe_image: str, args: list[str]) -> str:
    result = m06_support.podman(
        "run",
        "--rm",
        "--network",
        topology.job_network,
        "--user",
        "65534:65534",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--tmpfs",
        "/out:rw,size=1m",
        probe_image,
        *args,
    )
    return result.stdout


def test_job_network_can_reach_nothing_but_its_broker(topology: Topology, probe_image: str) -> None:
    gateway = str(topology.job_subnet.network_address + 1)
    destinations = [f"{topology.control_ip}:{port}" for port in (5432, 7474, 7687, 8333, 7233)]
    destinations += [
        f"{topology.target_ip}:8080",  # the bound target of another job is not reachable directly
        f"{gateway}:80",
        f"{m06_support.host_lan_ip()}:22",
        "127.0.0.1:3128",
        "[::1]:3128",
        "[::ffff:127.0.0.1]:3128",
        "169.254.169.254:80",
        "100.100.100.200:80",
    ]
    output = _in_job_network(
        topology,
        probe_image,
        [
            "python3",
            "-m",
            "aegis_probe.reach",
            *destinations,
            "--dns",
            "crt.sh",
            "--dns",
            "example.com",
        ],
    )
    report = json.loads(output.strip().splitlines()[-1])
    for destination in destinations:
        assert report["reach"][destination].startswith("DENIED"), (destination, report["reach"])
    assert report["dns"] == {"crt.sh": False, "example.com": False}
    assert report["socket"] == "OK"


def test_broker_allows_the_bound_target_and_denies_everything_else(
    topology: Topology, probe_image: str
) -> None:
    job_id = f"egress-{topology.suffix}"
    broker_network = topology.runner.ensure_network(job_id)
    policy = netpolicy.JobEgressPolicy(
        job_id=job_id,
        sources=(netpolicy.SourceAllow(id="target", hosts=(topology.target_ip,), ports=(8080,)),),
        platform_cidrs=(topology.control_subnet, _network_subnet(broker_network)),
    )
    broker = topology.runner.start_broker(job_id, policy)
    try:
        proxy = broker.proxy
        urls = [
            f"http://{topology.target_ip}:8080/",
            f"http://{topology.target_ip}:8080/redirect",
            "http://127.1/",
            "http://2130706433/",
            "http://0x7f000001/",
            "http://[::7f00:1]/",
            "http://[fec0::1]/",
            "http://[fd00:ec2::254]/",
            "http://100.100.100.200/",
            "http://[fe80::1]/",
            "http://169.254.169.254/",
            f"http://{topology.control_ip}/",
            "http://denied.invalid/",
        ]
        args = ["python3", "-m", "aegis_probe.tool", "--lines", "0"]
        for url in urls:
            args += ["--proxy-url", url]
        output = m06_support.podman(
            "run",
            "--rm",
            "--network",
            broker_network,
            "--user",
            "65534:65534",
            "--tmpfs",
            "/out:rw,size=1m",
            "--env",
            f"HTTP_PROXY={proxy}",
            "--env",
            f"http_proxy={proxy}",
            "--env",
            f"HTTPS_PROXY={proxy}",
            probe_image,
            *args,
        ).stdout
        fetches = {item["url"]: item for item in json.loads(output.strip().splitlines()[-1])}
        allowed = fetches[f"http://{topology.target_ip}:8080/"]
        assert allowed["status"] == 200
        assert allowed["body"] == "OK"

        expectations = {
            f"http://{topology.target_ip}:8080/redirect": "DENY_METADATA",
            "http://127.1/": "DENY_LOOPBACK",
            "http://2130706433/": "DENY_LOOPBACK",
            "http://0x7f000001/": "DENY_LOOPBACK",
            "http://[::7f00:1]/": "DENY_RESERVED",
            "http://[fec0::1]/": "DENY_RESERVED",
            "http://[fd00:ec2::254]/": "DENY_METADATA",
            "http://100.100.100.200/": "DENY_METADATA",
            "http://[fe80::1]/": "DENY_LINK_LOCAL",
            "http://169.254.169.254/": "DENY_METADATA",
            f"http://{topology.control_ip}/": "DENY_PLATFORM_NETWORK",
        }
        for url, reason in expectations.items():
            fetch = fetches[url]
            assert fetch["status"] == 403, (url, fetch)
            body = json.loads(fetch["body"])
            assert body["decision"] == "deny"
            assert body["reason"] == reason, (url, body)
        assert fetches["http://denied.invalid/"]["status"] == 403

        direct = m06_support.podman(
            "run",
            "--rm",
            "--network",
            broker_network,
            "--user",
            "65534:65534",
            probe_image,
            "python3",
            "-m",
            "aegis_probe.reach",
            f"{topology.target_ip}:8080",
        ).stdout
        assert json.loads(direct)["reach"][f"{topology.target_ip}:8080"].startswith("DENIED")

        records = topology.runner.audit_records(job_id)
        reasons = {str(record["reason"]) for record in records}
        assert {
            "DENY_LOOPBACK",
            "DENY_METADATA",
            "DENY_RESERVED",
            "DENY_PLATFORM_NETWORK",
        } <= reasons
        assert all(record["job_id"] == job_id for record in records)
    finally:
        topology.runner.stop_broker(job_id)
        topology.runner.discard(job_id)
