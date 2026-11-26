"""L3 gateway mode end to end (G1.6 item 5): the broker is the job's gateway, via the OCI hook.

The job runs on an internal network with no default route; the deployment's OCI `createContainer`
hook installs the only route it has, `default via <broker>`. The script inside the job is the
conformance gate and proves, from inside the job:

* the signed target:port is reachable and the broker forwarded it (nft flow counter > 0);
* an unbound port on the same host, a metadata address and loopback are unreachable;
* the route table holds nothing but the default via the broker and the job subnet;
* the job has no capabilities and cannot add a route;
* its only resolver is the broker.

A job with no hook configured, or one whose hook fails, is refused before it can run (fail closed):
there is no "start anyway" path and no direct route to fall back to.
"""

from __future__ import annotations

import ipaddress
import json
import time
import uuid
from pathlib import Path

import pytest

from aegis.common.ports import ContainerSpec
from aegis.common.repo import repository_root
from aegis.m06_runner import netpolicy
from aegis.m06_runner.podman import PodmanRunner, RunnerError

from . import m06_support

BROKER_IMAGE = "localhost/aegis-broker:g16-l3-test"
HOOK = repository_root() / "deploy" / "l3" / "hooks" / "aegis-l3-route"
PRIVATE = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
MIB = 1024 * 1024


@pytest.fixture(scope="module")
def broker_image() -> str:
    m06_support.require_podman()
    built = m06_support.podman(
        "build",
        "--quiet",
        "--file",
        str(repository_root() / "deploy" / "broker" / "Containerfile"),
        "--tag",
        BROKER_IMAGE,
        str(repository_root()),
        check=False,
    )
    if built.returncode != 0:
        raise RuntimeError(f"broker image build failed: {built.stderr[-3000:]}")
    return BROKER_IMAGE


@pytest.fixture(scope="module")
def probe_image() -> str:
    m06_support.require_podman()
    return m06_support.build_probe_image()


def _spec(image: str, job_id: str, args: list[str]) -> ContainerSpec:
    return ContainerSpec(
        job_id=job_id,
        image_digest=image,
        args=args,
        cpu=1.0,
        memory_mb=128,
        timeout_seconds=60,
        max_output_bytes=4 * MIB,
        network="exec",
        network_profile="internet",
        egress_mode="l3",
    )


def _policy(job_id: str, target_ip: str, *, port: int = 8080) -> netpolicy.JobEgressPolicy:
    return netpolicy.JobEgressPolicy(
        job_id=job_id,
        egress_mode="l3",
        profile="internet",
        target_ips=(ipaddress.ip_network(f"{target_ip}/32"),),
        target_ports=(port,),
        private_cidrs=tuple(ipaddress.ip_network(entry) for entry in PRIVATE),
    )


def _wait_audit(path: Path, event: str, timeout: float = 10.0) -> list[dict[str, object]]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file():
            records = [json.loads(line) for line in path.read_text().splitlines() if line]
            if any(record.get("event") == event for record in records):
                return records
        time.sleep(0.2)
    return []


def test_the_l3_gateway_allows_only_the_signed_ip_and_port(
    tmp_path_factory: pytest.TempPathFactory, broker_image: str, probe_image: str
) -> None:
    m06_support.require_podman()
    suffix = uuid.uuid4().hex[:6]
    uplink = m06_support.create_network(f"aegis-l3-up-{suffix}", internal=False)
    job_id = f"l3-{suffix}"
    target_name = f"aegis-l3-target-{suffix}"
    extra_name = f"aegis-l3-extra-{suffix}"
    runner = PodmanRunner(
        base_dir=tmp_path_factory.mktemp("l3-flow"),
        broker_image=broker_image,
        uplink_network=uplink,
        l3_hook=HOOK,
    )
    job_network = runner.ensure_network(job_id)
    broker_ip = runner.broker_ip(job_id)
    audit_path = runner.layout(job_id).audit / "egress.jsonl"
    try:
        m06_support.run_detached(
            target_name,
            probe_image,
            ["python3", "-m", "aegis_probe.target", "8080"],
            networks=[uplink],
        )
        m06_support.wait_for_logs(target_name)
        m06_support.run_detached(
            extra_name,
            probe_image,
            ["python3", "-m", "aegis_probe.listeners", "9090"],
            networks=[uplink],
        )
        m06_support.wait_for_logs(extra_name)
        target_ip = m06_support.container_ip(target_name, uplink)
        runner.start_broker(job_id, _policy(job_id, target_ip))

        script = (
            "import json, socket, subprocess\n"
            "def probe(host, port):\n"
            "    try:\n"
            "        socket.create_connection((host, port), timeout=3).close()\n"
            "        return 'OK'\n"
            "    except OSError as error:\n"
            "        return 'DENIED:' + type(error).__name__\n"
            "def routes():\n"
            "    return subprocess.run(['ip', '-o', 'route'], capture_output=True,\n"
            "                          text=True).stdout\n"
            "report = {\n"
            "    'signed': probe('" + target_ip + "', 8080),\n"
            "    'unbound_port': probe('" + target_ip + "', 9090),\n"
            "    'metadata': probe('169.254.169.254', 80),\n"
            "    'loopback': probe('127.0.0.1', 22),\n"
            "    'add_route': subprocess.run(\n"
            "        ['ip', 'route', 'add', '203.0.113.0/24', 'via', '" + broker_ip + "'],\n"
            "        capture_output=True, text=True).returncode == 0,\n"
            "}\n"
            "caps = [line for line in open('/proc/self/status') if line.startswith('CapEff')]\n"
            "report['cap_eff'] = caps[0].split()[1] if caps else 'missing'\n"
            "report['routes'] = routes()\n"
            "report['resolv'] = [line.split()[1] for line in open('/etc/resolv.conf')\n"
            "                    if line.startswith('nameserver')]\n"
            "print(json.dumps(report))\n"
        )
        handle = runner.run(_spec(probe_image, job_id, ["python3", "-c", script]))
        m06_support.podman("wait", handle.container_id, timeout=120)
        log = runner.logs(handle)
        report = json.loads(log.strip().splitlines()[-1])

        assert report["signed"] == "OK"
        assert report["unbound_port"].startswith("DENIED:")
        assert report["metadata"].startswith("DENIED:")
        assert report["loopback"].startswith("DENIED:")
        assert report["cap_eff"] == "0000000000000000"
        assert report["add_route"] is False, "the job must not be able to change its route table"
        assert report["resolv"] == [broker_ip]
        # Exactly one default route, via the broker, plus the on-link subnet; nothing else.
        route_lines = [line for line in str(report["routes"]).splitlines() if line.strip()]
        assert any(line.startswith("default via " + broker_ip) for line in route_lines), route_lines
        assert len(route_lines) == 2, route_lines

        records = _wait_audit(audit_path, "flow")
        assert records, "the broker never audited the forwarded flow"
        installed = [record for record in records if record.get("event") == "installed"]
        assert installed, "the broker did not report the installed rule set"
        declared = installed[0].get("rules")
        rules = [str(item) for item in (declared if isinstance(declared, list) else [])]
        assert f"{target_ip}:8080/tcp" in rules
        assert f"{target_ip}:9090/tcp" not in rules
        flows = [record for record in records if record.get("event") == "flow"]
        allowed = [record for record in flows if record.get("dst") == target_ip]
        assert allowed and int(str(allowed[0].get("packets", 0))) > 0, flows
        assert any(record.get("event") == "denied" for record in records), records
    finally:
        m06_support.remove_container(extra_name)
        m06_support.remove_container(target_name)
        runner.reconcile([])
        m06_support.podman("network", "rm", "-f", job_network, check=False)
        m06_support.remove_network(uplink)
        m06_support.remove_tree(runner.base_dir)


def test_an_l3_job_without_a_hook_is_refused(
    tmp_path_factory: pytest.TempPathFactory, broker_image: str, probe_image: str
) -> None:
    """No hook configured: the job never starts (fail closed, no direct route to fall back to)."""
    m06_support.require_podman()
    suffix = uuid.uuid4().hex[:6]
    job_id = f"l3-nohook-{suffix}"
    uplink = m06_support.create_network(f"aegis-{job_id}-up", internal=False)
    runner = PodmanRunner(
        base_dir=tmp_path_factory.mktemp("l3-nohook"),
        broker_image=broker_image,
        uplink_network=uplink,
    )
    job_network = runner.ensure_network(job_id)
    try:
        runner.start_broker(job_id, _policy(job_id, "198.51.100.7"))
        with pytest.raises(RunnerError, match="route hook"):
            runner.run(_spec(probe_image, job_id, ["python3", "-c", "print('never')"]))
        assert runner.list_jobs() == ()
    finally:
        runner.reconcile([])
        m06_support.podman("network", "rm", "-f", job_network, check=False)
        m06_support.remove_network(uplink)
        m06_support.remove_tree(runner.base_dir)


def test_a_failing_hook_refuses_the_job(
    tmp_path_factory: pytest.TempPathFactory, broker_image: str, probe_image: str
) -> None:
    """A hook that fails aborts the container start: podman refuses it, M06 records the failure."""
    m06_support.require_podman()
    suffix = uuid.uuid4().hex[:6]
    job_id = f"l3-badhook-{suffix}"
    uplink = m06_support.create_network(f"aegis-{job_id}-up", internal=False)
    runner = PodmanRunner(
        base_dir=tmp_path_factory.mktemp("l3-badhook"),
        broker_image=broker_image,
        uplink_network=uplink,
    )
    job_network = runner.ensure_network(job_id)
    broken = runner.base_dir / "broken-hook"
    broken.write_text("#!/bin/sh\nexit 9\n", encoding="utf-8")
    broken.chmod(0o755)
    runner.l3_hook = broken
    try:
        runner.start_broker(job_id, _policy(job_id, "198.51.100.7"))
        with pytest.raises(RunnerError, match="could not start"):
            runner.run(_spec(probe_image, job_id, ["python3", "-c", "print('never')"]))
        # Production does this in `JobRunner.execute` when a sandbox cannot start; nothing may run.
        runner.discard(job_id)
        assert runner.list_jobs() == ()
    finally:
        runner.reconcile([])
        m06_support.podman("network", "rm", "-f", job_network, check=False)
        m06_support.remove_network(uplink)
        m06_support.remove_tree(runner.base_dir)
