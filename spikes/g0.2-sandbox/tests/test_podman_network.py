"""Network isolation under rootless Podman (spike G0.2).

Topology used by the tests (all names/suffixes unique per run):

    job network  10.89.x.0/24  internal, DNS disabled, only the broker reachable
    exec uplink  10.90.x.0/24  broker + the one allowed target
    control net  10.91.x.0/24  stand-in PostgreSQL/Neo4j/S3/Temporal listeners

The job container is started exactly like a real job (cap-drop ALL,
no-new-privileges, read-only rootfs, uid 65534, internal network, resolver =
broker) and a probe script reports what it can reach.
"""

from __future__ import annotations

import json
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import pytest

from aegis_g02 import netpolicy
from aegis_g02.podman_runner import (
    PODMAN,
    BrokerContainer,
    ContainerSpec,
    JobNetwork,
    run_job,
)

from .images import PRODUCT, PYTHON_312

pytestmark = pytest.mark.integration

SPIKE_ROOT = Path(__file__).resolve().parent.parent
PROBE_IMAGE = "localhost/g02-probe:local"
CONTROL_PORTS = (5432, 7474, 7687, 8333, 7233)
UPLINK = "10.90.0.0/24"
CONTROL = "10.91.0.0/24"


def sh(*args: str, check: bool = True, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run([PODMAN, *args], capture_output=True, text=True, check=check, timeout=timeout)


def wait_ready(name: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        logs = sh("logs", name, check=False).stdout
        if "READY" in logs:
            return
        time.sleep(0.2)
    raise RuntimeError(f"{name} did not become ready: {sh('logs', name, check=False).stdout[-500:]}")


def container_ip(name: str, network: str) -> str:
    data = json.loads(sh("inspect", name).stdout)[0]
    return data["NetworkSettings"]["Networks"][network]["IPAddress"]


def create_network(name: str, subnet: str, *, internal: bool) -> str:
    args = ["network", "create", "--subnet", subnet, "--label", "aegis.spike=g0.2", name]
    if internal:
        args += ["--internal", "--disable-dns"]
    sh(*args)
    return name


@dataclass
class Harness:
    suffix: str
    job_net: JobNetwork
    uplink: str
    control: str
    target_name: str
    target_ip: str
    control_ips: list[str]
    broker: BrokerContainer
    host_ip: str

    @property
    def target(self) -> str:
        return f"{self.target_ip}:8080"

    @property
    def proxy(self) -> str:
        return f"http://{self.broker.network.broker_ip()}:3128"

    @property
    def socks(self) -> str:
        # urllib wants a scheme, Naabu's -proxy wants host:port without one.
        return f"socks5://{self.broker.network.broker_ip()}:1080"

    @property
    def socks_hostport(self) -> str:
        return f"{self.broker.network.broker_ip()}:1080"


@pytest.fixture(scope="module")
def harness(tmp_path_factory: pytest.TempPathFactory) -> Harness:
    build = subprocess.run(
        [PODMAN, "build", "-q", "-t", PROBE_IMAGE, "-f",
         str(SPIKE_ROOT / "images" / "probe" / "Containerfile"), str(SPIKE_ROOT)],
        capture_output=True, text=True,
    )
    assert build.returncode == 0, build.stderr[-2000:]
    suffix = uuid.uuid4().hex[:6]
    workdir = tmp_path_factory.mktemp("g02-net")
    job_net = JobNetwork(f"net-{suffix}", pool="10.89.0.0/16", prefix=24).create()
    uplink = create_network(f"g02-up-{suffix}", UPLINK, internal=False)
    control = create_network(f"g02-ctl-{suffix}", CONTROL, internal=False)
    created: list[str] = []
    try:
        target_name = f"g02-target-{suffix}"
        sh(
            "run", "-d", "--name", target_name, "--label", "aegis.spike=g0.2",
            "--network", uplink, "--user", "65534:65534",
            PROBE_IMAGE, "python3", "-m", "aegis_g02.allowed_target", "8080",
        )
        created.append(target_name)
        wait_ready(target_name)
        target_ip = container_ip(target_name, uplink)

        control_name = f"g02-standins-{suffix}"
        sh(
            "run", "-d", "--name", control_name, "--label", "aegis.spike=g0.2",
            "--network", control, "--user", "65534:65534",
            PROBE_IMAGE, "python3", "-m", "aegis_g02.standins", *[str(p) for p in CONTROL_PORTS],
        )
        created.append(control_name)
        wait_ready(control_name)
        control_ip = container_ip(control_name, control)

        policy = {
            "job_id": f"g02-{suffix}",
            "mode": "egress",
            "target_ips": [f"{target_ip}/32"],
            "target_ports": [8080],
            "platform_cidrs": [str(job_net.subnet), CONTROL, "10.88.0.0/16"],
            "deny_cidrs": ["10.90.0.200/32"],
            "sources": [],
        }
        policy_path = workdir / "policy.json"
        policy_path.write_text(json.dumps(policy))
        audit_dir = workdir / "audit"
        audit_dir.mkdir()
        audit_dir.chmod(0o777)
        broker = BrokerContainer(
            job_id=f"g02-{suffix}",
            image=PROBE_IMAGE,
            network=job_net,
            uplink=uplink,
            policy_path=policy_path,
            audit_dir=audit_dir,
        ).start()
        created.append(broker.container_id)
        host_ip = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "scope", "global"],
            capture_output=True, text=True,
        ).stdout.split()[3].split("/")[0]
        yield Harness(
            suffix=suffix,
            job_net=job_net,
            uplink=uplink,
            control=control,
            target_name=target_name,
            target_ip=target_ip,
            control_ips=[control_ip],
            broker=broker,
            host_ip=host_ip,
        )
    finally:
        for name in created:
            sh("rm", "-f", name, check=False)
        for net in (job_net.name, uplink, control):
            sh("network", "rm", "-f", net, check=False)


def probe(harness: Harness, request: dict) -> dict:
    spec = ContainerSpec(
        job_id=f"probe-{uuid.uuid4().hex[:8]}",
        image_digest=PROBE_IMAGE,
        args=["python3", "-m", "aegis_g02.job_probe", json.dumps(request)],
        cpu=1.0,
        memory_mb=256,
        timeout_seconds=120,
        max_output_bytes=1024 * 1024,
        network="exec",
    )
    run = run_job(
        spec,
        network=harness.job_net.name,
        dns=harness.broker.network.broker_ip(),
        extra=[],
    )
    assert run.exit_code == 0, run.stdout + run.stderr
    return json.loads(run.stdout.strip().splitlines()[-1])


def test_job_has_no_route_to_control_plane_or_metadata(harness: Harness):
    targets = [f"{ip}:{port}" for ip in harness.control_ips for port in CONTROL_PORTS]
    targets += [
        "169.254.169.254:80",
        "127.0.0.1:5432",
        "[::1]:5432",
        "[::ffff:127.0.0.1]:5432",
        f"{harness.job_net.gateway}:5432",
        f"{harness.host_ip}:5432",
        f"{harness.target_ip}:8080",  # allowed target is only reachable via the broker
    ]
    result = probe(harness, {"direct": targets})
    reached = {k: v for k, v in result["direct"].items() if v == "CONNECTED"}
    assert not reached, f"unexpectedly reachable: {reached}"
    for target, outcome in result["direct"].items():
        assert "CONNECTED" not in outcome


def test_job_has_no_external_dns(harness: Harness):
    result = probe(harness, {"dns": ["example.com", "crt.sh"]})
    assert all("Error" in v or ":" in v for v in result["dns"].values()), result["dns"]


def test_broker_allows_the_bound_target(harness: Harness):
    result = probe(
        harness,
        {"proxy": harness.proxy, "urls": [f"http://{harness.target}/ok"]},
    )
    outcome = result["proxy"][f"http://{harness.target}/ok"]
    assert outcome["status"] == 200
    assert outcome["body"] == "allowed-target-ok"


def test_broker_denies_control_plane_metadata_and_unbound(harness: Harness):
    urls = [
        "http://127.0.0.1:5432/",
        "http://169.254.169.254/",
        "http://[::1]:5432/",
        "http://[::ffff:127.0.0.1]:5432/",
        f"http://{harness.control_ips[0]}:5432/",
        f"http://10.90.0.200:8080/",
        f"http://{harness.target_ip}:5432/",
    ]
    result = probe(harness, {"proxy": harness.proxy, "urls": urls})
    for url in urls:
        assert result["proxy"][url]["status"] == 403, (url, result["proxy"][url])

    reasons = {(r["host"], r["reason"]) for r in harness.broker.audit_records()}
    assert ("127.0.0.1", "DENY_LOOPBACK") in reasons
    assert ("169.254.169.254", "DENY_LINK_LOCAL") in reasons
    assert ("::1", "DENY_LOOPBACK") in reasons
    assert ("::ffff:127.0.0.1", "DENY_LOOPBACK") in reasons
    assert (harness.control_ips[0], "DENY_PLATFORM_NETWORK") in reasons
    assert ("10.90.0.200", "DENY_TARGET_DENYLIST") in reasons
    assert reason_for_port_mismatch(harness) == "PORT_NOT_ALLOWED"


def reason_for_port_mismatch(harness: Harness) -> str:
    for record in harness.broker.audit_records():
        if record["host"] == harness.target_ip and record["port"] == 5432:
            return record["reason"]
    return "MISSING"


def test_redirect_target_is_rechecked(harness: Harness):
    result = probe(
        harness,
        {
            "proxy": harness.proxy,
            "urls": [f"http://{harness.target}/redirect?to=http://169.254.169.254/"],
        },
    )
    outcome = result["proxy"][f"http://{harness.target}/redirect?to=http://169.254.169.254/"]
    assert outcome["status"] == 403
    assert any(
        r["host"] == "169.254.169.254" and r["reason"] == "DENY_LINK_LOCAL"
        for r in harness.broker.audit_records()
    )


def test_socks5_broker_denies_and_allows(harness: Harness):
    result = probe(
        harness,
        {
            "proxy": harness.socks,
            "socks5_targets": [f"{harness.target_ip}:8080", "127.0.0.1:5432"],
        },
    )
    assert result["socks5"][f"{harness.target_ip}:8080"] == "CONNECTED"
    assert result["socks5"]["127.0.0.1:5432"] == "DENIED-BY-RULESET"


def test_policy_document_matches_broker_reasons(harness: Harness):
    policy = netpolicy.load_policy(json.loads(harness.broker.policy_path.read_text()))
    denied = netpolicy.decide(policy, "169.254.169.254", 80)
    assert not denied.allowed and denied.reason is netpolicy.Reason.DENY_LINK_LOCAL


# --- Naabu: what a raw-socket scanner can and cannot reach ------------------


def naabu(
    harness: Harness,
    *,
    network: str,
    scan: str,
    sock: str | None,
    raw: bool = True,
    user: str = "0:0",
    silent: bool = True,
) -> str:
    """Run the pinned Naabu image and return its combined output."""
    args = [
        "-host", harness.target_ip, "-p", "8080",
        "-s", scan, "-no-color", "-disable-update-check",
        "-timeout", "5",
    ]
    args += ["-silent"] if silent else ["-v"]
    if sock:
        args += ["-proxy", sock]
    spec = ContainerSpec(
        job_id=f"naabu-{uuid.uuid4().hex[:8]}",
        image_digest=PRODUCT["naabu"],
        args=args,
        cpu=1.0,
        memory_mb=512,
        timeout_seconds=120,
        max_output_bytes=1024 * 1024,
        network="exec",
        raw_socket=raw,
        user=user,
    )
    run = run_job(spec, network=network)
    return run.stdout + run.stderr


def test_naabu_syn_mode_downgrades_rootless(harness: Harness):
    """Pinned naabu 2.7.0 does not run SYN here, even with NET_RAW effective.

    Evidence: the kernel grants the raw socket (CapEff=0x2000 is asserted in
    test_raw_socket_denied_without_capability_and_allowed_with_it) but naabu
    logs "Running CONNECT scan with non root privileges". A raw-socket
    provider must therefore prove the *effective* scan mode at conformance
    time instead of trusting the -s flag.
    """
    verbose = naabu(harness, network=harness.uplink, scan="syn", sock=None, silent=False)
    assert "CONNECT scan with non root privileges" in verbose, verbose[-800:]
    out = naabu(harness, network=harness.uplink, scan="syn", sock=None)
    assert f"{harness.target_ip}:8080" in out, out[-800:]


def test_naabu_direct_scan_cannot_use_the_job_network(harness: Harness):
    """Same scanner, same capability, but the job network has no L3 path."""
    out = naabu(harness, network=harness.job_net.name, scan="connect", sock=None, raw=False)
    assert f"{harness.target_ip}:8080" not in out, out[-800:]


def test_naabu_connect_scan_through_the_broker(harness: Harness):
    """Connect scan needs no raw socket and works through the SOCKS5 broker."""
    out = naabu(
        harness,
        network=harness.job_net.name,
        scan="connect",
        sock=harness.socks_hostport,
        raw=False,
    )
    assert f"{harness.target_ip}:8080" in out, out[-800:]


def test_naabu_connect_scan_denied_by_policy(harness: Harness):
    """The broker refuses loopback even though the tool asks for it."""
    spec_args = [
        "-host", "127.0.0.1", "-p", "5432", "-s", "connect",
        "-silent", "-no-color", "-disable-update-check", "-proxy", harness.socks_hostport,
    ]
    spec = ContainerSpec(
        job_id=f"naabu-deny-{uuid.uuid4().hex[:6]}",
        image_digest=PRODUCT["naabu"],
        args=spec_args,
        cpu=1.0,
        memory_mb=512,
        timeout_seconds=60,
        max_output_bytes=1024 * 1024,
        network="exec",
        raw_socket=False,
        user="0:0",
    )
    run = run_job(spec, network=harness.job_net.name)
    assert "5432" not in run.stdout
    assert any(r["reason"] == "DENY_LOOPBACK" for r in harness.broker.audit_records())
