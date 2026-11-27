"""DNS-over-broker end to end (G1.6 item 4): the job resolves only through the broker.

A fake upstream resolver answers a fixed table, so the test needs no internet. The job container is
run on its own internal network with `--dns <broker_ip>` - exactly what M06 gives an internet job -
and its `/etc/resolv.conf` is the only resolver it has:

* a bound target name resolves to its signed address;
* a name the task does not bind is refused (and never reaches the upstream);
* an answer inside the deny set is dropped, so the name does not resolve;
* the broker's audit carries one `kind: dns` line per query with the decision and reason.
"""

from __future__ import annotations

import ipaddress
import json
import uuid

import pytest

from aegis.m06_runner import netpolicy
from aegis.m06_runner.podman import PodmanRunner

from . import m06_support

BOUND = "bound.example"
UNBOUND = "unbound.example"
DENIED = "denied.example"
SIGNED = "198.51.100.7"
FAKE_PORT = 5353
PRIVATE = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")


@pytest.fixture(scope="module")
def probe_image() -> str:
    m06_support.require_podman()
    return m06_support.build_probe_image()


def test_a_job_resolves_only_through_the_broker_and_is_audited(
    tmp_path_factory: pytest.TempPathFactory, probe_image: str
) -> None:
    m06_support.require_podman()
    suffix = uuid.uuid4().hex[:6]
    uplink = m06_support.create_network(f"aegis-dns-up-{suffix}", internal=False)
    upstream_name = f"aegis-dns-fake-{suffix}"
    job_id = f"dns-{suffix}"
    runner = PodmanRunner(
        base_dir=tmp_path_factory.mktemp("dns-flow"),
        broker_image=probe_image,
        uplink_network=uplink,
    )
    job_network = runner.ensure_network(job_id)
    broker_ip = runner.broker_ip(job_id)
    answers = {BOUND: [SIGNED], DENIED: ["169.254.169.254"]}
    policy = netpolicy.JobEgressPolicy(
        job_id=job_id,
        profile="internet",
        dns_names=(BOUND, DENIED),
        dns_target_names=(BOUND,),
        target_ips=(ipaddress.ip_network(f"{SIGNED}/32"),),
        private_cidrs=tuple(ipaddress.ip_network(entry) for entry in PRIVATE),
    )
    try:
        m06_support.run_detached(
            upstream_name,
            probe_image,
            ["python3", "-m", "aegis_probe.fake_dns", str(FAKE_PORT), json.dumps(answers)],
            networks=[uplink],
        )
        m06_support.wait_for_logs(upstream_name)
        upstream_ip = m06_support.container_ip(upstream_name, uplink)
        runner.broker_dns_upstream = f"{upstream_ip}:{FAKE_PORT}"
        runner.start_broker(job_id, policy)

        script = (
            "import json, socket\n"
            "report = {}\n"
            "for name in ('" + BOUND + "', '" + UNBOUND + "', '" + DENIED + "'):\n"
            "    try:\n"
            "        report[name] = socket.gethostbyname(name)\n"
            "    except OSError as error:\n"
            "        report[name] = 'ERROR:' + type(error).__name__\n"
            "print(json.dumps(report))\n"
        )
        result = m06_support.podman(
            "run",
            "--rm",
            *m06_support.ci_job_label_args(),
            "--network",
            job_network,
            "--user",
            "65534:65534",
            "--cap-drop=ALL",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,size=8m",
            "--dns",
            broker_ip,
            probe_image,
            "python3",
            "-c",
            script,
        )
        report = json.loads(result.stdout.strip().splitlines()[-1])
        assert report[BOUND] == SIGNED
        assert report[UNBOUND].startswith("ERROR:")
        assert report[DENIED].startswith("ERROR:")

        records = [record for record in runner.audit_records(job_id) if record.get("kind") == "dns"]
        by_name = {str(record["name"]): record for record in records}
        assert by_name[BOUND]["decision"] == "allow"
        assert by_name[BOUND]["answers"] == [SIGNED]
        assert by_name[UNBOUND]["reason"] == "NAME_NOT_BOUND"
        assert by_name[DENIED]["reason"] == "NO_ADDRESS_ALLOWED"
        assert {str(record["network_profile"]) for record in records} == {"internet"}
        # The job's resolv.conf names the broker: no in-job open resolver.
        resolv = m06_support.podman(
            "run",
            "--rm",
            *m06_support.ci_job_label_args(),
            "--network",
            job_network,
            "--dns",
            broker_ip,
            probe_image,
            "cat",
            "/etc/resolv.conf",
        ).stdout
        assert broker_ip in resolv
    finally:
        m06_support.remove_container(upstream_name)
        runner.reconcile([])
        m06_support.podman("network", "rm", "-f", job_network, check=False)
        m06_support.remove_network(uplink)
        m06_support.remove_tree(runner.base_dir)
