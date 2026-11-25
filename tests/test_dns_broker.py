"""The job's DNS front end: per-query checks, filtered answers, audit (G1.6 item 4).

Everything here is in process: a stub resolver answers with fixed addresses, and the broker's own
UDP/TCP DNS servers are started for the transport tests. No real DNS is used, so the outcomes are
deterministic and CI needs no network.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import socketserver
import struct
import threading
from pathlib import Path

from aegis.m06_runner import broker as broker_mod
from aegis.m06_runner import dns as dns_wire
from aegis.m06_runner.netpolicy import JobEgressPolicy

PRIVATE = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
AUTHORIZATION = "owner, item 61, 2026-11-25"
TARGET = "198.51.100.7"


class Stub:
    def __init__(self, answers: dict[str, list[str]]) -> None:
        self.answers = answers
        self.asked: list[str] = []

    def __call__(self, name: str) -> list[str]:
        self.asked.append(name)
        return list(self.answers.get(name, []))


def _policy(
    *,
    names: tuple[str, ...] = ("bound.example",),
    target_names: tuple[str, ...] = ("bound.example",),
    targets: tuple[str, ...] = (TARGET,),
    profile: str = "internet",
) -> JobEgressPolicy:
    return JobEgressPolicy(
        job_id="job-1",
        profile=profile,
        campaign_id="01934f6a-0000-7000-8000-000000000001",
        authorization=AUTHORIZATION,
        target_ips=tuple(
            ipaddress.ip_network(f"{address}/{ipaddress.ip_address(address).max_prefixlen}")
            for address in targets
        ),
        private_cidrs=tuple(ipaddress.ip_network(entry) for entry in PRIVATE),
        dns_names=names,
        dns_target_names=target_names,
    )


def _query(name: str, qtype: int = dns_wire.TYPE_A, qid: int = 1) -> bytes:
    return dns_wire.build_query(qid, name, qtype)


def _forwarder(tmp_path: Path, policy: JobEgressPolicy, stub: Stub) -> dns_wire.DnsForwarder:
    audit = broker_mod.AuditLog(
        tmp_path / "egress.jsonl",
        policy.job_id,
        profile=policy.profile,
        campaign_id=policy.campaign_id,
        authorization=policy.authorization,
    )
    return dns_wire.DnsForwarder(policy, audit, resolver=stub)


def _answer(
    forwarder: dns_wire.DnsForwarder, name: str, qtype: int = dns_wire.TYPE_A
) -> tuple[int, list[str]]:
    reply = forwarder.handle(_query(name, qtype))
    assert reply is not None
    (_qid, flags, _qd, _an, _ns, _ar) = struct.unpack_from("!HHHHHH", reply)
    return flags & 0x000F, dns_wire.parse_addresses(reply)


def _audit(tmp_path: Path) -> list[dict[str, object]]:
    path = tmp_path / "egress.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def test_a_bound_target_name_resolves_to_its_signed_address(tmp_path: Path) -> None:
    stub = Stub({"bound.example": [TARGET]})
    forwarder = _forwarder(tmp_path, _policy(), stub)
    rcode, addresses = _answer(forwarder, "bound.example")
    assert rcode == dns_wire.RCODE_NOERROR and addresses == [TARGET]
    record = _audit(tmp_path)[-1]
    assert record["kind"] == "dns"
    assert record["name"] == "bound.example"
    assert record["decision"] == "allow"
    assert record["answers"] == [TARGET]
    assert record["network_profile"] == "internet"
    assert record["authorization"] == AUTHORIZATION


def test_an_unbound_name_is_refused_without_resolving_it(tmp_path: Path) -> None:
    stub = Stub({"evil.example": [TARGET]})
    forwarder = _forwarder(tmp_path, _policy(), stub)
    rcode, addresses = _answer(forwarder, "evil.example")
    assert rcode == dns_wire.RCODE_REFUSED and addresses == []
    assert stub.asked == [], "an unbound name must never reach the resolver"
    record = _audit(tmp_path)[-1]
    assert record["decision"] == "deny" and record["reason"] == "NAME_NOT_BOUND"


def test_a_deny_set_answer_is_dropped(tmp_path: Path) -> None:
    stub = Stub({"bound.example": ["169.254.169.254"]})
    forwarder = _forwarder(tmp_path, _policy(), stub)
    rcode, addresses = _answer(forwarder, "bound.example")
    assert rcode == dns_wire.RCODE_NXDOMAIN and addresses == []
    record = _audit(tmp_path)[-1]
    assert record["reason"] == "NO_ADDRESS_ALLOWED"
    assert record["dropped"] == ["169.254.169.254"]


def test_a_target_name_never_answers_outside_the_signed_addresses(tmp_path: Path) -> None:
    # The resolver says the name moved; the task signed one address, so DNS says nothing else.
    stub = Stub({"bound.example": [TARGET, "198.51.100.8"]})
    forwarder = _forwarder(tmp_path, _policy(), stub)
    rcode, addresses = _answer(forwarder, "bound.example")
    assert rcode == dns_wire.RCODE_NOERROR
    assert addresses == [TARGET]
    assert _audit(tmp_path)[-1]["dropped"] == ["198.51.100.8"]


def test_a_private_target_name_answers_only_when_the_campaign_targets_it(tmp_path: Path) -> None:
    private_target = "10.1.2.3"
    signed = _policy(
        names=("internal.example",),
        target_names=("internal.example",),
        targets=(private_target,),
    )
    stub = Stub({"internal.example": [private_target]})
    rcode, addresses = _answer(_forwarder(tmp_path, signed, stub), "internal.example")
    assert rcode == dns_wire.RCODE_NOERROR and addresses == [private_target]

    not_targeted = _policy(
        names=("other.example",), target_names=("other.example",), targets=(TARGET,)
    )
    stub = Stub({"other.example": [private_target]})
    rcode, addresses = _answer(_forwarder(tmp_path, not_targeted, stub), "other.example")
    assert rcode == dns_wire.RCODE_NXDOMAIN and addresses == []


def test_a_declared_source_name_resolves_but_is_not_a_target(tmp_path: Path) -> None:
    stub = Stub({"crt.sh": ["93.184.216.34"]})
    policy = _policy(names=("crt.sh",), target_names=("bound.example",), targets=(TARGET,))
    rcode, addresses = _answer(_forwarder(tmp_path, policy, stub), "crt.sh")
    assert rcode == dns_wire.RCODE_NOERROR and addresses == ["93.184.216.34"]


def test_an_unresolvable_name_is_servfail(tmp_path: Path) -> None:
    forwarder = _forwarder(tmp_path, _policy(), Stub({}))
    rcode, _addresses = _answer(forwarder, "bound.example")
    # An empty answer is "no address allowed" (NXDOMAIN) and is audited as such.
    assert rcode == dns_wire.RCODE_NXDOMAIN
    assert _audit(tmp_path)[-1]["reason"] == "NO_ADDRESS_ALLOWED"


def test_another_qtype_is_not_implemented(tmp_path: Path) -> None:
    forwarder = _forwarder(tmp_path, _policy(), Stub({}))
    rcode, _addresses = _answer(forwarder, "bound.example", qtype=15)
    assert rcode == dns_wire.RCODE_NOTIMP
    assert _audit(tmp_path)[-1]["reason"] == "QTYPE_UNSUPPORTED"


def test_a_malformed_packet_gets_formerr_and_no_audit(tmp_path: Path) -> None:
    forwarder = _forwarder(tmp_path, _policy(), Stub({}))
    reply = forwarder.handle(struct.pack("!HHHHHH", 5, 0x0100, 0, 0, 0, 0))
    assert reply is not None
    _qid, flags, *_ = struct.unpack_from("!HHHHHH", reply)
    assert flags & 0x000F == dns_wire.RCODE_FORMERR
    assert _audit(tmp_path) == []


def test_udp_and_tcp_servers_answer_the_same_decision(tmp_path: Path) -> None:
    stub = Stub({"bound.example": [TARGET]})
    forwarder = _forwarder(tmp_path, _policy(), stub)
    udp = broker_mod._DnsUdpServer(("127.0.0.1", 0), forwarder)
    tcp = broker_mod._DnsTcpServer(("127.0.0.1", 0), forwarder)
    threads = [
        threading.Thread(target=udp.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True),
        threading.Thread(target=tcp.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        query = _query("bound.example", qid=11)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(5.0)
            client.sendto(query, udp.server_address)
            udp_reply, _ = client.recvfrom(4096)
        tcp_address = (str(tcp.server_address[0]), int(tcp.server_address[1]))
        with socket.create_connection(tcp_address, timeout=5.0) as client:
            client.sendall(struct.pack("!H", len(query)) + query)
            (length,) = struct.unpack("!H", client.recv(2))
            tcp_reply = b""
            while len(tcp_reply) < length:
                tcp_reply += client.recv(length - len(tcp_reply))
        assert dns_wire.parse_addresses(udp_reply) == [TARGET]
        assert dns_wire.parse_addresses(tcp_reply) == [TARGET]
        assert len(_audit(tmp_path)) == 2
    finally:
        for server in (udp, tcp):
            server.shutdown()
            server.server_close()


def test_the_upstream_resolver_parses_a_fake_dns_server() -> None:
    """The `--dns-upstream` client: one UDP server answering A records, no system resolver."""

    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            data, sock = self.request
            question = dns_wire.parse_question(data)
            sock.sendto(dns_wire.build_response(question, [TARGET]), self.client_address)

    class Server(socketserver.UDPServer):
        allow_reuse_address = True

    with Server(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )
        thread.start()
        try:
            resolver = dns_wire.UpstreamResolver("127.0.0.1", int(server.server_address[1]))
            assert set(resolver("bound.example")) == {TARGET}
        finally:
            server.shutdown()
            server.server_close()
