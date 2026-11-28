"""The `--dns-upstream` reader: an upstream answer is checked before it is read (N7).

The broker trusts its pinned upstream only as far as it can verify the answer belongs to the query
it sent and that the rcode is an answer. Before N7 `UpstreamResolver` read A/AAAA and CNAME records
out of any datagram with the QR bit - a stale or spoofed packet with another id, a SERVFAIL, or a
REFUSED became "no address" / "no CNAME", and the broker turned that into a containment decision.
These are wire tests against a local fake resolver only: a loopback UDP socket on an ephemeral
port, never the host resolver.
"""

from __future__ import annotations

import socket
import struct
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

import pytest

from aegis.m06_runner import dns as dns_wire
from aegis.m06_runner.netpolicy import JobEgressPolicy

NOERROR = dns_wire.RCODE_NOERROR
SERVFAIL = dns_wire.RCODE_SERVFAIL
NXDOMAIN = dns_wire.RCODE_NXDOMAIN
REFUSED = dns_wire.RCODE_REFUSED
TARGET = "198.51.100.7"


@dataclass
class FakeUpstream:
    """A scripted UDP resolver: `answers[(name, qtype)]` is `(rcode, values)`.

    `values` are addresses for A/AAAA and CNAME targets for CNAME. An unscripted question gets
    NXDOMAIN, which is a real resolver's answer for a name it does not know.
    """

    answers: dict[tuple[str, int], tuple[int, list[str]]] = field(default_factory=dict)
    wrong_qid: bool = False
    asked: list[tuple[str, int]] = field(default_factory=list)
    _sock: socket.socket = field(init=False)
    _thread: threading.Thread = field(init=False)

    def __post_init__(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return int(self._sock.getsockname()[1])

    def resolver(self, timeout: float = 2.0) -> dns_wire.UpstreamResolver:
        return dns_wire.UpstreamResolver("127.0.0.1", self.port, timeout=timeout)

    def _serve(self) -> None:
        while True:
            try:
                data, address = self._sock.recvfrom(4096)
            except OSError:
                return
            question = dns_wire.parse_question(data)
            self.asked.append((question.name, question.qtype))
            rcode, values = self.answers.get((question.name, question.qtype), (NXDOMAIN, []))
            if question.qtype == dns_wire.TYPE_CNAME:
                reply = dns_wire.build_cname_response(question, values, rcode=rcode)
            else:
                reply = dns_wire.build_response(question, values, rcode=rcode)
            if self.wrong_qid:
                reply = self._with_qid(reply, question.id ^ 0xFFFF)
            self._sock.sendto(reply, address)

    @staticmethod
    def _with_qid(message: bytes, qid: int) -> bytes:
        return struct.pack("!H", qid) + message[2:]

    def close(self) -> None:
        self._sock.close()


@pytest.fixture()
def fake_upstream() -> Iterator[FakeUpstream]:
    server = FakeUpstream()
    try:
        yield server
    finally:
        server.close()


def _policy(*, names: tuple[str, ...] = ("bound.example",)) -> JobEgressPolicy:
    return JobEgressPolicy(
        job_id="job-1",
        profile="internet",
        campaign_id="01934f6a-0000-7000-8000-000000000001",
        authorization="owner, item 61, 2026-11-25",
        dns_names=names,
        dns_target_names=names,
    )


class Audit:
    def __init__(self) -> None:
        self.lines: list[dict[str, object]] = []

    def write_dns(self, line: dict[str, object]) -> None:
        self.lines.append(line)


def _forwarder(
    policy: JobEgressPolicy, resolver: Callable[[str], list[str]]
) -> tuple[dns_wire.DnsForwarder, Audit]:
    audit = Audit()
    return dns_wire.DnsForwarder(policy, audit, resolver=resolver), audit


def test_a_valid_answer_is_still_read(fake_upstream: FakeUpstream) -> None:
    fake_upstream.answers[("bound.example", dns_wire.TYPE_A)] = (NOERROR, [TARGET])
    assert set(fake_upstream.resolver()("bound.example")) == {TARGET}


def test_an_answer_with_another_qid_is_refused(fake_upstream: FakeUpstream) -> None:
    fake_upstream.wrong_qid = True
    fake_upstream.answers[("bound.example", dns_wire.TYPE_A)] = (NOERROR, [TARGET])
    with pytest.raises(ValueError, match="qid"):
        fake_upstream.resolver()("bound.example")


def test_a_servfail_answer_is_not_an_empty_address_list(fake_upstream: FakeUpstream) -> None:
    fake_upstream.answers[("bound.example", dns_wire.TYPE_A)] = (SERVFAIL, [])
    with pytest.raises(ValueError, match="SERVFAIL"):
        fake_upstream.resolver()("bound.example")


def test_a_refused_answer_is_not_an_empty_address_list(fake_upstream: FakeUpstream) -> None:
    fake_upstream.answers[("bound.example", dns_wire.TYPE_A)] = (REFUSED, [])
    with pytest.raises(ValueError, match="REFUSED"):
        fake_upstream.resolver()("bound.example")


def test_nxdomain_is_an_empty_address_list(fake_upstream: FakeUpstream) -> None:
    fake_upstream.answers[("bound.example", dns_wire.TYPE_A)] = (NXDOMAIN, [])
    fake_upstream.answers[("bound.example", dns_wire.TYPE_AAAA)] = (NXDOMAIN, [])
    assert fake_upstream.resolver()("bound.example") == []


def test_a_cname_answer_with_another_qid_is_refused(fake_upstream: FakeUpstream) -> None:
    fake_upstream.wrong_qid = True
    fake_upstream.answers[("bound.example", dns_wire.TYPE_CNAME)] = (NOERROR, ["edge.example"])
    with pytest.raises(ValueError, match="qid"):
        fake_upstream.resolver().cnames("bound.example")


def test_a_first_hop_nxdomain_has_no_chain(fake_upstream: FakeUpstream) -> None:
    fake_upstream.answers[("bound.example", dns_wire.TYPE_CNAME)] = (NXDOMAIN, [])
    assert fake_upstream.resolver().cnames("bound.example") == []


def test_a_mid_chain_nxdomain_raises(fake_upstream: FakeUpstream) -> None:
    fake_upstream.answers[("bound.example", dns_wire.TYPE_CNAME)] = (NOERROR, ["middle.example"])
    fake_upstream.answers[("middle.example", dns_wire.TYPE_CNAME)] = (NXDOMAIN, [])
    with pytest.raises(ValueError, match="NXDOMAIN"):
        fake_upstream.resolver().cnames("bound.example")


def test_a_mid_chain_servfail_raises(fake_upstream: FakeUpstream) -> None:
    fake_upstream.answers[("bound.example", dns_wire.TYPE_CNAME)] = (NOERROR, ["middle.example"])
    fake_upstream.answers[("middle.example", dns_wire.TYPE_CNAME)] = (SERVFAIL, [])
    with pytest.raises(ValueError, match="SERVFAIL"):
        fake_upstream.resolver().cnames("bound.example")


def test_the_forwarder_turns_a_broken_upstream_answer_into_servfail(
    fake_upstream: FakeUpstream,
) -> None:
    fake_upstream.answers[("bound.example", dns_wire.TYPE_A)] = (SERVFAIL, [])
    forwarder, audit = _forwarder(_policy(), fake_upstream.resolver())
    reply = forwarder.handle(dns_wire.build_query(3, "bound.example", dns_wire.TYPE_A))
    assert reply is not None
    (_qid, flags, _qd, an, _ns, _ar) = struct.unpack_from("!HHHHHH", reply)
    assert flags & 0x000F == SERVFAIL
    assert an == 0
    assert audit.lines[-1]["reason"] == "RESOLVE_FAILED"
    assert audit.lines[-1]["rcode"] == "SERVFAIL"


def test_the_forwarder_never_reads_a_cname_from_another_query(
    fake_upstream: FakeUpstream,
) -> None:
    fake_upstream.wrong_qid = True
    fake_upstream.answers[("bound.example", dns_wire.TYPE_CNAME)] = (NOERROR, ["edge.example"])
    forwarder, audit = _forwarder(_policy(), fake_upstream.resolver())
    reply = forwarder.handle(dns_wire.build_query(4, "bound.example", dns_wire.TYPE_CNAME))
    assert reply is not None
    (_qid, flags, _qd, an, _ns, _ar) = struct.unpack_from("!HHHHHH", reply)
    assert flags & 0x000F == SERVFAIL and an == 0
    assert audit.lines[-1]["reason"] == "RESOLVE_FAILED"
