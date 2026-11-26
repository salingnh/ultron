"""The CNAME lookup of the signing guardrail (F3 guardrail 2) against a local fake resolver.

R5 made "the lookup raised" fail closed; R5b (re-verification 2) found the parser still dropped the
DNS **rcode**, so an answered SERVFAIL/REFUSED - or an NXDOMAIN mid-chain - read as "no CNAME" and
the target was signed. These are wire tests: a real UDP socket on 127.0.0.1 serves crafted
responses, `cname_chain` parses them, and M05's guardrail maps the raise to
`target_cname_lookup_failed`.

No real DNS leaves the host: the fake resolver is a loopback datagram socket on an ephemeral port
(and the conftest guard refuses the system resolver and port 53 anyway).
"""

from __future__ import annotations

import socket
import struct
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field

import pytest

from aegis.common import dns_cname
from aegis.m05_registry import egress
from aegis.m05_registry.errors import M05Error

from . import m06_support

TYPE_CNAME = 5
CLASS_IN = 1
NOERROR = 0
SERVFAIL = 2
NXDOMAIN = 3
REFUSED = 5
#: The real implementation, captured before any test monkeypatches the module attribute (the fake
#: resolver and the M05 guardrail share it, so the wire parser is always the code under test).
REAL_CNAME_CHAIN = dns_cname.cname_chain


@dataclass
class FakeDns:
    """One scripted UDP responder: `answers[name]` is a `(rcode, cname_target | None)` pair.

    An unknown name gets NXDOMAIN, the answer a resolver gives. `wrong_qid` makes the response
    carry another id (`qid ^ 0xFFFF`), which the client must refuse.
    """

    answers: dict[str, tuple[int, str | None]] = field(default_factory=dict)
    wrong_qid: bool = False
    asked: list[str] = field(default_factory=list)
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

    def chain(self, name: str) -> tuple[str, ...]:
        return REAL_CNAME_CHAIN(name, resolver="127.0.0.1", port=self.port, timeout=2.0)

    def _serve(self) -> None:
        while True:
            try:
                data, address = self._sock.recvfrom(4096)
            except OSError:
                return
            asked, _ = dns_cname._read_name(data, 12)
            self.asked.append(asked)
            rcode, target = self.answers.get(asked.strip(".").lower(), (NXDOMAIN, None))
            self._sock.sendto(self._response(data, rcode, target), address)

    def _response(self, query: bytes, rcode: int, target: str | None) -> bytes:
        qid = struct.unpack_from("!H", query)[0]
        if self.wrong_qid:
            qid ^= 0xFFFF
        question = query[12:]
        flags = 0x8180 | rcode
        if target is None:
            return struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0) + question
        encoded = b"".join(bytes([len(label)]) + label.encode() for label in target.split("."))
        record = b"\xc0\x0c" + struct.pack("!HHIH", TYPE_CNAME, CLASS_IN, 60, len(encoded) + 1)
        return (
            struct.pack("!HHHHHH", qid, flags, 1, 1, 0, 0) + question + record + encoded + b"\x00"
        )

    def close(self) -> None:
        self._sock.close()


@pytest.fixture()
def fake_dns() -> Iterator[FakeDns]:
    server = FakeDns()
    try:
        yield server
    finally:
        server.close()


def test_the_chain_follows_a_cname(fake_dns: FakeDns) -> None:
    fake_dns.answers["www.icomm.vn"] = (NOERROR, "edge.cloudflare.net")
    fake_dns.answers["edge.cloudflare.net"] = (NOERROR, None)
    assert fake_dns.chain("www.icomm.vn") == ("edge.cloudflare.net",)
    assert fake_dns.asked == ["www.icomm.vn", "edge.cloudflare.net"]


def test_a_name_without_a_cname_has_an_empty_chain(fake_dns: FakeDns) -> None:
    fake_dns.answers["www.icomm.vn"] = (NOERROR, None)
    assert fake_dns.chain("www.icomm.vn") == ()


def test_a_servfail_answer_raises(fake_dns: FakeDns) -> None:
    fake_dns.answers["flaky.icomm.vn"] = (SERVFAIL, None)
    with pytest.raises(ValueError, match="SERVFAIL"):
        fake_dns.chain("flaky.icomm.vn")


def test_a_refused_answer_raises(fake_dns: FakeDns) -> None:
    fake_dns.answers["lame.icomm.vn"] = (REFUSED, None)
    with pytest.raises(ValueError, match="REFUSED"):
        fake_dns.chain("lame.icomm.vn")


def test_a_mid_chain_servfail_raises(fake_dns: FakeDns) -> None:
    # The first hop answered, the second did not: the rest of the chain is unknown, so refuse.
    fake_dns.answers["mid.icomm.vn"] = (NOERROR, "servfail.icomm.vn")
    fake_dns.answers["servfail.icomm.vn"] = (SERVFAIL, None)
    with pytest.raises(ValueError, match="SERVFAIL"):
        fake_dns.chain("mid.icomm.vn")


def test_a_first_hop_nxdomain_is_an_empty_chain(fake_dns: FakeDns) -> None:
    # The name does not exist; there is no chain to check (and its address lookup fails on its own).
    fake_dns.answers["gone.icomm.vn"] = (NXDOMAIN, None)
    assert fake_dns.chain("gone.icomm.vn") == ()


def test_a_mid_chain_nxdomain_raises(fake_dns: FakeDns) -> None:
    fake_dns.answers["mid.icomm.vn"] = (NOERROR, "gone.icomm.vn")
    fake_dns.answers["gone.icomm.vn"] = (NXDOMAIN, None)
    with pytest.raises(ValueError, match="breaks at 'gone.icomm.vn'"):
        fake_dns.chain("mid.icomm.vn")


def test_a_response_for_another_query_raises(fake_dns: FakeDns) -> None:
    fake_dns.answers["www.icomm.vn"] = (NOERROR, None)
    fake_dns.wrong_qid = True
    with pytest.raises(ValueError, match="qid"):
        fake_dns.chain("www.icomm.vn")


# --- the guardrail on top of the parser: M05 refuses, it never signs ----------------------------


def _binding_with_fake_dns(monkeypatch: pytest.MonkeyPatch, fake_dns: FakeDns, host: str) -> None:
    monkeypatch.setattr(
        dns_cname,
        "cname_chain",
        lambda name: fake_dns.chain(name),
    )
    record = m06_support.record("manifest.naabu.yaml")
    egress.build_egress_binding(
        record,
        merged_input={"ports": [443]},
        targets=m06_support.resolved_targets(record, [f"dns:{host}"]),
        binder=m06_support.StaticBinder({host: ["203.0.113.7"]}),
        network_profile="internet",
        authorized_suffixes=("icomm.vn",),
    )


@pytest.mark.parametrize(
    "answer",
    [(SERVFAIL, None), (REFUSED, None)],
    ids=["servfail", "refused"],
)
def test_m05_refuses_a_target_whose_cname_query_errors(
    monkeypatch: pytest.MonkeyPatch, fake_dns: FakeDns, answer: tuple[int, str | None]
) -> None:
    host = "www.icomm.vn"
    fake_dns.answers[host] = answer
    with pytest.raises(M05Error) as caught:
        _binding_with_fake_dns(monkeypatch, fake_dns, host)
    assert caught.value.refusal.rule == "target_cname_lookup_failed"


def test_m05_refuses_a_target_whose_cname_chain_breaks_mid_way(
    monkeypatch: pytest.MonkeyPatch, fake_dns: FakeDns
) -> None:
    fake_dns.answers["www.icomm.vn"] = (NOERROR, "servfail.icomm.vn")
    fake_dns.answers["servfail.icomm.vn"] = (SERVFAIL, None)
    with pytest.raises(M05Error) as caught:
        _binding_with_fake_dns(monkeypatch, fake_dns, "www.icomm.vn")
    assert caught.value.refusal.rule == "target_cname_lookup_failed"
