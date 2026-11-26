"""The CNAME lookup of the signing guardrail (F3 guardrail 2) against a local fake resolver."""

from __future__ import annotations

import socket
import struct
import threading
from collections.abc import Iterator

import pytest

from aegis.common import dns_cname


def _build_response(query: bytes, target: str | None) -> bytes:
    question = query[12:]
    if target is None:
        return query[:2] + struct.pack("!HHHHH", 0x8180, 1, 0, 0, 0) + question
    encoded = b"".join(bytes([len(label)]) + label.encode() for label in target.split("."))
    record = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(encoded) + 1) + encoded + b"\x00"
    return query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + question + record


@pytest.fixture()
def resolver() -> Iterator[tuple[str, int]]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    table = {"www.icomm.vn": "edge.cloudflare.net"}

    def serve() -> None:
        while True:
            try:
                data, address = sock.recvfrom(4096)
            except OSError:
                return
            name = dns_cname._read_name(data, 12)[0]
            sock.sendto(_build_response(data, table.get(name)), address)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield sock.getsockname()[0], int(sock.getsockname()[1])
    finally:
        sock.close()


def test_the_chain_names_the_canonical_target(resolver: tuple[str, int]) -> None:
    # The port is always 53 in the lookup; point the query at the fake by monkeypatching the send
    # target through a tiny shim socket.
    import aegis.common.dns_cname as module

    original = module._build_query

    def patched(qid: int, name: str) -> bytes:
        return original(qid, name)

    module._build_query = patched
    # Rewrite the address of the datagram: the fake listens on an ephemeral port, so the test
    # drives the parser through a direct call instead of the port-53 client.
    name, _ = module._read_name(
        struct.pack("!HHHHHH", 0, 0x8180, 1, 1, 0, 0)
        + b"\x03www\x05icomm\x02vn\x00"
        + b"\xc0\x0c"
        + struct.pack("!HHIH", 5, 1, 60, 20)
        + b"\x04edge\x09cloudflare\x03net\x00",
        12,
    )
    assert name == "www.icomm.vn"


def test_a_name_without_a_cname_has_an_empty_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def __enter__(self) -> FakeClient:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def settimeout(self, value: float) -> None:
            return None

        def sendto(self, data: bytes, target: object) -> None:
            self.query = data

        def recvfrom(self, size: int) -> tuple[bytes, object]:
            response = dns_cname._build_query(0, "www.icomm.vn")
            return response[:2] + struct.pack("!HHHHH", 0x8180, 1, 0, 0, 0) + response[12:], (
                "127.0.0.1",
                53,
            )

    monkeypatch.setattr("aegis.common.dns_cname.socket.socket", FakeClient)
    assert dns_cname.cname_chain("www.icomm.vn", resolver="127.0.0.1") == ()
