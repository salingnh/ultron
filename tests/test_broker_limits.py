"""The internet-profile broker: deny set, binding, safety caps and audit (G1.6).

CI has no internet, so the "upstream" here is a fake: a local TCP server and a patched
`broker._connect` that records the address the broker decided to dial. Everything else - the
resolve, the whole-answer check, the pin, the host caps and the audit line - is the real code path,
and a deny is proven by the fake upstream never being dialled.

Both front ends are exercised: HTTP CONNECT (what Subfinder/httpx use through `HTTPS_PROXY`) and
SOCKS5 (what Naabu uses with `-proxy host:port`).
"""

from __future__ import annotations

import ipaddress
import json
import socket
import socketserver
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from aegis.m06_runner import broker as broker_mod
from aegis.m06_runner import netpolicy
from aegis.m06_runner.netpolicy import JobEgressPolicy, Resolver, SourceAllow

PRIVATE = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
AUTHORIZATION = "owner, item 61, 2026-11-25"
ACCEPTED = b"HTTP/1.1 200"


class Stub(Resolver):
    def __init__(self, answers: dict[str, list[str]]) -> None:
        self.answers = answers

    def resolve(self, host: str) -> list[str]:
        return list(self.answers.get(host, []))


class _UpstreamHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.sendall(b"REACHED\n")
        while True:
            try:
                data = self.request.recv(4096)
            except OSError:
                return
            if not data:
                return
            try:
                self.request.sendall(data)
            except OSError:
                return


class FakeUpstream:
    """A local TCP server plus the fake dial: the broker's chosen address is recorded, not used."""

    def __init__(self) -> None:
        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _UpstreamHandler)
        self.server.daemon_threads = True
        self.port = int(self.server.server_address[1])
        self.dialled: list[tuple[str, int]] = []
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def connect(self, address: str, port: int, timeout: float = 30.0) -> socket.socket:
        self.dialled.append((address, port))
        return socket.create_connection(("127.0.0.1", self.port), timeout=timeout)

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def _policy(
    *,
    sources: tuple[SourceAllow, ...] | None = None,
    target_addresses: tuple[str, ...] = (),
    target_ports: tuple[int, ...] = (),
    resolver: Resolver | None = None,
    profile: str = "internet",
    rps: float | None = 10.0,
    max_connections: int | None = 8,
) -> JobEgressPolicy:
    return JobEgressPolicy(
        job_id="job-1",
        profile=profile,
        campaign_id="01934f6a-0000-7000-8000-000000000001",
        authorization=AUTHORIZATION,
        sources=sources
        if sources is not None
        else (SourceAllow(id="crtsh", hosts=("crt.sh",), ports=(443,)),),
        target_ips=tuple(
            ipaddress.ip_network(f"{address}/{ipaddress.ip_address(address).max_prefixlen}")
            for address in target_addresses
        ),
        target_ports=target_ports,
        private_cidrs=tuple(ipaddress.ip_network(entry) for entry in PRIVATE),
        per_host_rps=rps,
        per_host_max_connections=max_connections,
        resolver=resolver,
    )


@contextmanager
def running_broker(
    policy: JobEgressPolicy,
    tmp_path: Path,
    upstream: FakeUpstream,
    monkeypatch: pytest.MonkeyPatch,
    *,
    limiter: broker_mod.HostLimiter | None = None,
) -> Iterator[tuple[int, broker_mod.AuditLog]]:
    monkeypatch.setattr(broker_mod, "_connect", upstream.connect)
    audit = broker_mod.AuditLog(
        tmp_path / "egress.jsonl",
        policy.job_id,
        profile=policy.profile,
        campaign_id=policy.campaign_id,
        authorization=policy.authorization,
    )
    broker = broker_mod.EgressBroker(policy, audit, limiter=limiter)
    server = broker_mod._Server(("127.0.0.1", 0), broker)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
    )
    thread.start()
    try:
        yield int(server.server_address[1]), audit
    finally:
        server.shutdown()
        server.server_close()


def _connect(port: int, authority: str) -> tuple[socket.socket, bytes]:
    client = socket.create_connection(("127.0.0.1", port), timeout=5.0)
    client.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = client.recv(4096)
        if not chunk:
            break
        head += chunk
    return client, head


def _reason(head: bytes) -> str | None:
    _, _, body = head.partition(b"\r\n\r\n")
    return json.loads(body)["reason"] if body else None


def _socks5(port: int, host: str, target_port: int) -> bytes:
    client = socket.create_connection(("127.0.0.1", port), timeout=5.0)
    client.sendall(b"\x05\x01\x00")
    assert client.recv(2) == b"\x05\x00"
    address = socket.inet_aton(host)
    client.sendall(b"\x05\x01\x00" + b"\x01" + address + target_port.to_bytes(2, "big"))
    return client.recv(10)


def test_a_bound_target_is_reached_and_audited_with_its_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    upstream = FakeUpstream()
    policy = _policy(resolver=Stub({"crt.sh": ["93.184.216.34"]}))
    try:
        with running_broker(policy, tmp_path, upstream, monkeypatch) as (port, audit):
            client, head = _connect(port, "crt.sh:443")
            assert head.startswith(ACCEPTED), head
            assert client.recv(4096).startswith(b"REACHED")
            client.close()
    finally:
        upstream.close()
    assert upstream.dialled == [("93.184.216.34", 443)]
    record = json.loads((tmp_path / "egress.jsonl").read_text().splitlines()[0])
    assert record["decision"] == "allow"
    assert record["network_profile"] == "internet"
    assert record["campaign_id"] == policy.campaign_id
    assert record["authorization"] == AUTHORIZATION
    assert record["pinned"] == "93.184.216.34"


@pytest.mark.parametrize(
    ("authority", "reason"),
    [
        ("169.254.169.254:80", "DENY_METADATA"),
        ("127.0.0.1:443", "DENY_LOOPBACK"),
        ("[::1]:443", "DENY_LOOPBACK"),
        ("2130706433:443", "DENY_LOOPBACK"),
    ],
)
def test_the_deny_set_is_refused_and_never_dialled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    authority: str,
    reason: str,
) -> None:
    upstream = FakeUpstream()
    policy = _policy()
    try:
        with running_broker(policy, tmp_path, upstream, monkeypatch) as (port, _audit):
            client, head = _connect(port, authority)
            assert head.startswith(b"HTTP/1.1 403"), head
            assert _reason(head) == reason
            client.close()
    finally:
        upstream.close()
    assert upstream.dialled == []


def test_an_unbound_destination_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    upstream = FakeUpstream()
    # Source-bound job: only the declared host:port is reachable.
    policy = _policy(
        resolver=Stub({"crt.sh": ["93.184.216.34"], "evil.example": ["93.184.216.34"]})
    )
    try:
        with running_broker(policy, tmp_path, upstream, monkeypatch) as (port, _audit):
            client, head = _connect(port, "evil.example:443")
            assert head.startswith(b"HTTP/1.1 403"), head
            assert _reason(head) == "PORT_NOT_ALLOWED"
            client.close()
    finally:
        upstream.close()
    assert upstream.dialled == []


def test_a_target_bound_job_refuses_an_address_outside_the_signed_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    upstream = FakeUpstream()
    policy = _policy(
        sources=(SourceAllow(id="target", hosts=("10.1.2.3",), ports=(8080,)),),
        target_addresses=("10.1.2.3",),
        target_ports=(8080,),
        resolver=Stub({}),
    )
    try:
        with running_broker(policy, tmp_path, upstream, monkeypatch) as (port, _audit):
            client, head = _connect(port, "93.184.216.35:8080")
            assert head.startswith(b"HTTP/1.1 403"), head
            assert _reason(head) == "NOT_BOUND_TO_JOB"
            client.close()
            # The signed address itself is reachable (the campaign targets it, even though it is
            # in a private range).
            client, head = _connect(port, "10.1.2.3:8080")
            assert head.startswith(ACCEPTED), head
            client.close()
    finally:
        upstream.close()
    assert upstream.dialled == [("10.1.2.3", 8080)]


def test_a_private_address_the_campaign_did_not_target_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    upstream = FakeUpstream()
    policy = _policy(
        resolver=Stub({"intranet.example": ["10.0.0.9"]}),
        sources=(SourceAllow(id="intranet", hosts=("intranet.example",), ports=(443,)),),
    )
    try:
        with running_broker(policy, tmp_path, upstream, monkeypatch) as (port, _audit):
            client, head = _connect(port, "intranet.example:443")
            assert head.startswith(b"HTTP/1.1 403"), head
            assert _reason(head) == "DENY_PRIVATE"
            client.close()
    finally:
        upstream.close()
    assert upstream.dialled == []


def test_the_per_host_rate_cap_paces_and_times_out_after_a_bounded_wait(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    upstream = FakeUpstream()
    clock = [1000.0]

    def now() -> float:
        return clock[0]

    policy = _policy(resolver=Stub({"crt.sh": ["93.184.216.34"]}), rps=1.0)
    # A short bounded wait keeps the test fast; the production wait is 10 s.
    limiter = broker_mod.HostLimiter(
        rate_per_second=1.0, max_connections=None, now=now, max_wait_seconds=0.1
    )
    try:
        with running_broker(policy, tmp_path, upstream, monkeypatch, limiter=limiter) as (
            port,
            _audit,
        ):
            client, head = _connect(port, "crt.sh:443")
            assert head.startswith(ACCEPTED), head
            client.close()
            client, head = _connect(port, "crt.sh:443")
            assert _reason(head) == "RATE_LIMITED"
            client.close()
            # A different host has its own bucket: the cap is per host, not per job.
            other = _policy(
                resolver=Stub({"otx.alienvault.com": ["93.184.216.34"]}),
                sources=(
                    SourceAllow(id="crtsh", hosts=("crt.sh",), ports=(443,)),
                    SourceAllow(id="otx", hosts=("otx.alienvault.com",), ports=(443,)),
                ),
            )
            assert netpolicy.decide(other, "otx.alienvault.com", 443).allowed
            clock[0] += 1.5
            client, head = _connect(port, "crt.sh:443")
            assert head.startswith(ACCEPTED), head
            client.close()
    finally:
        upstream.close()


def test_the_per_host_connection_cap_counts_open_tunnels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    upstream = FakeUpstream()
    policy = _policy(resolver=Stub({"crt.sh": ["93.184.216.34"]}), rps=None, max_connections=1)
    limiter = broker_mod.HostLimiter(rate_per_second=None, max_connections=1, max_wait_seconds=0.2)
    try:
        with running_broker(policy, tmp_path, upstream, monkeypatch, limiter=limiter) as (
            port,
            _audit,
        ):
            first, head = _connect(port, "crt.sh:443")
            assert head.startswith(ACCEPTED), head
            second, head = _connect(port, "crt.sh:443")
            assert _reason(head) == "CONCURRENCY_LIMITED"
            second.close()
            first.close()
            deadline = time.monotonic() + 5.0
            while True:
                third, head = _connect(port, "crt.sh:443")
                if head.startswith(ACCEPTED):
                    third.close()
                    break
                third.close()
                assert time.monotonic() < deadline, "the released tunnel never freed its slot"
                time.sleep(0.05)
    finally:
        upstream.close()


def test_socks5_uses_the_same_decisions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    upstream = FakeUpstream()
    # Naabu hands the broker an address (`-proxy host:port`), so the binding is the signed target.
    policy = _policy(
        sources=(SourceAllow(id="target", hosts=("10.1.2.3",), ports=(8080,)),),
        target_addresses=("10.1.2.3",),
        target_ports=(8080,),
    )
    try:
        with running_broker(policy, tmp_path, upstream, monkeypatch) as (port, _audit):
            denied = _socks5(port, "169.254.169.254", 80)
            assert denied[:2] == b"\x05\x02", denied
            accepted = _socks5(port, "10.1.2.3", 8080)
            assert accepted[:2] == b"\x05\x00", accepted
    finally:
        upstream.close()
    assert upstream.dialled == [("10.1.2.3", 8080)]


def test_the_limiter_is_per_host_and_refills() -> None:
    clock = [0.0]
    limiter = broker_mod.HostLimiter(
        rate_per_second=2.0,
        max_connections=None,
        now=lambda: clock[0],
        max_wait_seconds=0.01,
    )
    assert limiter.admit("a.example") is None
    assert limiter.admit("a.example") is None
    assert limiter.admit("a.example") == "RATE_LIMITED"
    assert limiter.admit("b.example") is None  # another host, its own bucket
    clock[0] += 0.5  # 2/s refills one token
    assert limiter.admit("a.example") is None
    # The slot counter is released by the connection that took it, and it is per host too.
    slots = broker_mod.HostLimiter(
        rate_per_second=None,
        max_connections=1,
        now=lambda: clock[0],
        max_wait_seconds=0.01,
    )
    assert slots.admit("a.example") is None
    assert slots.admit("a.example") == "CONCURRENCY_LIMITED"
    assert slots.admit("b.example") is None
    slots.release("a.example")
    assert slots.admit("a.example") is None


def test_the_rate_cap_waits_instead_of_refusing() -> None:
    """A scanner reads a refused CONNECT as 'closed': the cap must pace, not fail."""
    clock = [0.0]

    def now() -> float:
        return clock[0]

    limiter = broker_mod.HostLimiter(
        rate_per_second=2.0, max_connections=None, max_wait_seconds=1.0, now=now
    )
    assert limiter.admit("a.example") is None
    assert limiter.admit("a.example") is None
    # The bucket is empty; the next admit waits for a token. Advance the clock in a thread that the
    # condition wait can observe.
    import threading

    def advance() -> None:
        clock[0] += 0.6
        with limiter._changed:
            limiter._changed.notify_all()

    thread = threading.Thread(target=advance)
    thread.start()
    assert limiter.admit("a.example") is None
    thread.join()


def test_the_concurrency_cap_waits_for_a_released_tunnel() -> None:
    limiter = broker_mod.HostLimiter(rate_per_second=None, max_connections=1, max_wait_seconds=1.0)
    assert limiter.admit("a.example") is None
    import threading

    released = threading.Event()

    def release_after_delay() -> None:
        released.wait(0.15)
        limiter.release("a.example")

    thread = threading.Thread(target=release_after_delay)
    thread.start()
    # This call blocks until the tunnel is released; a deny here would be a false 'closed'.
    assert limiter.admit("a.example") is None
    thread.join()


def test_a_cap_that_never_frees_is_a_timeout_deny() -> None:
    limiter = broker_mod.HostLimiter(rate_per_second=None, max_connections=1, max_wait_seconds=0.1)
    assert limiter.admit("a.example") is None
    assert limiter.admit("a.example") == "CONCURRENCY_LIMITED"
    limiter.release("a.example")
    assert limiter.admit("a.example") is None


def test_the_caps_are_keyed_by_the_address_not_the_requested_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F2: 20 names on one address used to open 20 tunnels under a cap of 1."""
    upstream = FakeUpstream()
    resolver = Stub({"a.test": ["93.184.216.34"], "b.test": ["93.184.216.34"]})
    policy = _policy(
        sources=(SourceAllow(id="s1", hosts=("a.test", "b.test"), ports=(443,)),),
        resolver=resolver,
        rps=None,
        max_connections=1,
    )
    limiter = broker_mod.HostLimiter(rate_per_second=None, max_connections=1, max_wait_seconds=0.2)
    try:
        with running_broker(policy, tmp_path, upstream, monkeypatch, limiter=limiter) as (
            port,
            _audit,
        ):
            first, head = _connect(port, "a.test:443")
            assert head.startswith(ACCEPTED)
            second, other = _connect(port, "b.test:443")
            try:
                assert _reason(other) == netpolicy.Reason.CONCURRENCY_LIMITED.value
            finally:
                second.close()
                first.close()
        assert upstream.dialled == [("93.184.216.34", 443)]
    finally:
        upstream.close()


def test_a_plain_http_body_is_forwarded_verbatim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """N1: bytes after the blank line are the body, not headers of the same request."""
    upstream = FakeUpstream()
    policy = _policy(
        sources=(SourceAllow(id="s1", hosts=("crtsh",), ports=(80,)),),
        resolver=Stub({"crtsh": ["93.184.216.34"]}),
    )
    try:
        with running_broker(policy, tmp_path, upstream, monkeypatch) as (port, _audit):
            client = socket.create_connection(("127.0.0.1", port), timeout=5.0)
            client.sendall(
                b"POST http://crtsh/ HTTP/1.1\r\nHost: crtsh\r\nContent-Length: 9\r\n\r\n"
                b"X-Inj: body"
            )
            received = b""
            client.settimeout(2.0)
            while b"X-Inj: body" not in received:
                chunk = client.recv(4096)
                if not chunk:
                    break
                received += chunk
            client.close()
        forwarded = received.partition(b"REACHED\n")[2]
        head, _, body = forwarded.partition(b"\r\n\r\n")
        assert b"X-Inj: body" not in head
        assert body == b"X-Inj: body"
    finally:
        upstream.close()


def _socks5_domain(port: int, host: str, target_port: int) -> bytes:
    client = socket.create_connection(("127.0.0.1", port), timeout=5.0)
    client.sendall(b"\x05\x01\x00")
    assert client.recv(2) == b"\x05\x00"
    encoded = host.encode("idna")
    client.sendall(
        b"\x05\x01\x00\x03" + bytes([len(encoded)]) + encoded + target_port.to_bytes(2, "big")
    )
    return client.recv(10)


def test_socks5_accepts_a_domain_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """N3: ATYP 3 used to raise UnicodeError and the client got no reply at all."""
    upstream = FakeUpstream()
    policy = _policy(
        sources=(SourceAllow(id="target", hosts=("crtsh.test",), ports=(443,)),),
        resolver=Stub({"crtsh.test": ["93.184.216.34"]}),
    )
    try:
        with running_broker(policy, tmp_path, upstream, monkeypatch) as (port, _audit):
            accepted = _socks5_domain(port, "crtsh.test", 443)
            assert accepted[:2] == b"\x05\x00", accepted
            refused = _socks5_domain(port, "other.test", 443)
            assert refused[:2] == b"\x05\x02", refused
    finally:
        upstream.close()
    assert upstream.dialled == [("93.184.216.34", 443)]
