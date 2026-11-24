"""Per-job egress broker (M06; S1.5a §Sandbox): HTTP CONNECT, plain HTTP and SOCKS5.

The job container has one reachable peer on its internal network: this process at a fixed
address. Every connection is decided by `netpolicy.decide` in the control plane, so the resolve,
the whole-answer check, the pin to the checked address and the audit record all happen where the
job cannot rewrite them.

Denials carry a stable reason code in the body (`{"decision":"deny","reason":"DENY_LOOPBACK"}`)
and one JSON line in the audit file. A redirect is simply the next request through the proxy, so
it is checked again; there is no bypass path.

Standard library only: the broker image ships `aegis/m06_runner/{denyset,netpolicy,broker}.py`
and nothing else.

Run it as a container next to the job::

    python -m aegis.m06_runner.broker --policy /policy.json --audit /audit/egress.jsonl
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import select
import signal
import socket
import socketserver
import sys
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from aegis.m06_runner import netpolicy

MAX_HEADER_BYTES = 64 * 1024
HANDSHAKE_TIMEOUT_SECONDS = 30.0
RELAY_CHUNK = 64 * 1024
IDLE_RELAY_SECONDS = 60.0
DENY_STATUS = "403 Forbidden"


class AuditLog:
    """One JSON line per decision, flushed per line: an audit line is evidence, not a buffer."""

    def __init__(self, path: Path, job_id: str) -> None:
        self.path = path
        self.job_id = job_id
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, decision: netpolicy.Decision) -> None:
        record: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "job_id": self.job_id,
            **decision.as_audit(),
        }
        line = json.dumps(record, sort_keys=True) + "\n"
        with self._lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())


def _deny_response(decision: netpolicy.Decision) -> bytes:
    body = json.dumps(decision.as_audit(), sort_keys=True).encode("utf-8")
    head = (
        f"HTTP/1.1 {DENY_STATUS}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    return head + body


def _read_head(conn: socket.socket) -> bytes | None:
    """Read up to and including the blank line; None on EOF/oversize."""
    buffer = bytearray()
    while b"\r\n\r\n" not in buffer:
        if len(buffer) > MAX_HEADER_BYTES:
            return None
        chunk = conn.recv(4096)
        if not chunk:
            return None
        buffer.extend(chunk)
    return bytes(buffer)


def _relay(left: socket.socket, right: socket.socket) -> None:
    """Pipe both directions until both are closed (half-close aware)."""
    peers = {left: right, right: left}
    open_sockets = [left, right]
    while open_sockets:
        readable, _, _ = select.select(open_sockets, [], [], IDLE_RELAY_SECONDS)
        if not readable:
            return
        for source in readable:
            try:
                data = source.recv(RELAY_CHUNK)
            except OSError:
                data = b""
            if not data:
                open_sockets.remove(source)
                try:
                    peers[source].shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                continue
            try:
                peers[source].sendall(data)
            except OSError:
                return


def _connect(address: str, port: int, timeout: float = HANDSHAKE_TIMEOUT_SECONDS) -> socket.socket:
    return socket.create_connection((address, port), timeout=timeout)


@dataclass(frozen=True)
class _Target:
    host: str
    port: int


def _parse_authority(authority: str, default_port: int) -> _Target | None:
    """`host:port`, a bare host or a bracketed IPv6 authority, as a proxy request carries it."""
    text = authority.strip()
    if not text:
        return None
    port_text = ""
    if text.startswith("["):
        end = text.find("]")
        if end < 0:
            return None
        host = text[1:end]
        rest = text[end + 1 :]
        if rest and not rest.startswith(":"):
            return None
        port_text = rest[1:]
    else:
        head, separator, tail = text.rpartition(":")
        if separator and tail.isdigit():
            host, port_text = head, tail
        else:
            host = text
    if not host or (port_text and not port_text.isdigit()):
        return None
    port = int(port_text) if port_text else default_port
    if not 1 <= port <= 65535:
        return None
    return _Target(host, port)


def _origin_form(target: str) -> str:
    """`http://host:port/path?query` -> `/path?query` for the upstream request line."""
    _, _, rest = target.partition("://")
    slash = rest.find("/")
    return rest[slash:] if slash >= 0 else "/"


class EgressBroker:
    """Decision + dialling shared by both front ends."""

    def __init__(self, policy: netpolicy.JobEgressPolicy, audit: AuditLog) -> None:
        self.policy = policy
        self.audit = audit

    def decide(self, host: str, port: int) -> netpolicy.Decision:
        decision = netpolicy.decide(self.policy, host, port)
        self.audit.write(decision)
        return decision

    def dial(self, decision: netpolicy.Decision) -> socket.socket | None:
        if decision.pinned is None:
            return None
        try:
            return _connect(decision.pinned, decision.port)
        except OSError:
            return None


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], broker: EgressBroker) -> None:
        super().__init__(address, _Handler)
        self.broker = broker


class _Handler(socketserver.BaseRequestHandler):
    """One connection: SOCKS5 when the first byte is 0x05, otherwise the HTTP proxy."""

    def handle(self) -> None:
        conn: socket.socket = self.request
        conn.settimeout(HANDSHAKE_TIMEOUT_SECONDS)
        try:
            first = conn.recv(1, socket.MSG_PEEK)
        except OSError:
            return
        if not first:
            return
        broker = cast(_Server, self.server).broker
        try:
            if first == b"\x05":
                _socks5(conn, broker)
            else:
                _http(conn, broker)
        except OSError:
            return  # a client that hangs up mid-handshake is not a broker failure


def _http(conn: socket.socket, broker: EgressBroker) -> None:
    head = _read_head(conn)
    if head is None:
        return
    lines = head.split(b"\r\n")
    try:
        method_b, target_b, version_b = lines[0].split(b" ")
    except ValueError:
        conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
        return
    method = method_b.decode("ascii", "replace").upper()
    target = target_b.decode("ascii", "replace")
    version = version_b.decode("ascii", "replace") or "HTTP/1.1"
    if method == "CONNECT":
        upstream_target: str | None = None
        parsed = _parse_authority(target, 443)
    else:
        upstream_target = _origin_form(target)
        host_port = target.partition("://")[2].split("/", 1)[0]
        parsed = _parse_authority(host_port, 80)
    if parsed is None:
        conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
        return

    decision = broker.decide(parsed.host, parsed.port)
    if not decision.allowed:
        conn.sendall(_deny_response(decision))
        return
    upstream = broker.dial(decision)
    if upstream is None:
        conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        return
    with upstream:
        if method == "CONNECT":
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            conn.settimeout(None)
            upstream.settimeout(None)
            _relay(conn, upstream)
            return
        headers = [
            line
            for line in lines[1:]
            if line and not line.lower().startswith((b"proxy-", b"connection:"))
        ]
        request = (
            f"{method} {upstream_target} {version}\r\n".encode("ascii", "replace")
            + b"\r\n".join(headers)
            + b"\r\n\r\n"
        )
        upstream.sendall(request)
        conn.settimeout(None)
        upstream.settimeout(None)
        _relay(conn, upstream)


def _socks5(conn: socket.socket, broker: EgressBroker) -> None:
    greeting = conn.recv(2)
    if len(greeting) != 2 or greeting[0] != 5:
        return
    methods = conn.recv(greeting[1])
    if not methods:
        return
    conn.sendall(b"\x05\x00")  # no authentication offered or required
    header = conn.recv(4)
    if len(header) != 4:
        return
    _, command, _, address_type = header
    if command != 0x01:  # CONNECT only
        conn.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        return
    host = _read_socks_address(conn, address_type)
    if host is None:
        conn.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
        return
    port_bytes = conn.recv(2)
    if len(port_bytes) != 2:
        return
    port = int.from_bytes(port_bytes, "big")
    decision = broker.decide(host, port)
    if not decision.allowed:
        conn.sendall(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
        return
    upstream = broker.dial(decision)
    if upstream is None:
        conn.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
        return
    with upstream:
        bind_host, bind_port = upstream.getsockname()[:2]
        reply = b"\x05\x00\x00\x01" + ipaddress.IPv4Address(str(bind_host)).packed
        conn.sendall(reply + int(bind_port).to_bytes(2, "big"))
        conn.settimeout(None)
        upstream.settimeout(None)
        _relay(conn, upstream)


def _read_socks_address(conn: socket.socket, address_type: int) -> str | None:
    if address_type == 0x01:
        raw = conn.recv(4)
        return str(ipaddress.IPv4Address(raw)) if len(raw) == 4 else None
    if address_type == 0x04:
        raw = conn.recv(16)
        return str(ipaddress.IPv6Address(raw)) if len(raw) == 16 else None
    if address_type == 0x03:
        length = conn.recv(1)
        if len(length) != 1:
            return None
        raw = conn.recv(length[0])
        return raw.decode("idna", "replace") if len(raw) == length[0] else None
    return None


def serve(
    policy: netpolicy.JobEgressPolicy,
    audit: AuditLog,
    *,
    http_port: int,
    socks_port: int,
    bind: str,
) -> None:
    broker = EgressBroker(policy, audit)
    servers = [
        _Server((bind, http_port), broker),
        _Server((bind, socks_port), broker),
    ]
    stop = threading.Event()

    def _signal(_signum: int, _frame: object) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, _signal)
    signal.signal(signal.SIGINT, _signal)
    for server in servers:
        threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True
        ).start()
    print(
        f"READY http={bind}:{http_port} socks={bind}:{socks_port} job={policy.job_id}",
        flush=True,
    )
    stop.wait()
    for server in servers:
        server.shutdown()
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AEGIS per-job egress broker")
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--audit", required=True, type=Path)
    parser.add_argument("--http-port", type=int, default=3128)
    parser.add_argument("--socks-port", type=int, default=1080)
    parser.add_argument("--bind", default="0.0.0.0")
    args = parser.parse_args(argv)
    policy = netpolicy.load_policy(json.loads(args.policy.read_text(encoding="utf-8")))
    started = time.monotonic()
    serve(
        policy,
        AuditLog(args.audit, policy.job_id),
        http_port=args.http_port,
        socks_port=args.socks_port,
        bind=args.bind,
    )
    print(f"stopped after {time.monotonic() - started:.2f}s", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
