"""Per-job egress broker (spike G0.2).

The job container sits on an internal Podman network whose only reachable
peer is this broker; the broker is dual-homed on the execution uplink. Every
connection the tool makes is therefore terminated here and checked by
:mod:`aegis_g02.netpolicy` before any socket is opened:

* ``HTTPS_PROXY``/``HTTP_PROXY`` style CONNECT tunnels (subfinder, httpx, BBOT
  HTTP modules, DNSx over DoH),
* plain HTTP with an absolute-URI request line (redirect re-check happens
  naturally: each hop is a new request and is decided again),
* SOCKS5 CONNECT (``naabu -proxy socks5://...`` with connect scan).

Connection pinning: the broker resolves in the control plane, checks every
answer, then connects to the checked IPv4/IPv6 address, never to a fresh
lookup. A denied decision never opens a socket and is written to the audit log
with a stable reason code.

Run: python3 -m aegis_g02.egress_broker --policy job.json --audit audit.jsonl
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import struct
import sys
import threading
import time
from pathlib import Path

from . import netpolicy

MAX_HEAD = 64 * 1024
CONNECT_TIMEOUT = 10.0
PUMP_TIMEOUT = 120.0


class Audit:
    def __init__(self, path: Path | None, job_id: str):
        self._path = path
        self._job_id = job_id
        self._lock = threading.Lock()
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch(exist_ok=True)

    def write(self, proto: str, decision: netpolicy.Decision) -> None:
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "job_id": self._job_id,
            "proto": proto,
            **decision.as_audit(),
        }
        line = json.dumps(record, sort_keys=True)
        with self._lock:
            if self._path is not None:
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            print(line, file=sys.stderr, flush=True)


class Broker:
    def __init__(self, policy: netpolicy.JobEgressPolicy, audit: Audit):
        self.policy = policy
        self.audit = audit
        self.resolver = netpolicy.Resolver()

    # -- helpers ---------------------------------------------------------
    def decide(self, proto: str, host: str, port: int) -> netpolicy.Decision:
        decision = netpolicy.decide(self.policy, host, port, resolver=self.resolver)
        self.audit.write(proto, decision)
        return decision

    @staticmethod
    def _pinned_socket(decision: netpolicy.Decision) -> socket.socket:
        addr = ipaddress.ip_address(decision.pinned)
        family = socket.AF_INET6 if addr.version == 6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)
        sock.connect((str(addr), decision.port))
        return sock

    @staticmethod
    def _pump(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                chunk = src.recv(65536)
                if not chunk:
                    break
                dst.sendall(chunk)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def tunnel(self, client: socket.socket, upstream: socket.socket) -> None:
        t = threading.Thread(target=self._pump, args=(client, upstream), daemon=True)
        t.start()
        self._pump(upstream, client)
        t.join(timeout=1.0)

    # -- HTTP proxy ------------------------------------------------------
    def handle_http(self, client: socket.socket) -> None:
        data = b""
        while b"\r\n\r\n" not in data and len(data) < MAX_HEAD:
            chunk = client.recv(4096)
            if not chunk:
                return
            data += chunk
        if not data:
            return
        head, _, rest = data.partition(b"\r\n\r\n")
        line = head.split(b"\r\n", 1)[0].decode("latin-1")
        try:
            method, target, version = line.split(" ")
        except ValueError:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            return

        if method.upper() == "CONNECT":
            host, _, port_text = target.rpartition(":")
            port = int(port_text) if port_text.isdigit() else 443
            host = host.strip("[]")
            decision = self.decide("http-connect", host, port)
            if not decision.allowed:
                client.sendall(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
                return
            try:
                upstream = self._pinned_socket(decision)
            except OSError:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                return
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.tunnel(client, upstream)
            return

        # Plain HTTP: absolute-URI request line, rewritten to origin form.
        if not target.lower().startswith("http://"):
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            return
        without_scheme = target[len("http://") :]
        authority, _, path = without_scheme.partition("/")
        host, _, port_text = authority.rpartition(":")
        if not port_text.isdigit():
            host, port = authority, 80
        else:
            port = int(port_text)
        host = host.strip("[]")
        decision = self.decide("http", host, port)
        if not decision.allowed:
            client.sendall(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
            return
        try:
            upstream = self._pinned_socket(decision)
        except OSError:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            return
        headers = head.split(b"\r\n")[1:]
        rewritten = [f"{method} /{path} {version}".encode("latin-1")]
        rewritten.extend(h for h in headers if not h.lower().startswith(b"proxy-"))
        rewritten.append(b"Connection: close")
        upstream.sendall(b"\r\n".join(rewritten) + b"\r\n\r\n" + rest)
        self.tunnel(client, upstream)

    # -- SOCKS5 ----------------------------------------------------------
    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("eof")
            buf += chunk
        return buf

    def handle_socks5(self, client: socket.socket) -> None:
        try:
            version, nmethods = self._recv_exact(client, 2)
            if version != 5:
                return
            methods = self._recv_exact(client, nmethods)
            if 0 not in methods:  # no-auth only; the network is the boundary
                client.sendall(b"\x05\xff")
                return
            client.sendall(b"\x05\x00")
            ver, cmd, _rsv, atyp = self._recv_exact(client, 4)
            if ver != 5 or cmd != 1:
                client.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
                return
            if atyp == 1:
                host = socket.inet_ntoa(self._recv_exact(client, 4))
            elif atyp == 3:
                (length,) = self._recv_exact(client, 1)
                host = self._recv_exact(client, length).decode("idna")
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, self._recv_exact(client, 16))
            else:
                client.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
                return
            port = struct.unpack("!H", self._recv_exact(client, 2))[0]
            decision = self.decide("socks5", host, port)
            if not decision.allowed:
                # 0x02 = connection not allowed by ruleset
                client.sendall(b"\x05\x02\x00\x01" + b"\x00" * 6)
                return
            try:
                upstream = self._pinned_socket(decision)
            except OSError:
                client.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)  # refused
                return
            client.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
            self.tunnel(client, upstream)
        except (ConnectionError, OSError):
            return

    # -- servers ---------------------------------------------------------
    def _serve(self, listener: socket.socket, handler) -> None:
        while True:
            try:
                client, _ = listener.accept()
            except OSError:
                return
            client.settimeout(PUMP_TIMEOUT)
            threading.Thread(
                target=self._safe, args=(handler, client), daemon=True
            ).start()

    def _safe(self, handler, client: socket.socket) -> None:
        try:
            handler(client)
        except (OSError, ValueError):
            pass
        finally:
            try:
                client.close()
            except OSError:
                pass

    def run(self, http_addr: tuple[str, int], socks_addr: tuple[str, int]) -> None:
        http_listener = self._listener(http_addr)
        socks_listener = self._listener(socks_addr)
        print("READY", flush=True)
        threading.Thread(
            target=self._serve, args=(http_listener, self.handle_http), daemon=True
        ).start()
        threading.Thread(
            target=self._serve, args=(socks_listener, self.handle_socks5), daemon=True
        ).start()
        while True:
            time.sleep(3600)

    @staticmethod
    def _listener(addr: tuple[str, int]) -> socket.socket:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(addr)
        server.listen(128)
        return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="per-job egress broker")
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--audit", type=Path, default=None)
    parser.add_argument("--http-listen", default="0.0.0.0:3128")
    parser.add_argument("--socks-listen", default="0.0.0.0:1080")
    parser.add_argument("--ready-file", type=Path, default=None)
    args = parser.parse_args(argv)

    raw = json.loads(args.policy.read_text(encoding="utf-8"))
    policy = netpolicy.load_policy(raw)
    audit = Audit(args.audit, policy.job_id)
    broker = Broker(policy, audit)

    def parse_addr(text: str) -> tuple[str, int]:
        host, _, port = text.rpartition(":")
        return host, int(port)

    if args.ready_file is not None:
        args.ready_file.write_text("ready", encoding="utf-8")
    broker.run(parse_addr(args.http_listen), parse_addr(args.socks_listen))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
