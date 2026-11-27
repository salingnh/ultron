#!/usr/bin/env python3
"""A minimal SOCKS5 CONNECT proxy with an allow-list, for the G1.6b lab proxy verification.

It is not a product component: `scripts/lab/httpx-proxy-check.sh` starts it in a throwaway
container on the lab network, between httpx and the two lab web services, to prove that httpx
really routes its requests through the proxy (`proxyAware: true` in its manifest). Every CONNECT
is checked against the allow-list that stands in for the broker's binding and logged as one JSON
line on stdout, so the run can show *which* destinations the tool needed.

Usage: proxy.py --listen 0.0.0.0 --port 1080 --allow 10.114.53.21:8080 --allow 10.114.53.22:8443
No authentication (the container is only reachable on the internal lab network), TCP CONNECT only.
"""

from __future__ import annotations

import argparse
import json
import select
import socket
import struct
import sys
import threading

BUFFER = 65536


def _read_exact(connection: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise ConnectionError("peer closed the connection")
        data += chunk
    return data


def _reply(connection: socket.socket, code: int) -> None:
    # VER=5, REP=code, RSV=0, ATYP=1 (IPv4), BND.ADDR=0.0.0.0, BND.PORT=0
    connection.sendall(struct.pack("!BBBB4sH", 5, code, 0, 1, b"\x00\x00\x00\x00", 0))


def _pipe(source: socket.socket, target: socket.socket) -> None:
    try:
        while True:
            ready, _, _ = select.select([source, target], [], [], 60)
            if not ready:
                return
            for item in ready:
                data = item.recv(BUFFER)
                if not data:
                    return
                (target if item is source else source).sendall(data)
    except OSError:
        return
    finally:
        for item in (source, target):
            try:
                item.close()
            except OSError:
                pass


def _log(event: dict[str, object]) -> None:
    print(json.dumps(event, sort_keys=True), flush=True)


def handle(connection: socket.socket, allowed: set[tuple[str, int]]) -> None:
    peer = f"{connection.getpeername()[0]}:{connection.getpeername()[1]}"
    try:
        version, methods = _read_exact(connection, 2)
        if version != 5 or methods == 0:
            connection.close()
            return
        _read_exact(connection, methods)  # offered methods; "no authentication" is the only one
        connection.sendall(struct.pack("!BB", 5, 0))
        version, command, _, address_type = _read_exact(connection, 4)
        if version != 5 or command != 1:  # CONNECT only
            _reply(connection, 7)
            connection.close()
            return
        if address_type == 1:
            host = socket.inet_ntoa(_read_exact(connection, 4))
        elif address_type == 4:
            host = socket.inet_ntop(socket.AF_INET6, _read_exact(connection, 16))
        elif address_type == 3:
            host = _read_exact(connection, _read_exact(connection, 1)[0]).decode()
        else:
            _reply(connection, 8)
            connection.close()
            return
        port = struct.unpack("!H", _read_exact(connection, 2))[0]
        destination = (host, port)
        if destination not in allowed:
            _log({"event": "denied", "peer": peer, "destination": f"{host}:{port}"})
            _reply(connection, 2)  # connection not allowed by ruleset
            connection.close()
            return
        try:
            upstream = socket.create_connection(destination, timeout=10)
        except OSError as error:
            _log(
                {
                    "event": "unreachable",
                    "peer": peer,
                    "destination": f"{host}:{port}",
                    "error": str(error),
                }
            )
            _reply(connection, 5)
            connection.close()
            return
        _log({"event": "connect", "peer": peer, "destination": f"{host}:{port}"})
        _reply(connection, 0)
        threading.Thread(target=_pipe, args=(connection, upstream), daemon=True).start()
    except (ConnectionError, OSError):
        try:
            connection.close()
        except OSError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=1080)
    parser.add_argument("--allow", action="append", default=[])
    args = parser.parse_args()
    allowed = set()
    for entry in args.allow:
        host, _, port = entry.rpartition(":")
        allowed.add((host, int(port)))
    if not allowed:
        print("no --allow destination given", file=sys.stderr)
        return 2
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((args.listen, args.port))
        server.listen(64)
        _log(
            {
                "event": "listening",
                "port": args.port,
                "allowed": sorted(f"{h}:{p}" for h, p in allowed),
            }
        )
        while True:
            connection, _ = server.accept()
            threading.Thread(target=handle, args=(connection, allowed), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())
