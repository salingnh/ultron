"""In-container reachability probe of the M06 tests.

    python3 -m aegis_probe.reach HOST:PORT [HOST:PORT ...] [--dns NAME ...]

It prints one JSON object: which destinations accepted a TCP connection, which names resolved, and
whether an outbound socket could be created at all. Everything is an observation, nothing is
assumed: the isolation tests assert on this output, not on container configuration.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys


def _reach(host: str, port: int, timeout: float = 2.0) -> str:
    try:
        connection = socket.create_connection((host, port), timeout=timeout)
    except OSError as error:
        return f"DENIED({error.__class__.__name__})"
    connection.close()
    return "CONNECTED"


def _resolve(name: str) -> bool:
    try:
        socket.getaddrinfo(name, None)
    except OSError:
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("destinations", nargs="*")
    parser.add_argument("--dns", action="append", default=[])
    args = parser.parse_args(argv)
    reach: dict[str, str] = {}
    for destination in args.destinations:
        host, _, port = destination.rpartition(":")
        reach[destination] = _reach(host.strip("[]"), int(port))
    socket_result = "OK"
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.close()
    except OSError as error:  # pragma: no cover - only on a host that forbids sockets
        socket_result = f"DENIED({error.__class__.__name__})"
    print(
        json.dumps(
            {
                "reach": reach,
                "dns": {name: _resolve(name) for name in args.dns},
                "socket": socket_result,
            }
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
