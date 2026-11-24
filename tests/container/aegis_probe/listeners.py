"""Stand-in control/data-plane listeners for the reachability tests (M06).

    python3 -m aegis_probe.listeners 5432 7474 7687 8333 7233

They accept a connection and keep it, exactly like a server would; the test only asks whether the
job container can open a TCP connection at all. `READY` is printed once every socket listens.
"""

from __future__ import annotations

import socket
import sys
import threading


def _serve(port: int) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(8)
    while True:
        connection, _ = server.accept()
        threading.Thread(target=_hold, args=(connection,), daemon=True).start()


def _hold(connection: socket.socket) -> None:
    try:
        connection.recv(1024)
    except OSError:
        pass
    finally:
        connection.close()


def main(argv: list[str] | None = None) -> int:
    ports = [int(part) for part in (argv if argv is not None else sys.argv[1:])]
    for port in ports:
        threading.Thread(target=_serve, args=(port,), daemon=True).start()
    print("READY", flush=True)
    threading.Event().wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())
