"""Stand-in control/data services for the isolation tests.

Binds several TCP ports (PostgreSQL, Neo4j HTTP/Bolt, S3, Temporal) and prints
one line per accepted connection. It plays the part of the platform services
the sandbox must never reach; it is not a database and holds no data.
"""

from __future__ import annotations

import socket
import sys
import threading
import time

PORTS = (5432, 7474, 7687, 8333, 7233)


def serve(port: int) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", port))
    listener.listen(8)
    while True:
        try:
            conn, addr = listener.accept()
        except OSError:
            return
        print(f"ACCEPT {port} from {addr[0]}", flush=True)
        conn.close()


if __name__ == "__main__":
    ports = [int(p) for p in sys.argv[1:]] or list(PORTS)
    for port in ports:
        threading.Thread(target=serve, args=(port,), daemon=True).start()
    print("READY " + ",".join(str(p) for p in ports), flush=True)
    while True:
        time.sleep(3600)
