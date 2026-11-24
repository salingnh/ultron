#!/usr/bin/env python3
"""Local passive-source stub for the authorized AEGIS lab zone (G0.4c).

Subfinder's crt.sh source sends `GET https://crt.sh/?q=%25.<domain>&output=json`. For a
non-public lab zone a real passive source has nothing to return, and a lab run must not
contact a third party. This stub answers exactly that one query for `lab.aegis.test` from a
committed fixture, so the Subfinder -> DNSx chain is reproducible offline.

Trust is lab-local only: `make lab-up` generates a throwaway CA and a `crt.sh` certificate
under `deploy/lab/.run/tls` (git-ignored), and the Subfinder run container gets
`SSL_CERT_FILE` pointing at that CA plus an /etc/hosts entry for crt.sh. Nothing outside the
lab network can reach this process, and it serves nothing but the authorized query.
"""

import json
import signal
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ZONE = "lab.aegis.test"
AUTHORIZED_Q = "%." + ZONE
FIXTURE = Path("/lab-fixtures/crtsh.lab.aegis.test.json")
TLS_DIR = Path("/lab-tls")


class Handler(BaseHTTPRequestHandler):
    server_version = "aegis-lab-passive/1"

    def _json(self, status: int, payload) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        requested = (query.get("q") or [""])[0]
        output = (query.get("output") or [""])[0]
        if parsed.path != "/" or output != "json" or requested != AUTHORIZED_Q:
            print(f"REFUSED {self.path}", flush=True)
            self._json(403, {"error": "only the authorized lab query is served"})
            return
        print(f"SERVED {self.path}", flush=True)
        self._json(200, json.loads(FIXTURE.read_text(encoding="utf-8")))

    def log_message(self, fmt: str, *args) -> None:  # keep the request log above
        print(f"{self.address_string()} {fmt % args}", flush=True)


def main() -> None:
    # The stub is PID 1 in its container: without a handler the kernel ignores SIGTERM for
    # init and `podman stop` waits out its timeout before SIGKILL.
    def stop(signum, _frame):
        print(f"signal {signum}: stopping", flush=True)
        sys.exit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(TLS_DIR / "crt.sh.crt", TLS_DIR / "crt.sh.key")
    server = ThreadingHTTPServer(("0.0.0.0", 443), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"aegis lab passive stub: https://crt.sh/ for {ZONE} only", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
