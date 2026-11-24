"""HTTP target of the M06 egress tests.

    python3 -m aegis_probe.target 8080

* `/` -> 200 `OK`
* `/redirect` -> 302 to `http://169.254.169.254/` (a denied destination: the proxy must deny the
  next hop, which proves redirects are re-checked)
* `/unbound` -> 302 to `http://denied.invalid/` (a name outside the binding)
* `/echo` -> 200 with the request line, to prove plain-HTTP absolute-URI forwarding works
"""

from __future__ import annotations

import http.server
import socketserver
import sys
import threading


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "aegis-probe-target"

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        if self.path == "/redirect":
            self._redirect("http://169.254.169.254/latest/meta-data/")
            return
        if self.path == "/unbound":
            self._redirect("http://denied.invalid/")
            return
        body = b"OK" if self.path == "/" else f"GET {self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - http.server API
        return


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main(argv: list[str] | None = None) -> int:
    ports = [int(part) for part in (argv if argv is not None else sys.argv[1:])] or [8080]
    for port in ports:
        server = _Server(("0.0.0.0", port), _Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print("READY", flush=True)
    threading.Event().wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())
