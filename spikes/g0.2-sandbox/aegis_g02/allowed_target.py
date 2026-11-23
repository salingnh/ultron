"""The one allowed destination of the egress tests.

Serves /ok and /redirect; /redirect answers 302 to a URL from the query string,
which is how the tests prove that a redirect target is re-checked by the broker
instead of being followed blindly inside one allowed connection.
"""

from __future__ import annotations

import http.server
import sys
from urllib.parse import parse_qs, urlsplit


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        parts = urlsplit(self.path)
        if parts.path == "/redirect":
            target = parse_qs(parts.query).get("to", ["http://169.254.169.254/"])[0]
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"allowed-target-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:
        print("TARGET " + (fmt % args), flush=True)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"READY {port}", flush=True)
    server.serve_forever()
