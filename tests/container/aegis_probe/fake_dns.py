"""A fake upstream resolver for the M06 DNS tests (test-only, never shipped).

    python3 -m aegis_probe.fake_dns 5353 '{"bound.example": ["198.51.100.7"]}'

It speaks the small wire format `aegis.m06_runner.dns` defines, so the broker's `--dns-upstream`
client is exercised against a real UDP server without touching the internet. `READY` is printed on
stdout once it is listening (the tests wait for it).
"""

from __future__ import annotations

import json
import socketserver
import sys

from aegis.m06_runner import dns as wire


class _Handler(socketserver.BaseRequestHandler):
    answers: dict[str, list[str]] = {}

    def handle(self) -> None:
        data, sock = self.request
        try:
            question = wire.parse_question(data)
        except ValueError:
            return
        addresses = self.answers.get(question.name, [])
        rcode = wire.RCODE_NOERROR if addresses else wire.RCODE_NXDOMAIN
        sock.sendto(wire.build_response(question, addresses, rcode=rcode), self.client_address)


class _Server(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2:
        print("usage: python -m aegis_probe.fake_dns <port> <json answers>", file=sys.stderr)
        return 2
    _Handler.answers = {str(k).lower(): [str(a) for a in v] for k, v in json.loads(args[1]).items()}
    with _Server(("0.0.0.0", int(args[0])), _Handler) as server:
        print("READY", flush=True)
        server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
