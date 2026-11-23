"""Probe executed *inside* the sandboxed job container.

It reports what the job can reach directly and what the egress broker allows,
so the test asserts on data instead of parsing wget output.
"""

from __future__ import annotations

import json
import socket
import ssl
import sys
import urllib.error
import urllib.request

CONNECT_TIMEOUT = 3.0


def tcp(host: str, port: int) -> str:
    try:
        sock = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
        sock.close()
        return "CONNECTED"
    except OSError as exc:
        return f"{exc.__class__.__name__}:{exc.strerror or exc}"


def direct(targets: list[str]) -> dict:
    out = {}
    for target in targets:
        host, _, port = target.rpartition(":")
        host = host.strip("[]")
        out[target] = tcp(host, int(port))
    return out


def via_proxy(proxy: str, urls: list[str]) -> dict:
    out = {}
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    )
    for url in urls:
        try:
            with opener.open(url, timeout=CONNECT_TIMEOUT + 3) as response:
                out[url] = {"status": response.status, "body": response.read(64).decode("latin-1")}
        except urllib.error.HTTPError as exc:
            out[url] = {"status": exc.code, "error": "HTTPError"}
        except Exception as exc:  # noqa: BLE001 - report, never raise
            out[url] = {"status": None, "error": f"{exc.__class__.__name__}:{exc}"}
    return out


def tls_via_proxy(proxy: str, host: str, port: int) -> dict:
    """CONNECT through the broker and complete a TLS handshake (SNI check)."""
    try:
        sock = socket.create_connection(_proxy_hostport(proxy), timeout=CONNECT_TIMEOUT)
        request = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
        sock.sendall(request.encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = sock.recv(4096)
            if not chunk:
                break
            head += chunk
        status = head.split(b"\r\n", 1)[0].decode("latin-1")
        if "200" not in status:
            sock.close()
            return {"connect": status, "tls": None}
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with context.wrap_socket(sock, server_hostname=host) as tls:
            return {"connect": status, "tls": tls.version()}
    except Exception as exc:  # noqa: BLE001
        return {"connect": None, "tls": None, "error": f"{exc.__class__.__name__}:{exc}"}


def _proxy_hostport(proxy: str) -> tuple[str, int]:
    from urllib.parse import urlsplit

    parts = urlsplit(proxy if "//" in proxy else f"//{proxy}")
    return parts.hostname or "", parts.port or 0


def dns(hosts: list[str]) -> dict:
    out = {}
    for host in hosts:
        try:
            out[host] = socket.gethostbyname(host)
        except OSError as exc:
            out[host] = f"{exc.__class__.__name__}:{exc.strerror or exc}"
    return out


def socks5(proxy: str, targets: list[str]) -> dict:
    """SOCKS5 CONNECT through the broker, no external library."""
    import struct

    out = {}
    host_proxy, port_proxy = _proxy_hostport(proxy)
    for target in targets:
        host, _, port_text = target.rpartition(":")
        host = host.strip("[]")
        port = int(port_text)
        try:
            sock = socket.create_connection((host_proxy, port_proxy), timeout=CONNECT_TIMEOUT)
            sock.sendall(b"\x05\x01\x00")
            if sock.recv(2) != b"\x05\x00":
                out[target] = "GREETING-REJECTED"
                sock.close()
                continue
            request = b"\x05\x01\x00\x03" + bytes([len(host)]) + host.encode()
            request += struct.pack("!H", port)
            sock.sendall(request)
            reply = sock.recv(10)
            out[target] = {0: "CONNECTED", 2: "DENIED-BY-RULESET", 5: "REFUSED"}.get(
                reply[1] if len(reply) > 1 else -1, f"REP-{reply[1] if len(reply) > 1 else -1}"
            )
            sock.close()
        except OSError as exc:
            out[target] = f"{exc.__class__.__name__}:{exc.strerror or exc}"
    return out


def main(argv: list[str]) -> int:
    request = json.loads(argv[0])
    result: dict = {}
    if "direct" in request:
        result["direct"] = direct(request["direct"])
    if "proxy" in request and request.get("urls"):
        result["proxy"] = via_proxy(request["proxy"], request["urls"])
    if "dns" in request:
        result["dns"] = dns(request["dns"])
    if "socks5_targets" in request:
        result["socks5"] = socks5(request["proxy"], request.get("socks5_targets", []))
    if "tls" in request:
        result["tls"] = tls_via_proxy(request["proxy"], request["tls"][0], request["tls"][1])
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
