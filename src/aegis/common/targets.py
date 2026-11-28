"""Canonical-key parsing M21 needs: the address and port a signed target stands for.

A verification run is bound to the finding's asset, and the asset's canonical key is the one
identity the graph and the signed task agree on. The run's evidence is per address:port (a tool
dials the address), so the decision compares the document's answers with the address and port the
key names, not with the key text.

Two shapes exist today:

    service:<ip>:<port>/tcp        a known service (the L1 httpd check)
    app:<scheme>://<host>:<port>   an application endpoint (E1 config checks, slice S4)

A name in either shape is refused: the evidence would need a resolution step M21 cannot audit, and
the deployment's targets are signed as addresses.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

__all__ = ["TargetError", "address_port"]

_SERVICE = re.compile(r"^service:(?P<address>.+):(?P<port>\d+)/tcp$")


class TargetError(ValueError):
    """The key is not a canonical key this module can turn into an address and a port."""


def _ip(value: str, key: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip("[]")))
    except ValueError as error:
        raise TargetError(f"{key}: {value!r} is not an IP address") from error


def address_port(key: str) -> tuple[str, int]:
    """The (address, port) of a canonical key; raises `TargetError` for any other shape."""
    service = _SERVICE.match(key)
    if service is not None:
        return _ip(service.group("address"), key), int(service.group("port"))
    if key.startswith("app:"):
        parts = urlsplit(key[len("app:") :])
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise TargetError(f"{key}: an application key must be app:<http(s)://host:port>")
        if parts.port is None:
            raise TargetError(f"{key}: the application key has no explicit port")
        return _ip(parts.hostname, key), int(parts.port)
    raise TargetError(f"{key}: not a service or application canonical key")
