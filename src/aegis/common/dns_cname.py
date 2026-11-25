"""A stdlib CNAME lookup for the signing guardrail (F3 guardrail 2, item #61).

The active capabilities must not turn an owner name that CNAMEs out of the authorized suffixes
into a third-party address: discovery records the name, not the canonical target. M05 signs at
dispatch time, so this is the last point where the chain is still visible. Only the system
resolver (`/etc/resolv.conf`) is asked, with one short query per hop; an error or a missing
resolver returns no chain (the caller treats "unknown" as "no reason to refuse").

The wire format is the subset this lookup needs: one question, and the CNAME rdata of the answer.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import struct

__all__ = ["cname_chain", "resolver_address"]

_HEADER = struct.Struct("!HHHHHH")
TYPE_CNAME = 5
CLASS_IN = 1
MAX_HOPS = 5


def resolver_address(path: str = "/etc/resolv.conf") -> str | None:
    """The first `nameserver` of the system resolver, if it is an address."""
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                fields = line.split()
                if len(fields) >= 2 and fields[0] == "nameserver":
                    try:
                        ipaddress.ip_address(fields[1])
                    except ValueError:
                        continue
                    return fields[1]
    except OSError:
        return None
    return None


def _build_query(qid: int, name: str) -> bytes:
    labels = b"".join(
        bytes([len(label)]) + label.encode("idna") for label in name.split(".") if label
    )
    return (
        _HEADER.pack(qid, 0x0100, 1, 0, 0, 0)
        + labels
        + b"\x00"
        + struct.pack("!HH", TYPE_CNAME, CLASS_IN)
    )


def _skip_name(message: bytes, offset: int) -> int:
    while True:
        if offset >= len(message):
            raise ValueError("truncated name")
        length = message[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + length


def _read_name(message: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    end = offset
    while True:
        if offset >= len(message):
            raise ValueError("truncated name")
        length = message[offset]
        if length == 0:
            return ".".join(labels), (end if jumped else offset + 1)
        if length & 0xC0 == 0xC0:
            if not jumped:
                end = offset + 2
                jumped = True
            pointer = struct.unpack_from("!H", message, offset)[0] & 0x3FFF
            offset = pointer
            continue
        offset += 1
        labels.append(message[offset : offset + length].decode("ascii", "replace"))
        offset += length


def _parse_cname(message: bytes) -> tuple[str, str] | None:
    if len(message) < _HEADER.size:
        raise ValueError("short DNS message")
    _qid, flags, qdcount, ancount, _ns, _ar = _HEADER.unpack_from(message)
    if not flags & 0x8000:
        raise ValueError("not a response")
    offset = _HEADER.size
    for _ in range(qdcount):
        offset = _skip_name(message, offset) + 4
    for _ in range(ancount):
        owner, offset = _read_name(message, offset)
        if offset + 10 > len(message):
            raise ValueError("truncated record")
        rtype, rclass, _ttl, rdlength = struct.unpack_from("!HHIH", message, offset)
        offset += 10
        rdata_offset = offset
        offset += rdlength
        if rclass == CLASS_IN and rtype == TYPE_CNAME:
            target, _ = _read_name(message, rdata_offset)
            return owner.strip(".").lower(), target.strip(".").lower()
    return None


def cname_chain(
    name: str, *, timeout: float = 2.0, resolver: str | None = None, port: int = 53
) -> tuple[str, ...]:
    """The CNAME targets of `name`, in order, at most `MAX_HOPS` of them.

    Raises OSError/ValueError on a resolution failure; callers decide whether that is a reason to
    refuse (fail closed only when the chain is known to leave the authorized suffixes).
    """
    current = name.strip(".").lower()
    hops: list[str] = []
    server = resolver or resolver_address()
    if server is None:
        return ()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(timeout)
        for _ in range(MAX_HOPS):
            query = _build_query(int.from_bytes(os.urandom(2), "big"), current)
            client.sendto(query, (server, port))
            data, _address = client.recvfrom(4096)
            pair = _parse_cname(data)
            if pair is None:
                return tuple(hops)
            _, target = pair
            hops.append(target)
            if target == current:
                return tuple(hops)
            current = target
    return tuple(hops)
