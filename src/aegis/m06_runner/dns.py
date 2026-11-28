"""DNS for a sandboxed job: the broker answers, the job has no resolver (G1.6, item 4).

An internet-profile job runs on a network with no DNS (`--disable-dns`) and nothing to talk to but
the broker; its `/etc/resolv.conf` names the broker. Every query is therefore answered **here**, in
the control plane, with the same rules as a CONNECT:

* **only bound names resolve.** A name may be queried when the signed task binds it: one of its
  target names (`player.example`) or one of the pinned manifest's declared source hosts (`crt.sh`).
  Any other name is `REFUSED` - an open resolver would be an exfiltration channel and a way to reach
  addresses the signed binding does not contain.
* **every answer is filtered against the deny set.** Each resolved address is checked exactly like a
  connection (`denyset.deny_reason`, platform CIDRs, the campaign denylist, private ranges unless
  the campaign targets the address); a target name's answer is further narrowed to the signed
  target addresses, so DNS cannot say something the broker would not connect to. Refused addresses
  are dropped; a name left with no address is `NXDOMAIN`.
* **short TTL.** Answers live 30 s, so a re-pointed name is re-checked on the next query (the
  CONNECT path resolves per connection anyway).
* **one audit line per query** (`kind: dns`): name, type, allowed/denied answers, decision, reason,
  profile and authorization reference.

The upstream resolver is a deployment choice (`--dns-upstream host:port`, the pinned resolver the
broker forwards to; unset = the control plane's system resolver). The broker never relays UDP
payloads: it parses the query, resolves it, and writes the answer itself, so a job cannot smuggle
traffic through the resolver.

An upstream answer is *checked* before it is read (N7, the same rules `common.dns_cname` applies):
its id must be the id of the query that was sent, and its rcode must be an answer - NXDOMAIN for the
queried name is "no address"/"no chain", a first-hop CNAME NXDOMAIN is an empty chain, NXDOMAIN
mid-chain is a broken chain, and every other rcode (SERVFAIL, REFUSED, FORMERR, ...) raises. A
reader that ignores either turns a broken resolver into a wrong answer (an empty address list is a
containment decision here, not a guess), so a raise maps to SERVFAIL/RESOLVE_FAILED at the front
end, never to NOERROR with no records.

Standard library only, like the rest of the broker image.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import struct
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Protocol

from aegis.m06_runner import denyset
from aegis.m06_runner.netpolicy import JobEgressPolicy

__all__ = [
    "Answer",
    "DnsForwarder",
    "Question",
    "build_cname_response",
    "build_query",
    "build_response",
    "parse_cnames",
    "parse_question",
    "parse_addresses",
    "rcode_name",
]

TYPE_A = 1
TYPE_CNAME = 5
TYPE_AAAA = 28
CLASS_IN = 1
RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_NOTIMP = 4
RCODE_REFUSED = 5
DEFAULT_TTL = 30
MAX_NAME_BYTES = 255

_HEADER = struct.Struct("!HHHHHH")
RCODES = {
    RCODE_NOERROR: "NOERROR",
    RCODE_FORMERR: "FORMERR",
    RCODE_SERVFAIL: "SERVFAIL",
    RCODE_NXDOMAIN: "NXDOMAIN",
    RCODE_NOTIMP: "NOTIMP",
    RCODE_REFUSED: "REFUSED",
}


def rcode_name(rcode: int) -> str:
    return RCODES.get(rcode, f"RCODE{rcode}")


class AddressResolver(Protocol):
    """Resolve a name to addresses (the deployment's resolver, or a stub in tests)."""

    def __call__(self, name: str) -> list[str]: ...


@dataclass(frozen=True, slots=True)
class Question:
    id: int
    name: str
    qtype: int
    #: The raw question section (name + type + class), echoed in the response.
    section: bytes
    #: Offset of the first byte of the name in the original message (usually 12).
    offset: int


@dataclass(frozen=True, slots=True)
class Answer:
    allowed: tuple[str, ...]
    denied: tuple[str, ...]
    reason: str
    rcode: int


def _decode_name(message: bytes, offset: int) -> tuple[str, int]:
    """Read a (non-compressed) name; return the text and the offset after its terminator.

    A query's QNAME is never compressed; an answer's owner name may be, so `skip_name` handles
    pointers when walking answer records.
    """
    labels: list[str] = []
    length = 0
    position = offset
    total = 0
    while True:
        if position >= len(message):
            raise ValueError("truncated name")
        size = message[position]
        if size & 0xC0:
            raise ValueError("compressed name in question")
        position += 1
        if size == 0:
            break
        if size > 63 or position + size > len(message):
            raise ValueError("invalid label")
        total += size + 1
        if total > MAX_NAME_BYTES:
            raise ValueError("name too long")
        # DNS labels are ASCII on the wire (IDNA is the encoded form); a non-ASCII byte is
        # replaced rather than decoded, so it can never match a bound name.
        labels.append(message[position : position + size].decode("ascii", "replace"))
        length += size + 1
        position += size
    return ".".join(labels), position


def skip_name(message: bytes, offset: int) -> int:
    """Offset after a name, following compression pointers without decoding it."""
    seen = 0
    while True:
        if offset >= len(message):
            raise ValueError("truncated name")
        size = message[offset]
        if size & 0xC0 == 0xC0:
            if offset + 2 > len(message):
                raise ValueError("truncated pointer")
            return offset + 2
        if size & 0xC0:
            raise ValueError("reserved label type")
        offset += 1
        if size == 0:
            return offset
        offset += size
        seen += 1
        if seen > 128:
            raise ValueError("runaway name")


def parse_question(message: bytes) -> Question:
    """Parse one DNS query; raise ValueError when it is not a well-formed single question."""
    if len(message) < _HEADER.size:
        raise ValueError("short DNS message")
    qid, _flags, qdcount, _an, _ns, _ar = _HEADER.unpack_from(message)
    if qdcount != 1:
        raise ValueError("one question expected")
    name, after_name = _decode_name(message, _HEADER.size)
    end = after_name + 4
    if end > len(message):
        raise ValueError("truncated question")
    qtype, qclass = struct.unpack_from("!HH", message, after_name)
    if qclass != CLASS_IN:
        raise ValueError("only class IN is supported")
    if not name:
        raise ValueError("empty name")
    return Question(
        id=qid,
        name=name.rstrip(".").lower(),
        qtype=qtype,
        section=message[_HEADER.size : end],
        offset=_HEADER.size,
    )


def _encode_name(name: str) -> bytes:
    encoded = [label.encode("idna") for label in name.strip(".").split(".") if label]
    return b"".join(bytes([len(label)]) + label for label in encoded) + b"\x00"


def _read_name(message: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    end = offset
    seen = 0
    while True:
        if offset >= len(message):
            raise ValueError("truncated name")
        size = message[offset]
        if size == 0:
            return ".".join(labels), (end if jumped else offset + 1)
        if size & 0xC0 == 0xC0:
            if offset + 2 > len(message):
                raise ValueError("truncated pointer")
            if not jumped:
                end = offset + 2
                jumped = True
            offset = struct.unpack_from("!H", message, offset)[0] & 0x3FFF
            seen += 1
            if seen > 128:
                raise ValueError("runaway pointer")
            continue
        if size & 0xC0:
            raise ValueError("reserved label type")
        offset += 1
        if offset + size > len(message):
            raise ValueError("truncated label")
        labels.append(message[offset : offset + size].decode("ascii", "replace"))
        offset += size
        seen += 1
        if seen > 128:
            raise ValueError("runaway name")


def build_query(qid: int, name: str, qtype: int) -> bytes:
    """A standard recursive query, used to forward to the deployment's resolver."""
    question = _encode_name(name) + struct.pack("!HH", qtype, CLASS_IN)
    return _HEADER.pack(qid, 0x0100, 1, 0, 0, 0) + question


def parse_cnames(message: bytes) -> list[str]:
    """CNAME targets of an answer message, in answer order."""
    if len(message) < _HEADER.size:
        raise ValueError("short DNS message")
    _qid, flags, qdcount, ancount, _ns, _ar = _HEADER.unpack_from(message)
    if not flags & 0x8000:
        raise ValueError("not a response")
    offset = _HEADER.size
    for _ in range(qdcount):
        offset = skip_name(message, offset) + 4
    targets: list[str] = []
    for _ in range(ancount):
        offset = skip_name(message, offset)
        if offset + 10 > len(message):
            raise ValueError("truncated record")
        rtype, rclass, _ttl, rdlength = struct.unpack_from("!HHIH", message, offset)
        offset += 10
        rdata_offset = offset
        offset += rdlength
        if rclass != CLASS_IN or rtype != TYPE_CNAME:
            continue
        target, _ = _read_name(message, rdata_offset)
        normalized = target.strip(".").lower()
        if normalized:
            targets.append(normalized)
    return targets


def build_cname_response(
    question: Question,
    targets: Iterable[str],
    *,
    rcode: int = RCODE_NOERROR,
    ttl: int = DEFAULT_TTL,
) -> bytes:
    """A DNS response carrying CNAME hops starting at `question.name`."""
    records = b""
    count = 0
    if rcode == RCODE_NOERROR:
        previous = ""
        for index, target in enumerate(targets):
            owner = b"\xc0\x0c" if index == 0 else _encode_name(previous)
            rdata = _encode_name(target)
            records += owner + struct.pack("!HHIH", TYPE_CNAME, CLASS_IN, ttl, len(rdata)) + rdata
            previous = target
            count += 1
    flags = 0x8180 | (rcode & 0x000F)
    return _HEADER.pack(question.id, flags, 1, count, 0, 0) + question.section + records


def parse_addresses(message: bytes) -> list[str]:
    """A/AAAA records of an answer message (addresses only; CNAME chains are followed by the
    resolver of the deployment, so a forwarder answer is normally already an address)."""
    if len(message) < _HEADER.size:
        raise ValueError("short DNS message")
    _qid, flags, qdcount, ancount, _ns, _ar = _HEADER.unpack_from(message)
    if not flags & 0x8000:
        raise ValueError("not a response")
    offset = _HEADER.size
    for _ in range(qdcount):
        offset = skip_name(message, offset)
        offset += 4
    addresses: list[str] = []
    for _ in range(ancount):
        offset = skip_name(message, offset)
        if offset + 10 > len(message):
            raise ValueError("truncated record")
        rtype, rclass, _ttl, rdlength = struct.unpack_from("!HHIH", message, offset)
        offset += 10
        rdata = message[offset : offset + rdlength]
        offset += rdlength
        if rclass != CLASS_IN or len(rdata) != rdlength:
            continue
        if rtype == TYPE_A and rdlength == 4:
            addresses.append(str(ipaddress.IPv4Address(rdata)))
        elif rtype == TYPE_AAAA and rdlength == 16:
            addresses.append(str(ipaddress.IPv6Address(rdata)))
    return addresses


def _answer_rdata(address: str) -> tuple[int, bytes]:
    parsed = ipaddress.ip_address(address)
    if isinstance(parsed, ipaddress.IPv4Address):
        return TYPE_A, parsed.packed
    return TYPE_AAAA, parsed.packed


def build_response(
    question: Question,
    addresses: Iterable[str],
    *,
    rcode: int = RCODE_NOERROR,
    ttl: int = DEFAULT_TTL,
) -> bytes:
    """A response carrying `addresses` as A/AAAA records, or an error `rcode` with none.

    The owner name is a pointer to the question name (offset 12), so no name compression table is
    needed and the response is a superset-free echo of the query.
    """
    records = b""
    count = 0
    if rcode == RCODE_NOERROR:
        for address in addresses:
            rtype, rdata = _answer_rdata(address)
            records += b"\xc0\x0c" + struct.pack("!HHIH", rtype, CLASS_IN, ttl, len(rdata)) + rdata
            count += 1
    flags = 0x8180 | (rcode & 0x000F)  # QR, RD, RA + rcode
    return _HEADER.pack(question.id, flags, 1, count, 0, 0) + question.section + records


class UpstreamResolver:
    """Forward queries to one pinned DNS server (`--dns-upstream host:port`), never to a job.

    Every answer is checked against the query that was sent: a different id, an answer that is
    not a response, or an rcode that is not `NOERROR` (NXDOMAIN is handled by the caller: it means
    "no address" for A/AAAA and "no chain" only on the first CNAME hop) raises `ValueError`,
    exactly like `common.dns_cname.cname_chain`. An unchecked answer would let a stale or spoofed
    packet decide an empty address list - and the broker treats "no address allowed" as a denial,
    not as an error.
    """

    def __init__(self, host: str, port: int = 53, timeout: float = 5.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout

    def __call__(self, name: str) -> list[str]:
        addresses: list[str] = []
        for qtype in (TYPE_A, TYPE_AAAA):
            addresses.extend(self._ask(name, qtype))
        return addresses

    def _ask_wire(self, name: str, qtype: int) -> tuple[int, int, bytes]:
        """Send one query; return `(qid, rcode, message)` after checking it answers this query."""
        qid = int.from_bytes(os.urandom(2), "big")
        query = build_query(qid, name, qtype)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(self.timeout)
            client.sendto(query, (self.host, self.port))
            data, _ = client.recvfrom(4096)
        answer_qid, answer_rcode = self._check(data, qid, name)
        if struct.unpack_from("!H", data, 2)[0] & 0x0200:
            answer_qid, answer_rcode, data = self._ask_tcp(query, qid, name)
        return answer_qid, answer_rcode, data

    @staticmethod
    def _check(message: bytes, qid: int, name: str) -> tuple[int, int]:
        """`(qid, rcode)` of a response, refusing anything that does not answer the query."""
        if len(message) < _HEADER.size:
            raise ValueError(f"the DNS response for {name!r} is a short message")
        answer_qid, flags = struct.unpack_from("!HH", message)
        if not flags & 0x8000:
            raise ValueError(f"the DNS answer for {name!r} is not a response")
        if answer_qid != qid:
            raise ValueError(f"the DNS response for {name!r} carries qid {answer_qid}, not {qid}")
        return answer_qid, flags & 0x000F

    def _ask(self, name: str, qtype: int) -> list[str]:
        _qid, rcode, data = self._ask_wire(name, qtype)
        if rcode == RCODE_NXDOMAIN:
            return []  # the name itself does not exist; that is an answer, not an error
        if rcode != RCODE_NOERROR:
            raise ValueError(
                f"the DNS lookup of {name!r} answered {rcode_name(rcode)}, not an answer"
            )
        return parse_addresses(data)

    def _ask_cname_raw(self, name: str) -> tuple[int, list[str]]:
        """`(rcode, targets)` for one CNAME query; the chain walker decides which rcodes answer."""
        _qid, rcode, data = self._ask_wire(name, TYPE_CNAME)
        if rcode != RCODE_NOERROR:
            return rcode, []
        return rcode, parse_cnames(data)

    def _ask_cname_once(self, name: str) -> list[str]:
        rcode, targets = self._ask_cname_raw(name)
        if rcode == RCODE_NXDOMAIN:
            return []
        if rcode != RCODE_NOERROR:
            raise ValueError(
                f"the CNAME lookup of {name!r} answered {rcode_name(rcode)}, not an answer"
            )
        return targets

    def cnames(self, name: str) -> list[str]:
        """Follow up to 5 CNAME hops for `name` against the pinned upstream."""
        return _follow_cnames(name, self._ask_cname_raw)

    def _ask_tcp(self, query: bytes, qid: int, name: str) -> tuple[int, int, bytes]:
        """Retry a truncated UDP answer over TCP and check the TCP answer the same way."""
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as client:
            client.sendall(struct.pack("!H", len(query)) + query)
            header = _read_exact(client, 2)
            (length,) = struct.unpack("!H", header)
            data = _read_exact(client, length)
        answer_qid, rcode = self._check(data, qid, name)
        return answer_qid, rcode, data


def _system_nameserver(path: str = "/etc/resolv.conf") -> str | None:
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


def _follow_cnames(name: str, query_once: Callable[[str], tuple[int, list[str]]]) -> list[str]:
    """Walk a CNAME chain with `dns_cname.cname_chain`'s rules: only NOERROR is an answer.

    First-hop NXDOMAIN means the name does not exist (there is no chain); NXDOMAIN at any later hop
    is a broken chain and raises; every other rcode raises as well, so a SERVFAIL can never look
    like "no CNAME".
    """
    current = _normalize(name)
    hops: list[str] = []
    seen = {current}
    for hop in range(5):
        rcode, targets = query_once(current)
        if rcode == RCODE_NXDOMAIN:
            if hop == 0:
                return hops
            raise ValueError(
                f"the CNAME chain of {name!r} breaks at {current!r}: the resolver answered NXDOMAIN"
            )
        if rcode != RCODE_NOERROR:
            raise ValueError(
                f"the CNAME lookup of {current!r} answered {rcode_name(rcode)}, not an answer"
            )
        if not targets:
            break
        added = False
        for target in targets:
            normalized = _normalize(target)
            if normalized and normalized not in seen:
                seen.add(normalized)
                hops.append(normalized)
                current = normalized
                added = True
        if not added:
            break
    return hops


def system_cname_resolver(name: str) -> list[str]:
    """CNAME chain from the control plane's system resolver (stdlib-only, no external imports)."""
    server = _system_nameserver()
    if server is None:
        return []
    return _follow_cnames(name, UpstreamResolver(server, 53, timeout=2.0)._ask_cname_raw)


def system_resolver(name: str) -> list[str]:
    """The control plane's own resolver (the deployment default)."""
    try:
        infos = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    addresses: list[str] = []
    for info in infos:
        address = str(info[4][0])
        # `getaddrinfo` may hand back a 4-in-6 mapped address; keep the plain IPv4 text.
        if address.lower().startswith("::ffff:"):
            address = address.split(":")[-1]
        if address not in addresses:
            addresses.append(address)
    return addresses


@dataclass
class DnsForwarder:
    """Per-query decision + answer + audit (the broker's DNS front end)."""

    policy: JobEgressPolicy
    audit: object  # AuditLog, injected to keep this module importable without the broker
    resolver: Callable[[str], list[str]] = system_resolver
    cname_resolver: Callable[[str], Sequence[str]] | None = None
    ttl: int = DEFAULT_TTL
    clock: Callable[[], float] = time.monotonic
    _targets: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = field(init=False)
    _names: frozenset[str] = field(init=False)
    _target_names: frozenset[str] = field(init=False)

    def __post_init__(self) -> None:
        self._names = frozenset(_normalize(name) for name in self.policy.dns_names)
        self._target_names = frozenset(_normalize(name) for name in self.policy.dns_target_names)
        self._targets = tuple(self.policy.target_ips)

    # -- decisions ---------------------------------------------------------------------------

    def _address_allowed(self, address: str) -> str | None:
        """None when the address may be returned, else the deny reason code."""
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return "RESOLVE_FAILED"
        parsed, embedded = denyset.checked_address(parsed)
        if embedded is not None:
            return embedded.value
        denied = denyset.deny_reason(parsed)
        if denied is not None:
            return denied.value
        if any(parsed in network for network in self.policy.platform_cidrs):
            return "DENY_PLATFORM_NETWORK"
        if any(parsed in network for network in self.policy.deny_cidrs):
            return "DENY_TARGET_DENYLIST"
        # R4: only a private range the RoE lists as a seed is reachable, not every private address
        # some discovered name happens to answer with.
        if any(parsed in network for network in self.policy.private_cidrs) and not any(
            parsed in network for network in self.policy.authorized_private_cidrs
        ):
            return "DENY_PRIVATE"
        return None

    def _resolve_cnames(self, name: str) -> Sequence[str]:
        if self.cname_resolver is not None:
            return self.cname_resolver(name)
        if isinstance(self.resolver, UpstreamResolver):
            return self.resolver.cnames(name)
        if self.resolver is system_resolver:
            return system_cname_resolver(name)
        return ()

    def decide(self, question: Question) -> Answer:
        name = _normalize(question.name)
        if question.qtype not in (TYPE_A, TYPE_AAAA, TYPE_CNAME):
            return Answer((), (), "QTYPE_UNSUPPORTED", RCODE_NOTIMP)
        if name not in self._names:
            return Answer((), (), "NAME_NOT_BOUND", RCODE_REFUSED)
        if question.qtype == TYPE_CNAME:
            try:
                cnames = tuple(
                    _normalize(str(item))
                    for item in self._resolve_cnames(name)
                    if _normalize(str(item))
                )
            except OSError, ValueError:
                return Answer((), (), "RESOLVE_FAILED", RCODE_SERVFAIL)
            return Answer(cnames, (), "OK", RCODE_NOERROR)
        try:
            resolved = self.resolver(name)
        except OSError, ValueError:
            return Answer((), (), "RESOLVE_FAILED", RCODE_SERVFAIL)
        allowed: list[str] = []
        denied: list[str] = []
        for address in resolved:
            if address in allowed or address in denied:
                continue
            reason = self._address_allowed(address)
            if reason is not None:
                denied.append(address)
                continue
            if name in self._target_names and self._targets:
                # A target name answers exactly what the task signed; DNS never widens the binding.
                if not any(ipaddress.ip_address(address) in network for network in self._targets):
                    denied.append(address)
                    continue
            allowed.append(address)
        if not allowed:
            return Answer((), tuple(denied), "NO_ADDRESS_ALLOWED", RCODE_NXDOMAIN)
        return Answer(tuple(allowed), tuple(denied), "OK", RCODE_NOERROR)

    # -- wire ---------------------------------------------------------------------------------

    def handle(self, message: bytes) -> bytes | None:
        """Answer one query; None when the message is not a DNS query we can parse."""
        try:
            question = parse_question(message)
        except ValueError:
            if len(message) >= _HEADER.size:
                qid, _flags, *_ = _HEADER.unpack_from(message)
                head = _HEADER.pack(qid, 0x8180 | RCODE_FORMERR, 0, 0, 0, 0)
                return head
            return None
        answer = self.decide(question)
        response = (
            build_cname_response(question, answer.allowed, rcode=answer.rcode, ttl=self.ttl)
            if question.qtype == TYPE_CNAME
            else build_response(question, answer.allowed, rcode=answer.rcode, ttl=self.ttl)
        )
        self._audit(question, answer)
        return response

    def _audit(self, question: Question, answer: Answer) -> None:
        write = getattr(self.audit, "write_dns", None)
        if write is None:  # pragma: no cover - the broker always passes an AuditLog
            return
        qtype_name = {
            TYPE_A: "A",
            TYPE_AAAA: "AAAA",
            TYPE_CNAME: "CNAME",
        }.get(question.qtype, str(question.qtype))
        write(
            {
                "kind": "dns",
                "name": question.name,
                "qtype": qtype_name,
                "answers": list(answer.allowed),
                "dropped": list(answer.denied),
                "decision": "allow" if answer.rcode == RCODE_NOERROR else "deny",
                "reason": answer.reason,
                "rcode": rcode_name(answer.rcode),
            }
        )


def _read_exact(stream: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise ValueError("truncated DNS response")
        data += chunk
    return data


def _normalize(name: str) -> str:
    return name.strip().lower().rstrip(".")
