"""Naabu v2.7.0 parser: the tool's JSONL output -> ResultEnvelope records (M09, G1.6a).

The core never imports a tool. M06 runs this function in the contained parser child named by the
pinned manifest (`parser.entrypoint: adapters.m09.naabu.parser:parse`), so the module is
stdlib-only and has no clock, no network, no environment and no database access:

    parse(output_dir, task, evidence) -> ParsedResults

It reads what Naabu writes with `-silent -json -s connect -list /in/targets.txt -ports-file
/in/ports.txt -o /out/result.jsonl`: one JSON object per *open* port, e.g.

    {"ip":"10.114.53.211","port":443,"protocol":"tcp","tls":true,"timestamp":"..."}

Naabu reports only ports that answered, so the file is the positive evidence of the scan; a port
that is closed or filtered is absent, and this parser never claims `net.port_state` for it (an
absence claim belongs to whoever owns that policy decision, not to a parser default).

Mapping (the manifest's `emits` block: service / `asset.seen`, `net.port_state`,
`service.protocol`, `EXPOSES`):
  * one `service` asset per (address, port, transport), canonical key
    `service:<ip>:<port>/<tcp|udp>` per `aegis-norm/1` (IPv6 bracketed, IPv4-mapped input
    collapsed), `discovered_from` the IP key M05 signed into the task;
  * `EXPOSES` from that `ip:` key to the service key - the edge the graph model reserves for
    "this address answers on this port";
  * `net.port_state: "open"` and `service.protocol: "<tcp|udp>"` observations on the service.

What this parser deliberately does not do: it does not invent a `:Application` node or a `SERVES`
edge. A port that answers is a *service* by address and transport; whether an HTTP server, a
database or an SSH daemon is behind it is the next capability's result (`web.probe`,
`service.banner`), not something a port scan may guess.

Canonical keys follow `aegis-norm/1`: addresses go through `ipaddress` (so `2001:DB8::10` and
`::ffff:203.0.113.10` become `2001:db8::10` and `203.0.113.10`, the IPv4-mapped form M27 also
collapses) and the host is bracketed inside a `service:` key when it contains a colon.

A line that is malformed, carries no parseable address, a non-integer/out-of-range port, an unknown
transport, or a port that the job's own `input.ports` did not bind raises `ParserInputError`: a
truncating or corrupt output file is a job error the runner quarantines, never a quietly partial
result. A port outside `input.ports` is also a binding violation - the sandbox could only reach the
ports the signed egress binding opened - so it fails loudly instead of entering the graph.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

__all__ = ["ParserInputError", "RESULT_FILE", "SERVICE_CONFIDENCE", "TRANSPORTS", "parse"]

RESULT_FILE = "result.jsonl"
#: `local_ref` of the raw file M06 stores and hands to the parser (collector evidence list).
RAW_REF = "raw"
#: Transports `aegis-norm/1` accepts in a `service:` key.
TRANSPORTS = ("tcp", "udp")
SERVICE_CONFIDENCE = 1.0
PORT_CONFIDENCE = 1.0
RELATIONSHIP_CONFIDENCE = 1.0


class ParserInputError(ValueError):
    """The output does not have the shape this pinned tool version writes."""


def parse(output_dir: Path, task: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    """Map Naabu's JSONL in `output_dir` to assets, observations, relationships, coverage."""
    targets = sorted({_ip_key(value) for value in _input_targets(task)})
    bound_ports = _bound_ports(task)
    assets: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    seen: dict[str, dict[str, Any]] = {}
    for line_number, record in _records(Path(output_dir)):
        address = _canonical_address(record, line_number)
        port = _port(record, line_number)
        if bound_ports is not None and port not in bound_ports:
            raise ParserInputError(
                f"{RESULT_FILE}:{line_number} reports port {port}, which the job did not bind "
                f"(input.ports = {sorted(bound_ports)})"
            )
        transport = _transport(record, line_number)
        ip_key = f"ip:{address}"
        service_key = _service_key(address, port, transport)
        if service_key in seen:
            continue  # the same open port reported twice is one service
        seen[service_key] = {
            "kind": "service",
            "canonical_key": service_key,
            "discovered_from": [ip_key],
            "confidence": SERVICE_CONFIDENCE,
            "evidence_refs": _evidence_refs(),
        }
        observations.extend(
            [
                {
                    "subject": service_key,
                    "predicate": "asset.seen",
                    "value": True,
                    "confidence": SERVICE_CONFIDENCE,
                    "evidence_refs": _evidence_refs(),
                },
                {
                    "subject": service_key,
                    "predicate": "net.port_state",
                    "value": "open",
                    "confidence": PORT_CONFIDENCE,
                    "evidence_refs": _evidence_refs(),
                },
                {
                    "subject": service_key,
                    "predicate": "service.protocol",
                    "value": transport,
                    "confidence": PORT_CONFIDENCE,
                    "evidence_refs": _evidence_refs(),
                },
            ]
        )
        relationships.append(
            {
                "type": "EXPOSES",
                "from": ip_key,
                "to": service_key,
                "confidence": RELATIONSHIP_CONFIDENCE,
                "evidence_refs": _evidence_refs(),
            }
        )
    assets.extend(seen.values())
    return {
        "assets": assets,
        "observations": observations,
        "relationships": relationships,
        "findings": [],
        "coverage_subjects": targets,
    }


def _records(directory: Path) -> Iterator[tuple[int, dict[str, Any]]]:
    """`(line number, object)` for every non-empty line of the tool's output file."""
    path = directory / RESULT_FILE
    if not path.is_file():
        raise ParserInputError(f"{RESULT_FILE} is missing: the tool wrote no result file")
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise ParserInputError(f"{RESULT_FILE} is not UTF-8 text: {error}") from error
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise ParserInputError(
                f"{RESULT_FILE}:{line_number} is not JSON ({error.msg})"
            ) from error
        if not isinstance(record, dict):
            raise ParserInputError(f"{RESULT_FILE}:{line_number} is not a JSON object")
        yield line_number, record


def _canonical_address(record: dict[str, Any], line_number: int) -> str:
    """The address naabu scanned: `ip` for an address target, `host` for a name target."""
    for field in ("ip", "host"):
        value = record.get(field)
        if value is None:
            continue
        if not isinstance(value, str) or not value.strip():
            raise ParserInputError(
                f"{RESULT_FILE}:{line_number} field {field!r} is not a non-empty string"
            )
        try:
            address = ipaddress.ip_address(value.strip())
        except ValueError as error:
            if field == "ip":
                raise ParserInputError(
                    f"{RESULT_FILE}:{line_number} field 'ip': {value!r} is not an IP address"
                ) from error
            # `host` may be a domain when a name was scanned; this adapter only accepts address
            # targets, so a domain here is output the pinned provider cannot produce for this job.
            raise ParserInputError(
                f"{RESULT_FILE}:{line_number} reports host {value!r} without an address"
            ) from error
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            # Same collapse as aegis-norm/1: a v4-mapped v6 address is the IPv4 identity, and the
            # `ip:` CanonicalKey pattern has no room for the dotted tail.
            address = address.ipv4_mapped
        return str(address)
    raise ParserInputError(f"{RESULT_FILE}:{line_number} has neither an 'ip' nor a 'host'")


def _port(record: dict[str, Any], line_number: int) -> int:
    port = record.get("port")
    if not isinstance(port, int) or isinstance(port, bool):
        raise ParserInputError(f"{RESULT_FILE}:{line_number} has a non-integer port {port!r}")
    if not 1 <= port <= 65535:
        raise ParserInputError(f"{RESULT_FILE}:{line_number} port {port} is out of range")
    return port


def _transport(record: dict[str, Any], line_number: int) -> str:
    value = record.get("protocol")
    if not isinstance(value, str) or value.strip().lower() not in TRANSPORTS:
        raise ParserInputError(
            f"{RESULT_FILE}:{line_number} has an unknown transport {value!r} "
            f"(expected one of {list(TRANSPORTS)})"
        )
    return value.strip().lower()


def _service_key(address: str, port: int, transport: str) -> str:
    host = f"[{address}]" if ":" in address else address
    return f"service:{host}:{port}/{transport}"


def _input_targets(task: dict[str, Any]) -> list[str]:
    targets = (task.get("input") or {}).get("targets")
    if not isinstance(targets, list) or not targets:
        raise ParserInputError("the approved task carries no input.targets")
    return [str(value) for value in targets]


def _bound_ports(task: dict[str, Any]) -> set[int] | None:
    """`input.ports`, the ports the signed binding opened; None when the task omits them."""
    ports = (task.get("input") or {}).get("ports")
    if ports is None:
        return None
    if not isinstance(ports, list) or not all(
        isinstance(port, int) and not isinstance(port, bool) for port in ports
    ):
        raise ParserInputError("input.ports must be an array of integers")
    return set(ports)


def _ip_key(value: str) -> str:
    """`input.targets` is a canonical key list; this capability accepts `ip:` addresses."""
    text = value.strip()
    if text.lower().startswith("ip:"):
        text = text[3:]
    try:
        address = ipaddress.ip_address(text)
    except ValueError as error:
        raise ParserInputError(f"input target {value!r} is not an IP address") from error
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return f"ip:{address}"


def _evidence_refs() -> list[dict[str, str]]:
    """The raw file this parser read; the collector stores it under `local_ref` `raw`."""
    return [{"local_ref": RAW_REF}]
