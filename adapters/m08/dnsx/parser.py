"""DNSx v1.2.2 parser: the tool's JSONL output -> ResultEnvelope records (M08, G1.3b).

The core never imports a tool. M06 runs this function in the contained parser child named by the
pinned manifest (`parser.entrypoint: adapters.m08.dnsx.parser:parse`), so the module is stdlib-only
and has no clock, no network, no environment and no database access:

    parse(output_dir, task, evidence) -> ParsedResults

It reads what DNSx writes with `-silent -json -o /out/result.jsonl`: one JSON object per queried
name, with the record sets it was asked for (`a`, `aaaa`, `cname`, ...) and `ttl`, plus the
`status_code` of the answer. The collector (M06) stamps `observed_at` and copies the task pins into
`provenance`, so nothing here depends on when or where the job ran.

Mapping (the manifest's `emits` block: domain, ip / `asset.seen`, `dns.record`, `dns.resolves`):
  * `A` and `AAAA` answers become `dns.record` observations `{type, value, ttl}`;
  * each answer is an `ip` asset (first host that produced it is `discovered_from`) with
    `asset.seen: true` and a `RESOLVES_TO` edge from the queried name;
  * `dns.resolves: true` only for a name this run actually resolved: a name with the answer code
    NXDOMAIN/REFUSED (or no address at all) produces no observation. Claiming it resolves would be a
    false statement in the graph, and "did not resolve" is an absence claim (`polarity: absent`)
    that belongs to whoever owns that policy decision, not to a parser default.

Not emitted, on purpose (both need a contract decision first, see the adapter README):
  * `cname`/`mx`/`ns`/`txt` answers: the pinned manifest's `argsTemplate` never asks DNSx for them
    (`record_types` is not rendered into argv), so a production run cannot produce them; mapping a
    CNAME target to an asset or an edge is an S1.5b shape decision.
  * `soa`/`ns`/`raw_resp` noise the tool writes with `-json`: not identity, and the SOA belongs to
    the zone, not to the queried name.

Canonical keys follow `aegis-norm/1`: addresses are taken through `ipaddress` (so `2001:DB8::10`
and `::ffff:203.0.113.10` become `2001:db8::10` and `203.0.113.10`, the IPv4-mapped form M27 also
collapses), names are lowercased with one trailing root dot dropped and the `dns:` prefix. The
adapter test checks every key against the contract `CanonicalKey` format, so a key the contract
would reject fails the gate instead of reaching M27.

A line whose JSON is malformed, that has no `host`, or whose address is not an IP raises
`ParserInputError`: a truncating or corrupt output file is a job error the runner quarantines,
never a quietly partial result.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

__all__ = ["ADDRESS_FIELDS", "ParserInputError", "RESULT_FILE", "parse"]

RESULT_FILE = "result.jsonl"
#: `local_ref` of the raw file M06 stores and hands to the parser (collector evidence list).
RAW_REF = "raw"
#: Record set in the tool's JSON -> observation type, in the order the answer is reported.
ADDRESS_FIELDS = (("a", "A"), ("aaaa", "AAAA"))
RECORD_CONFIDENCE = 1.0
ASSET_CONFIDENCE = 1.0


class ParserInputError(ValueError):
    """The output does not have the shape this pinned tool version writes."""


def parse(output_dir: Path, task: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    """Map DNSx's JSONL in `output_dir` to assets, observations, relationships, coverage."""
    targets = sorted({_domain_key(value) for value in _input_targets(task)})
    assets: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    seen_ips: dict[str, dict[str, Any]] = {}
    resolved: list[str] = []
    for line_number, record in _records(Path(output_dir)):
        host_key = _host_key(record, line_number)
        ttl = _ttl(record, line_number)
        answered = False
        for field, record_type in ADDRESS_FIELDS:
            for value in _addresses(record, field, line_number):
                ip_key = f"ip:{_canonical_address(value, line_number, field)}"
                observations.append(
                    {
                        "subject": host_key,
                        "predicate": "dns.record",
                        "value": {
                            "type": record_type,
                            "value": ip_key.removeprefix("ip:"),
                            "ttl": ttl,
                        },
                        "confidence": RECORD_CONFIDENCE,
                        "evidence_refs": _evidence_refs(),
                    }
                )
                relationships.append(
                    {
                        "type": "RESOLVES_TO",
                        "from": host_key,
                        "to": ip_key,
                        "confidence": RECORD_CONFIDENCE,
                        "evidence_refs": _evidence_refs(),
                    }
                )
                if ip_key not in seen_ips:
                    seen_ips[ip_key] = {
                        "kind": "ip",
                        "canonical_key": ip_key,
                        "discovered_from": [host_key],
                        "confidence": ASSET_CONFIDENCE,
                        "evidence_refs": _evidence_refs(),
                    }
                answered = True
        if answered and host_key not in resolved:
            resolved.append(host_key)
    assets.extend(seen_ips.values())
    for host_key in resolved:
        observations.append(
            {
                "subject": host_key,
                "predicate": "dns.resolves",
                "value": True,
                "confidence": RECORD_CONFIDENCE,
                "evidence_refs": _evidence_refs(),
            }
        )
    for ip_key in seen_ips:
        observations.append(
            {
                "subject": ip_key,
                "predicate": "asset.seen",
                "value": True,
                "confidence": ASSET_CONFIDENCE,
                "evidence_refs": _evidence_refs(),
            }
        )
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


def _host_key(record: dict[str, Any], line_number: int) -> str:
    host = record.get("host")
    if not isinstance(host, str) or not host.strip():
        raise ParserInputError(f"{RESULT_FILE}:{line_number} has no host")
    return _domain_key(host)


def _ttl(record: dict[str, Any], line_number: int) -> int | None:
    ttl = record.get("ttl")
    if ttl is None:
        return None
    if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl < 0:
        raise ParserInputError(f"{RESULT_FILE}:{line_number} has a non-integer ttl {ttl!r}")
    return ttl


def _addresses(record: dict[str, Any], field: str, line_number: int) -> list[str]:
    values = record.get(field)
    if values is None:
        return []
    if not isinstance(values, list):
        raise ParserInputError(f"{RESULT_FILE}:{line_number} field {field!r} is not a list")
    out: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value:
            raise ParserInputError(
                f"{RESULT_FILE}:{line_number} field {field!r} holds a non-string entry"
            )
        out.append(value)
    return out


def _canonical_address(value: str, line_number: int, field: str) -> str:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as error:
        raise ParserInputError(
            f"{RESULT_FILE}:{line_number} field {field!r}: {value!r} is not an IP address"
        ) from error
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        # Same collapse as aegis-norm/1: a v4-mapped v6 address is the IPv4 identity, and the
        # `ip:` CanonicalKey pattern has no room for the dotted tail.
        address = address.ipv4_mapped
    return str(address)


def _input_targets(task: dict[str, Any]) -> list[str]:
    targets = (task.get("input") or {}).get("targets")
    if not isinstance(targets, list) or not targets:
        raise ParserInputError("the approved task carries no input.targets")
    return [str(value) for value in targets]


def _domain_key(value: str) -> str:
    text = value.strip().lower().rstrip(".")
    return text if text.startswith("dns:") else f"dns:{text}"


def _evidence_refs() -> list[dict[str, str]]:
    """The raw file this parser read; the collector stores it under `local_ref` `raw`."""
    return [{"local_ref": RAW_REF}]
