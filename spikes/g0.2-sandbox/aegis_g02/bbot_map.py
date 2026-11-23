"""BBOT passive JSON (NDJSON) -> ParsedResults -> ResultEnvelope (spike G0.2).

Scope: prove the shape mapping for the passive-discovery events G1 needs
(DNS_NAME, IP_ADDRESS, OPEN_TCP_PORT, URL, HTTP_RESPONSE, TECHNOLOGY, ASN,
EMAIL_ADDRESS), not a finished adapter. Anything the current contract cannot
express is counted as unmapped with a reason instead of being invented.

Assumptions checked by the report:
  * BBOT emits one JSON object per line; ``type``/``data`` are the only
    mandatory keys and the rest are attributes.
  * ``scope_description`` holds the parent scope(s) of a discovered name.
  * ``resolved_hosts`` carries the A/AAAA answers of a DNS_NAME event.
  * CanonicalKey comes from M07; this module only builds the same strings so
    the envelope validates (G0.3c owns the real normalization rules).
"""

from __future__ import annotations

import ast
import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

DEFAULT_PORTS = {"http": 80, "https": 443}


def uuid7() -> str:
    """UUIDv7 as required by ids.v2 Id."""
    unix_ms = int(time.time() * 1000)
    rand = uuid.uuid4().int
    value = (unix_ms & ((1 << 48) - 1)) << 80
    value |= 0x7 << 76
    value |= (rand >> 64) & 0xFFF << 64
    value |= 0b10 << 62
    value |= rand & ((1 << 62) - 1)
    return str(uuid.UUID(int=value))


def canonical_domain(name: str) -> str:
    return f"dns:{name.strip().rstrip('.').lower()}"


def canonical_ip(value: str) -> str:
    import ipaddress

    return f"ip:{ipaddress.ip_address(value)}"


def canonical_service(ip: str, port: int, proto: str = "tcp") -> str:
    import ipaddress

    addr = ipaddress.ip_address(ip)
    host = f"[{addr}]" if addr.version == 6 else str(addr)
    return f"service:{host}:{port}/{proto}"


def canonical_url(url: str) -> str | None:
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    port = parts.port or DEFAULT_PORTS[parts.scheme]
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    return f"url:{parts.scheme}://{parts.hostname}:{port}/{path.lstrip('/')}"


def canonical_application(url: str) -> str | None:
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    port = parts.port or DEFAULT_PORTS[parts.scheme]
    return f"app:{parts.scheme}://{parts.hostname}:{port}"


def canonical_email(address: str) -> str:
    return f"email:{address.strip().lower()}"


@dataclass
class ParsedResults:
    assets: dict[str, dict] = field(default_factory=dict)
    observations: list[dict] = field(default_factory=list)
    relationships: list[dict] = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    coverage: set[str] = field(default_factory=set)
    unmapped: list[dict] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)

    def asset(self, kind: str, key: str, **extra) -> None:
        node = self.assets.setdefault(key, {"kind": kind, "canonical_key": key})
        node.update({k: v for k, v in extra.items() if v is not None})

    def observe(self, subject: str, predicate: str, value, observed_at: str) -> None:
        self.observations.append(
            {
                "subject": subject,
                "predicate": predicate,
                "value": value,
                "observed_at": observed_at,
            }
        )

    def relate(self, rel: str, src: str, dst: str, observed_at: str) -> None:
        key = (rel, src, dst)
        self.relationships[key] = {
            "type": rel,
            "from": src,
            "to": dst,
            "observed_at": observed_at,
            "confidence": 0.9,
        }


def _ts(event: dict, fallback: str) -> str:
    raw = event.get("timestamp")
    if isinstance(raw, (int, float)):
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(raw))
    return fallback


def _parents(event: dict) -> list[str]:
    """Parents of a discovered name.

    BBOT serializes ``scope_description`` with ``str()`` in some versions, so a
    JSON dump can carry "[\'a.example\']" instead of a list; accept both and
    never raise on unexpected shapes.
    """
    raw = event.get("scope_description")
    if isinstance(raw, (list, tuple, set)):
        return [str(item) for item in raw if item]
    if isinstance(raw, str):
        text = raw.strip()
        if text[:1] in "[{(":
            try:
                parsed = ast.literal_eval(text)
            except (ValueError, SyntaxError):
                return [text] if text else []
            if isinstance(parsed, (list, tuple, set)):
                return [str(item) for item in parsed if item]
            return [str(parsed)]
        return [text] if text else []
    return []


def _resolved(event: dict) -> list[str]:
    hosts = event.get("resolved_hosts") or []
    if isinstance(hosts, str):
        hosts = [hosts]
    return [h for h in hosts if isinstance(h, str)]


def map_events(events: Iterable[dict], *, observed_at: str) -> ParsedResults:
    parsed = ParsedResults()
    for event in events:
        kind = str(event.get("type", "")).upper()
        data = event.get("data")
        when = _ts(event, observed_at)
        parsed.counts[kind] = parsed.counts.get(kind, 0) + 1
        if kind in ("DNS_NAME", "DNS_NAME_UNRESOLVED"):
            if not isinstance(data, str) or not data:
                parsed.unmapped.append({"type": kind, "reason": "NO_DATA"})
                continue
            key = canonical_domain(data)
            parsed.asset("domain", key)
            parsed.coverage.add(key)
            for parent in _parents(event):
                if isinstance(parent, str) and parent and data.rstrip(".") != parent:
                    parsed.asset("domain", canonical_domain(parent))
                    parsed.relate("SUBDOMAIN_OF", key, canonical_domain(parent), when)
            for ip in _resolved(event):
                try:
                    parsed.asset("ip", canonical_ip(ip))
                except ValueError:
                    parsed.unmapped.append({"type": kind, "reason": "BAD_IP", "value": ip})
                    continue
                parsed.relate("RESOLVES_TO", key, canonical_ip(ip), when)
            if kind == "DNS_NAME_UNRESOLVED":
                parsed.observe(key, "dns.resolves", False, when)
        elif kind == "IP_ADDRESS":
            if not isinstance(data, str):
                parsed.unmapped.append({"type": kind, "reason": "NO_DATA"})
                continue
            try:
                parsed.asset("ip", canonical_ip(data))
            except ValueError:
                parsed.unmapped.append({"type": kind, "reason": "BAD_IP", "value": data})
        elif kind == "OPEN_TCP_PORT":
            if not isinstance(data, str) or ":" not in data:
                # bbot 3.x also emits host/port as separate JSON keys.
                if isinstance(event.get("host"), str) and isinstance(event.get("port"), int):
                    data = f"{event['host']}:{event['port']}"
                else:
                    parsed.unmapped.append({"type": kind, "reason": "NO_HOST_PORT"})
                    continue
            host, _, port_text = data.rpartition(":")
            if not port_text.isdigit():
                parsed.unmapped.append({"type": kind, "reason": "BAD_PORT", "value": data})
                continue
            port = int(port_text)
            addresses = _resolved(event) or [host]
            for ip in addresses:
                try:
                    key = canonical_service(ip, port)
                except ValueError:
                    parsed.unmapped.append(
                        {"type": kind, "reason": "OPEN_PORT_WITHOUT_IP", "value": data}
                    )
                    continue
                parsed.asset("service", key)
                parsed.observe(key, "net.port_state", "open", when)
                parsed.relate("EXPOSES", canonical_ip(ip), key, when)
                if host:
                    try:
                        parsed.relate("EXPOSES", canonical_domain(host), key, when)
                    except ValueError:
                        pass
        elif kind in ("URL", "HTTP_RESPONSE", "WEB_HEADER"):
            url = data if isinstance(data, str) else event.get("url")
            key = canonical_url(url) if isinstance(url, str) else None
            app = canonical_application(url) if isinstance(url, str) else None
            if key is None or app is None:
                parsed.unmapped.append({"type": kind, "reason": "BAD_URL", "value": url})
                continue
            parsed.asset("url", key)
            parsed.asset("application", app)
            parsed.relate("HAS_ENDPOINT", app, key, when)
            parsed.coverage.add(key)
            if kind == "HTTP_RESPONSE" and isinstance(event.get("status_code"), int):
                parsed.observe(app, "http.status", event["status_code"], when)
        elif kind == "TECHNOLOGY":
            if not isinstance(data, str):
                parsed.unmapped.append({"type": kind, "reason": "NO_DATA"})
                continue
            url = event.get("url") or f"https://{event.get('host', '')}/"
            app = canonical_application(url) if isinstance(url, str) else None
            if app is None:
                parsed.unmapped.append({"type": kind, "reason": "NO_HOST"})
                continue
            parsed.asset("application", app)
            parsed.observe(app, "http.technology", [data], when)
        elif kind == "ASN":
            host = event.get("host")
            asn = str(data).split(":")[-1] if data else None
            if not host or not asn:
                parsed.unmapped.append({"type": kind, "reason": "NO_ASN_OR_HOST"})
                continue
            try:
                subject = canonical_ip(host)
            except ValueError:
                parsed.unmapped.append({"type": kind, "reason": "ASN_HOST_NOT_AN_IP"})
                continue
            value = {"asn": int(asn) if asn.isdigit() else asn}
            if event.get("netname"):
                value["org"] = event["netname"]
            if event.get("cidr"):
                value["cidr"] = event["cidr"]
            parsed.observe(subject, "net.asn", value, when)
        elif kind == "EMAIL_ADDRESS":
            if not isinstance(data, str) or "@" not in data:
                parsed.unmapped.append({"type": kind, "reason": "NO_DATA"})
                continue
            parsed.asset("email", canonical_email(data))
        else:
            parsed.unmapped.append({"type": kind, "reason": "NO_MAPPING"})
    return parsed


def read_events(path: Path) -> list[dict]:
    events = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def build_envelope(
    parsed: ParsedResults,
    *,
    job_id: str,
    campaign_id: str,
    scope_id: str,
    capability: str,
    provider: dict,
    policy_version: str,
    seed_targets: list[str],
    input_fingerprint: str,
    started_at: str,
    finished_at: str,
    trace_id: str,
    status: str = "succeeded",
) -> dict:
    if parsed.unmapped:
        status = "partial"
    return {
        "schema_version": "2.0",
        "event_id": uuid7(),
        "dedup_key": f"job:{job_id}:envelope",
        "job_id": job_id,
        "campaign_id": campaign_id,
        "scope_id": scope_id,
        "capability": capability,
        "provider": provider,
        "policy_version": policy_version,
        "status": status,
        "coverage": {"subjects": sorted(parsed.coverage)},
        "results": {
            "assets": sorted(parsed.assets.values(), key=lambda a: a["canonical_key"]),
            "observations": parsed.observations,
            "relationships": sorted(
                parsed.relationships.values(), key=lambda r: (r["type"], r["from"], r["to"])
            ),
            "findings": parsed.findings,
        },
        "evidence": [],
        "errors": [],
        "provenance": {
            "input_fingerprint": input_fingerprint,
            "started_at": started_at,
            "finished_at": finished_at,
            "seed_targets": seed_targets,
        },
        "trace": {"trace_id": trace_id},
    }
