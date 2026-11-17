"""Reference conformance checks required by this contract bundle.

Every schema consumer must enable these semantic formats, including generated
DTO validators. These functions validate values; M07 still owns normalization.
"""
from __future__ import annotations

from ipaddress import ip_address, ip_network
from importlib.resources import files
from pathlib import Path
import re
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from jsonschema import FormatChecker
from openapi_spec_validator import OpenAPIV31SpecValidator


DOMAIN = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
TIMEZONES = frozenset(files("tzdata").joinpath("zones").read_text().splitlines())


def domain_name(value: str) -> bool:
    return bool(DOMAIN.fullmatch(value))


def domain_seed(value: str) -> bool:
    try:
        # Preserve the original seed; validate the normalized IDNA candidate.
        candidate = value[:-1] if value.endswith(".") else value
        return domain_name(candidate.encode("idna").decode("ascii").lower())
    except UnicodeError:
        return False


def ip_literal(value: str, *, canonical: bool = False) -> bool:
    if "%" in value:  # interface-local scope IDs are not asset identities
        return False
    try:
        address = ip_address(value)
        return not canonical or str(address) == value
    except ValueError:
        return False


def ip_or_cidr(value: str) -> bool:
    if "/" not in value:
        return ip_literal(value)
    if "%" in value:
        return False
    try:
        address, prefix = value.rsplit("/", 1)
        if not prefix.isascii() or not prefix.isdigit():
            return False
        ip_address(address)
        ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def canonical_key(value: str) -> bool:
    kind, _, body = value.partition(":")
    if kind == "dns":
        return domain_name(body)
    if kind == "ip":
        return ip_literal(body, canonical=True)
    if kind == "service":
        address, _, transport = body.rpartition("/")
        host, _, port = address.rpartition(":")
        bracketed = host.startswith("[") and host.endswith("]")
        host = host[1:-1] if bracketed else host
        return (
            transport in {"tcp", "udp"}
            and ip_literal(host, canonical=True)
            and (":" in host) == bracketed
            and 1 <= len(port) <= 5 and port.isascii() and port.isdigit()
            and str(int(port)) == port and 1 <= int(port) <= 65535
        )
    if kind in {"app", "url"}:
        try:
            parsed = urlsplit(body)
            host = parsed.hostname or ""
            authority = f"[{host}]:{parsed.port}" if ":" in host else f"{host}:{parsed.port}"
            return (
                parsed.scheme in {"http", "https"}
                and parsed.username is None and parsed.password is None
                and parsed.port is not None and 1 <= parsed.port <= 65535
                and parsed.netloc == authority
                and not parsed.fragment
                and (ip_literal(host, canonical=True) or domain_name(host))
                and (kind == "url" or not parsed.path and not parsed.query)
            )
        except ValueError:
            return False
    # Other namespaces are checked by their schema branches.
    return True


def iana_timezone(value: str) -> bool:
    if value not in TIMEZONES:
        return False
    try:
        ZoneInfo(value)
        return True
    except (ZoneInfoNotFoundError, ValueError):
        return False


def format_checker() -> FormatChecker:
    checker = FormatChecker()
    checks = {
        "aegis-canonical-key": canonical_key,
        "aegis-domain-target": lambda value: domain_name(value.removeprefix("dns:")),
        "aegis-domain-seed": domain_seed,
        "aegis-ip-address": ip_literal,
        "aegis-ip-or-cidr": ip_or_cidr,
        "aegis-iana-timezone": iana_timezone,
    }
    for name, check in checks.items():
        def validate(value, check=check):
            return not isinstance(value, str) or check(value)
        checker.checks(name)(validate)
    return checker


def openapi_errors(document: dict, source: Path) -> list[str]:
    """Validate all OpenAPI3.1 objects; resolve local refs from the source URI."""
    return [
        f"/{'/'.join(map(str, error.path))}: {error.message}"
        for error in OpenAPIV31SpecValidator(
            document, base_uri=source.resolve().as_uri()
        ).iter_errors()
    ]
