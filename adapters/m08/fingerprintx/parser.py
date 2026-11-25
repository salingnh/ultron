"""fingerprintx v1.1.19 parser: the tool's JSONL output -> ResultEnvelope records (M08, G1.6b).

The core never imports a tool. M06 runs this function in the contained parser child named by the
pinned manifest (`parser.entrypoint: adapters.m08.fingerprintx.parser:parse`), so the module is
stdlib-only and has no clock, no network, no environment and no database access:

    parse(output_dir, task, evidence) -> ParsedResults

It reads what fingerprintx writes with `-l /in/targets.txt --json -o /out/result.jsonl`: one JSON
object per open service it recognised, with the plugin's protocol name, whether TLS was used, the
`transport`, the version/banner string the plugin collected and a protocol-specific `metadata`
object. The collector (M06) stamps `observed_at` and copies the task pins into `provenance`, so
nothing here depends on when or where the job ran.

Mapping (the manifest's `emits` block: service / `service.protocol`, `service.banner`,
`service.product`):

  * `service.protocol` - the plugin's protocol name, lowercased (`http`, `https`, `ssh`,
    `postgresql`, ...). It is the tool's claim about the application protocol on that port, not a
    port-number guess: fingerprintx runs its plugins and reports the one that answered.
  * `service.banner` - the raw banner/version string when the plugin collected one: the SSH/FTP/
    SMTP/POP3 `banner` field, else the top-level `version` the plugin passed (for HTTP plugins that
    is the `Server` response header). Absent when the plugin reported none - a blank banner is
    recorded as no observation, never as `""`.
  * `service.product` - `{product, version, cpe}` when a product or version is known: the first
    versioned CPE the plugin produced (`metadata.cpes`, fingerprintx's own mapping), else built
    from the version/banner by the rule below. No version means no CPE (a `cpe:...:*` wildcard
    proves nothing and would feed CVE matching a product it cannot pin); the object then carries
    only `product`, and no `product` at all means no observation.

CPE 2.3 rule (documented here because the value ends up in `service.product.cpe`):
  1. a plugin CPE (`metadata.cpes`) is used as-is when its version field is concrete; the
     `product`, `vendor` and `version` fields are read from that CPE;
  2. otherwise split the version/banner on the first `/`, `_` or space whose right-hand side starts
     with `v?<digit>`: `nginx/1.29.8`, `OpenSSH_9.2p1`, `SimpleHTTP/0.6 Python/3.10.6` ->
     `(nginx, 1.29.8)`, `(OpenSSH, 9.2p1)`, `(SimpleHTTP, 0.6)`;
  3. the product token is lowercased and looked up in `CPE_PRODUCTS` (the small, reviewed table in
     this file) for `(vendor, product)`; without an entry, vendor = product token. The table holds
     only mappings that are unambiguous in NVD, and a product missing from it is built as
     `vendor == product`, which is the CPE convention for single-vendor products;
  4. the version keeps only CPE 2.3's allowed characters (`[A-Za-z0-9._~-]`), drops a leading
     `v`/`V` and trailing separators; an empty version means no CPE.

A line whose JSON is malformed, whose address is not an IP, whose port/transport is not a valid
`service:` key part, or that names a service this job did not target raises `ParserInputError`: a
corrupt or swapped output file is a job error the runner quarantines, never a quietly partial
result.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

__all__ = ["CPE_PRODUCTS", "ParserInputError", "RESULT_FILE", "parse"]

RESULT_FILE = "result.jsonl"
#: `local_ref` of the raw file M06 stores and hands to the parser (collector evidence list).
RAW_REF = "raw"
PROTOCOL_CONFIDENCE = 1.0
PRODUCT_CONFIDENCE = 0.8
#: version/banner fields a plugin may use; the protocol's own object carries its banner here.
BANNER_FIELDS = ("banner", "serverData")
#: `(vendor, product)` in NVD for products this chain meets; the key is the lowercased token the
#: tool reports. Add a row only with the NVD CPE dictionary entry it mirrors.
CPE_PRODUCTS: dict[str, tuple[str, str]] = {
    "nginx": ("nginx", "nginx"),
    "apache": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "openssh": ("openbsd", "openssh"),
    "openbsd": ("openbsd", "openssh"),
    "postgresql": ("postgresql", "postgresql"),
    "postgres": ("postgresql", "postgresql"),
    "jetty": ("eclipse", "jetty"),
    "tomcat": ("apache", "tomcat"),
    "mysql": ("mysql", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "redis": ("redis", "redis"),
}
_VERSION = re.compile(r"^[vV]?(?P<version>[0-9][0-9A-Za-z._~-]*)")
_CPE_PART = re.compile(r"^[A-Za-z0-9._~-]+$")


class ParserInputError(ValueError):
    """The output does not have the shape this pinned tool version writes."""


def parse(output_dir: Path, task: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    """Map fingerprintx's JSONL in `output_dir` to observations for the services it recognised."""
    targets = sorted({_service_key(value) for value in _input_targets(task)})
    targets_set = set(targets)
    observations: list[dict[str, Any]] = []
    for line_number, record in _records(Path(output_dir)):
        key = _record_key(record, line_number)
        if key not in targets_set:
            raise ParserInputError(
                f"{RESULT_FILE}:{line_number} reports {key!r}, which this job did not target"
            )
        protocol = _protocol(record, line_number)
        observations.append(_observation(key, "service.protocol", protocol, PROTOCOL_CONFIDENCE))
        banner = _banner(record)
        if banner is not None:
            observations.append(_observation(key, "service.banner", banner, PRODUCT_CONFIDENCE))
        product = _product(record)
        if product is not None:
            observations.append(_observation(key, "service.product", product, PRODUCT_CONFIDENCE))
    return {
        "assets": [],
        "observations": observations,
        "relationships": [],
        "findings": [],
        "coverage_subjects": targets,
    }


def _observation(subject: str, predicate: str, value: Any, confidence: float) -> dict[str, Any]:
    return {
        "subject": subject,
        "predicate": predicate,
        "value": value,
        "confidence": confidence,
        "evidence_refs": [{"local_ref": RAW_REF}],
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


def _record_key(record: dict[str, Any], line_number: int) -> str:
    raw_ip = record.get("ip")
    port = record.get("port")
    transport = record.get("transport")
    if not isinstance(raw_ip, str) or not raw_ip.strip():
        raise ParserInputError(f"{RESULT_FILE}:{line_number} has no ip")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ParserInputError(f"{RESULT_FILE}:{line_number} has an invalid port {port!r}")
    if transport != "tcp":
        # The capability's input schema refuses /udp targets, so a UDP record means the job ran a
        # different argv than the pinned one; recording it as a TCP service would be a false key.
        raise ParserInputError(
            f"{RESULT_FILE}:{line_number} reports transport {transport!r}; this capability only "
            "scans TCP services"
        )
    return f"service:{_canonical_address(raw_ip, line_number)}:{port}/{transport}"


def _protocol(record: dict[str, Any], line_number: int) -> str:
    protocol = record.get("protocol")
    if not isinstance(protocol, str) or not protocol.strip():
        raise ParserInputError(f"{RESULT_FILE}:{line_number} has no protocol")
    return protocol.strip().lower()


def _banner(record: dict[str, Any]) -> str | None:
    metadata = record.get("metadata")
    if isinstance(metadata, dict):
        for field in BANNER_FIELDS:
            value = metadata.get(field)
            if isinstance(value, str) and value.strip():
                return value.strip()
    version = record.get("version")
    if isinstance(version, str) and version.strip():
        return version.strip()
    return None


#: An SSH identification string is `SSH-<protocol>-<software>[-<comments>]` (RFC 4253 §4.2). The
#: prefix is the protocol, not part of the product, so it is dropped before the product/version
#: split; keeping it would build a `ssh-2.0-openssh` product and a CPE no CVE can match.
SSH_IDENTIFICATION = re.compile(r"^SSH-[0-9.]+-(?P<software>\S+)", re.IGNORECASE)


def _product_banner(banner: str) -> str:
    match = SSH_IDENTIFICATION.match(banner)
    return match.group("software") if match is not None else banner


def _product(record: dict[str, Any]) -> dict[str, Any] | None:
    """`{product, version, cpe}` for one record, or None when the plugin identified no product.

    Order of preference (the documented CPE rule): the tool's own CPE when it carries a concrete
    version; the tool's CPE vendor/product filled with the version this run read (fingerprintx
    emits wildcard-version CPEs on purpose and lets the caller enrich them, which is also how its
    `EnrichCPEVersions` works); then the reviewed table for the product token. A product without a
    version keeps only `product` - no CPE.
    """
    metadata = record.get("metadata")
    raw_cpes = metadata.get("cpes") if isinstance(metadata, dict) else None
    cpes = (
        [entry for entry in raw_cpes if isinstance(entry, str)]
        if isinstance(raw_cpes, list)
        else []
    )
    banner = _banner(record)
    source = _product_banner(banner) if banner else None
    split = _split_product_version(source) if source else None
    token, version = split if split is not None else (None, None)
    for cpe in cpes:
        fields = _cpe_fields(cpe)
        if fields is not None:
            product, cpe_version = fields
            return {"product": product, "version": cpe_version, "cpe": cpe.strip()}
    if token and version:
        mapped = CPE_PRODUCTS.get(token, (token, token))[1]
        for cpe in cpes:
            parts = cpe.strip().split(":")
            if len(parts) < 13 or parts[:3] != ["cpe", "2.3", "a"]:
                continue
            vendor, product = parts[3], parts[4]
            if product not in {mapped, token}:
                continue
            built = _cpe_23(vendor, product, version)
            if built is not None:
                return {"product": product, "version": version, "cpe": built}
    if token is None:
        return None
    vendor, product = CPE_PRODUCTS.get(token, (token, token))
    value: dict[str, Any] = {"product": product}
    if version is not None:
        value["version"] = version
        built = _cpe_23(vendor, product, version)
        if built is not None:
            value["cpe"] = built
    return value


def _split_product_version(text: str) -> tuple[str, str | None] | None:
    """Split `product<sep>version` on the first separator whose right side starts with a version."""
    candidate = text.strip()
    for index, char in enumerate(candidate):
        if char not in "/_ ":
            continue
        left, right = candidate[:index].strip(), candidate[index + 1 :].strip()
        if not left or not right:
            continue
        match = _VERSION.match(right)
        if match is None:
            continue
        # The product token is lowercased here, once: the CPE table and the tool's own CPE use
        # lowercase names, and an `OpenSSH`/`Apache` token would miss the table and build a
        # `<product>:<product>` CPE no CVE dictionary entry matches.
        return left.lower(), _normalise_version(match.group("version"))
    token = candidate.split()[0] if candidate.split() else ""
    if not token or not _CPE_PART.match(token):
        return None
    return token.lower(), None


def _normalise_version(raw: str) -> str | None:
    text = raw.strip().lstrip("vV")
    text = text.split()[0] if text.split() else ""
    text = re.sub(r"[^0-9A-Za-z._~-]", "", text).rstrip("._-")
    return text or None


def _cpe_fields(cpe: Any) -> tuple[str, str | None] | None:
    """`(product, version)` of a CPE 2.3 string with a concrete version, else None."""
    if not isinstance(cpe, str):
        return None
    parts = cpe.strip().split(":")
    if len(parts) < 13 or parts[0] != "cpe" or parts[1] != "2.3" or parts[2] != "a":
        return None
    product, version = parts[4], parts[5]
    if not _CPE_PART.match(product) or version in {"", "*", "-"}:
        return None
    normalised = _normalise_version(version)
    return (product, normalised) if normalised else None


def _cpe_23(vendor: str, product: str, version: str) -> str | None:
    if not _CPE_PART.match(vendor) or not _CPE_PART.match(product):
        return None
    return f"cpe:2.3:a:{vendor.lower()}:{product.lower()}:{version}:*:*:*:*:*:*:*"


def _canonical_address(value: str, line_number: int | None) -> str:
    where = "input target" if line_number is None else f"{RESULT_FILE}:{line_number}"
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as error:
        raise ParserInputError(f"{where}: {value!r} is not an IP address") from error
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return f"[{address}]" if isinstance(address, ipaddress.IPv6Address) else str(address)


def _input_targets(task: dict[str, Any]) -> list[str]:
    targets = (task.get("input") or {}).get("targets")
    if not isinstance(targets, list) or not targets:
        raise ParserInputError("the approved task carries no input.targets")
    return [str(value) for value in targets]


def _service_key(value: str) -> str:
    """`service:<ip>:<port>/<transport>` in canonical form, or a loud error."""
    text = value.strip().lower()
    if not text.startswith("service:"):
        raise ParserInputError(f"input target {value!r} is not a service canonical key")
    body = text[len("service:") :]
    host, _, tail = body.rpartition(":")
    port, _, transport = tail.partition("/")
    if not host or not port.isdigit() or transport not in {"tcp", "udp"}:
        raise ParserInputError(f"input target {value!r} is not service:<ip>:<port>/<transport>")
    canonical = _canonical_address(host.strip("[]"), None)
    return f"service:{canonical}:{int(port)}/{transport}"
