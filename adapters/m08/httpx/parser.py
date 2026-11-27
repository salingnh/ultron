"""httpx v1.12.0 parser: the tool's JSONL output -> Application assets and HTTP/TLS observations.

The core never imports a tool. M06 runs this function in the contained parser child named by the
pinned manifest (`parser.entrypoint: adapters.m08.httpx.parser:parse`), so the module is stdlib-only
and has no clock, no network, no environment and no database access:

    parse(output_dir, task, evidence) -> ParsedResults

It reads what httpx writes with `-l /in/targets.txt -json -silent -o /out/result.jsonl
-tech-detect -cpe -tls-grab -insecure`: one JSON object per URL it could talk HTTP to, with the
status, title, response headers, detected technologies (with versions where wappalyzergo knows
them), CPE matches, the TLS certificate it grabbed and the `input` line it came from.

The task's targets are service keys (`service:<ip>:<port>/tcp`), the file M06 writes for this
manifest is `<ip>:<port>` (`runtime.targetsFormat: host_port`), so each result is attributed back to
its service by that same `input` value. A result whose `input` is not one of the job's targets is a
corrupt or swapped output file and raises `ParserInputError`; nothing is attributed by guessing.

Mapping (the manifest's `emits` block):

  * one `application` asset `app:<scheme>://<host>:<port>` per HTTP answer (the contract's
    application key, `aegis-norm/1`), `discovered_from` = the service it answered on, and one
    `SERVES` Service -> Application edge. The scheme is the one that answered: https first, http
    when TLS failed, because the target file carries no scheme (httpx tries both by default);
  * `http.status` (integer), `http.title` (non-empty title only), `http.headers` (the response
    headers, lowercased names, sorted, capped: at most 32 headers and 512 characters per value -
    the full response stays in the raw evidence file), `http.technology` (the tool's `tech`
    entries, each `<name>` or `<name>:<version>` with the name lowercased and the version
    normalised), `tls.certificate` (`{subject_cn, sans[], issuer, not_before, not_after, sha256}`)
    on the application;
  * `service.product` (`{product, version, cpe}`) on the service, from the sources the response
    actually gives, in this order: a CPE the tool produced *with a concrete version*; the tool's own
    versionless CPE (`apache:tomcat:*`, from its fingerprint) filled with a version the response
    prints (page body or title, `Apache Tomcat/9.0.30`, or the header `X-Jenkins: 2.138`); a
    technology `-tech-detect` named with a version (`jenkins:2.138`) that `TECHNOLOGY_CPES` maps to
    its NVD `(vendor, product)`; finally a `PRODUCT_SIGNALS` match with the reviewed vendor table. A
    versionless CPE with no printed version, an unmapped technology and an unrelated title are not
    evidence: then no product observation is emitted. `-irr` carries the response body so the body
    can be read for exactly the markers listed in `PRODUCT_SIGNALS`.

`service.protocol` is deliberately not emitted here: fingerprintx owns that claim for the chain,
and two producers with different strings would turn one service into a contradiction.
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

__all__ = ["MAX_HEADER_VALUE", "MAX_HEADERS", "ParserInputError", "RESULT_FILE", "parse"]

RESULT_FILE = "result.jsonl"
#: `local_ref` of the raw file M06 stores and hands to the parser (collector evidence list).
RAW_REF = "raw"
MAX_HEADERS = 32
MAX_HEADER_VALUE = 512
MAX_TECHNOLOGIES = 64
APP_CONFIDENCE = 1.0
HTTP_CONFIDENCE = 1.0
TLS_CONFIDENCE = 1.0
PRODUCT_CONFIDENCE = 0.8
_VERSION = re.compile(r"^[vV]?(?P<version>[0-9][0-9A-Za-z._~-]*)")
_CPE_PART = re.compile(r"^[A-Za-z0-9._~-]+$")
#: Technologies the tool's own `-tech-detect` can name with a version, mapped to their NVD
#: `(vendor, product)`. `service.product` from a technology entry is the same claim the tool makes
#: in `http.technology`, with the CPE a later CVE match needs; a technology absent here keeps its
#: place in `http.technology` and is not turned into a product.
TECHNOLOGY_CPES: dict[str, tuple[str, str]] = {
    "jenkins": ("jenkins", "jenkins"),
    "jetty": ("eclipse", "jetty"),
    "tomcat": ("apache", "tomcat"),
    "nginx": ("f5", "nginx"),
    "apache http server": ("apache", "http_server"),
}
#: Product signals a response publishes itself, in the order they are trusted. Each entry is the
#: header (or `title`) to read, the pattern capturing the version, and the NVD `(vendor, product)`.
#: A product that is only inferred from behaviour (a Java stack behind a plain page) is never
#: guessed: the title and header rules cover exactly what the origin prints, and each is a fact of
#: that response that `http.title`/`http.headers` already records.
PRODUCT_SIGNALS: tuple[tuple[str, re.Pattern[str], str, str], ...] = (
    (
        "header:x-jenkins",
        re.compile(r"^\s*(?P<version>[0-9][0-9A-Za-z._~-]*)\s*$"),
        "jenkins",
        "jenkins",
    ),
    (
        "title",
        re.compile(r"Apache\s+Tomcat/(?P<version>[0-9][0-9A-Za-z._~-]*)", re.IGNORECASE),
        "apache",
        "tomcat",
    ),
    (
        # Tomcat's error/status page ends with `<h3>Apache Tomcat/9.0.30</h3>`; the page body is
        # only present with `-irr`, which this manifest passes.
        "body",
        re.compile(r"Apache\s+Tomcat/(?P<version>[0-9][0-9A-Za-z._~-]*)", re.IGNORECASE),
        "apache",
        "tomcat",
    ),
)


class ParserInputError(ValueError):
    """The output does not have the shape this pinned tool version writes."""


def parse(output_dir: Path, task: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    """Map httpx's JSONL in `output_dir` to applications, SERVES edges and http/tls observations."""
    targets = {_service_key(value): value for value in _input_targets(task)}
    applications: dict[str, dict[str, Any]] = {}
    observations: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    for line_number, record in _records(Path(output_dir)):
        service_key = _service_key_of(record, line_number, targets)
        application_key = _application_key(record, line_number)
        if application_key not in applications:
            applications[application_key] = {
                "kind": "application",
                "canonical_key": application_key,
                "discovered_from": [service_key],
                "confidence": APP_CONFIDENCE,
                "evidence_refs": _evidence_refs(),
            }
            relationships.append(
                {
                    "type": "SERVES",
                    "from": service_key,
                    "to": application_key,
                    "confidence": APP_CONFIDENCE,
                    "evidence_refs": _evidence_refs(),
                }
            )
        status = _status(record, line_number)
        observations.append(_observation(application_key, "http.status", status, HTTP_CONFIDENCE))
        title = record.get("title")
        if isinstance(title, str) and title.strip():
            observations.append(
                _observation(application_key, "http.title", title.strip(), HTTP_CONFIDENCE)
            )
        headers = _headers(record)
        if headers:
            observations.append(
                _observation(application_key, "http.headers", headers, HTTP_CONFIDENCE)
            )
        technologies = _technologies(record)
        if technologies:
            observations.append(
                _observation(application_key, "http.technology", technologies, HTTP_CONFIDENCE)
            )
        certificate = _certificate(record, line_number)
        if certificate is not None:
            observations.append(
                _observation(application_key, "tls.certificate", certificate, TLS_CONFIDENCE)
            )
        product = _product(record)
        if product is not None:
            observations.append(
                _observation(service_key, "service.product", product, PRODUCT_CONFIDENCE)
            )
    return {
        "assets": list(applications.values()),
        "observations": observations,
        "relationships": relationships,
        "findings": [],
        "coverage_subjects": sorted(targets),
    }


def _observation(subject: str, predicate: str, value: Any, confidence: float) -> dict[str, Any]:
    return {
        "subject": subject,
        "predicate": predicate,
        "value": value,
        "confidence": confidence,
        "evidence_refs": _evidence_refs(),
    }


def _evidence_refs() -> list[dict[str, str]]:
    """The raw file this parser read; the collector stores it under `local_ref` `raw`."""
    return [{"local_ref": RAW_REF}]


def _records(directory: Path) -> list[tuple[int, dict[str, Any]]]:
    """`(line number, object)` for every non-empty line of the tool's output file."""
    path = directory / RESULT_FILE
    if not path.is_file():
        raise ParserInputError(f"{RESULT_FILE} is missing: the tool wrote no result file")
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise ParserInputError(f"{RESULT_FILE} is not UTF-8 text: {error}") from error
    records: list[tuple[int, dict[str, Any]]] = []
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
        records.append((line_number, record))
    return records


def _service_key_of(record: dict[str, Any], line_number: int, targets: dict[str, str]) -> str:
    """The service a result belongs to, from the `input` line httpx echoes back."""
    raw = record.get("input")
    if not isinstance(raw, str) or not raw.strip():
        raise ParserInputError(f"{RESULT_FILE}:{line_number} has no input")
    for service_key, target in targets.items():
        if _host_port(target) == raw.strip().lower():
            return service_key
    raise ParserInputError(
        f"{RESULT_FILE}:{line_number} reports input {raw!r}, which this job did not target"
    )


def _application_key(record: dict[str, Any], line_number: int) -> str:
    url = record.get("url")
    if not isinstance(url, str) or not url.strip():
        raise ParserInputError(f"{RESULT_FILE}:{line_number} has no url")
    match = re.fullmatch(r"(?P<scheme>https?)://(?P<authority>[^/?#\s]+)/?", url.strip())
    if match is None:
        raise ParserInputError(
            f"{RESULT_FILE}:{line_number} url {url!r} is not an http(s) origin without a path"
        )
    scheme = match.group("scheme")
    host, port = _split_authority(match.group("authority").lower(), scheme, line_number)
    return f"app:{scheme}://{_authority(host, port)}"


def _split_authority(authority: str, scheme: str, line_number: int) -> tuple[str, int]:
    default = 443 if scheme == "https" else 80
    host_text, port_text = authority, ""
    if authority.startswith("["):
        host_text, _, rest = authority.partition("]")
        host_text += "]"
        port_text = rest[1:] if rest.startswith(":") else ""
    else:
        host_text, sep, tail = authority.rpartition(":")
        if not sep:
            host_text, port_text = authority, ""
        else:
            port_text = tail
    port = int(port_text) if port_text.isdigit() else default
    try:
        address = ipaddress.ip_address(host_text.strip("[]"))
    except ValueError:
        raise ParserInputError(
            f"{RESULT_FILE}:{line_number} authority {authority!r} is not an ip endpoint"
        ) from None
    if not 1 <= port <= 65535:
        raise ParserInputError(
            f"{RESULT_FILE}:{line_number} authority {authority!r} has a bad port"
        )
    return str(address), port


def _authority(address: str, port: int) -> str:
    text = str(ipaddress.ip_address(address))
    host = f"[{text}]" if ":" in text else text
    return f"{host}:{port}"


def _host_port(service_key: str) -> str:
    body = service_key[len("service:") :]
    host, _, tail = body.rpartition(":")
    port = tail.partition("/")[0]
    text = host.strip("[]")
    address = ipaddress.ip_address(text)
    shown = f"[{address}]" if address.version == 6 else str(address)
    return f"{shown}:{port}".lower()


def _status(record: dict[str, Any], line_number: int) -> int:
    status = record.get("status_code")
    if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
        raise ParserInputError(f"{RESULT_FILE}:{line_number} has an invalid status_code {status!r}")
    return status


def _headers(record: dict[str, Any]) -> dict[str, str]:
    raw = record.get("header")
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for name in sorted(raw)[:MAX_HEADERS]:
        value = raw[name]
        if isinstance(value, list):
            text = ", ".join(str(item) for item in value)
        elif isinstance(value, str):
            text = value
        else:
            continue
        name_text = str(name).strip().lower()
        if not name_text:
            continue
        out[name_text] = text[:MAX_HEADER_VALUE]
    return out


def _technologies(record: dict[str, Any]) -> list[str]:
    raw = record.get("tech")
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for item in raw[:MAX_TECHNOLOGIES]:
        if not isinstance(item, str) or not item.strip():
            continue
        name, _, version = item.strip().partition(":")
        name = name.strip().lower()
        if not name:
            continue
        normalised = _normalise_version(version) if version else None
        entry = f"{name}:{normalised}" if normalised else name
        if entry not in out:
            out.append(entry)
    return out


def _certificate(record: dict[str, Any], line_number: int) -> dict[str, Any] | None:
    raw = record.get("tls")
    if not isinstance(raw, dict):
        return None
    certificate: dict[str, Any] = {}
    subject = _first_text(raw.get("subject_cn"))
    if subject:
        certificate["subject_cn"] = subject
    sans = [str(item).strip() for item in raw.get("subject_an") or [] if str(item).strip()]
    if sans:
        certificate["sans"] = sorted(set(sans))
    issuer = _first_text(raw.get("issuer_cn")) or _first_text(raw.get("issuer_dn"))
    if issuer:
        certificate["issuer"] = issuer
    for field, source in (("not_before", "not_before"), ("not_after", "not_after")):
        moment = _timestamp(raw.get(source), line_number, source)
        if moment is not None:
            certificate[field] = moment
    fingerprints = raw.get("fingerprint_hash")
    if isinstance(fingerprints, dict):
        digest = _first_text(fingerprints.get("sha256"))
        if digest and re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            certificate["sha256"] = digest.lower()
    return certificate or None


def _timestamp(value: Any, line_number: int, field: str) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise ParserInputError(
            f"{RESULT_FILE}:{line_number} tls.{field} {value!r} is not a timestamp"
        ) from None
    if moment.tzinfo is None:
        raise ParserInputError(f"{RESULT_FILE}:{line_number} tls.{field} has no timezone")
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _product(record: dict[str, Any]) -> dict[str, Any] | None:
    """`{product, version, cpe}` from the first CPE with a concrete version, else None."""
    raw = record.get("cpe")
    for entry in raw if isinstance(raw, list) else []:
        if not isinstance(entry, dict):
            continue
        cpe = entry.get("cpe")
        parts = str(cpe).strip().split(":") if isinstance(cpe, str) else []
        if len(parts) < 13:
            continue
        product, version = parts[4], parts[5]
        normalised = _normalise_version(version) if version not in {"", "*", "-"} else None
        if not normalised or not _CPE_PART.match(product):
            continue
        return {
            "product": product.lower(),
            "version": normalised,
            "cpe": ":".join(parts[:13]),
        }
    printed = _printed_versions(record)
    if raw:
        for entry in raw if isinstance(raw, list) else []:
            parts = str(entry.get("cpe") if isinstance(entry, dict) else "").strip().split(":")
            if len(parts) < 13 or parts[0] != "cpe" or parts[1] != "2.3":
                continue
            vendor, product = parts[3], parts[4]
            if not _CPE_PART.match(vendor) or not _CPE_PART.match(product):
                continue
            printed_version = printed.get(product)
            if printed_version is None:
                continue
            return {
                "product": product,
                "version": printed_version,
                "cpe": f"cpe:2.3:a:{vendor}:{product}:{printed_version}:*:*:*:*:*:*:*",
            }
    return _product_from_technology(record)


def _printed_versions(record: dict[str, Any]) -> dict[str, str]:
    """Versions the response prints, keyed by the NVD product they belong to."""
    found: dict[str, str] = {}
    for _source, pattern, _vendor, product in PRODUCT_SIGNALS:
        for text in _signal_texts(record, _source):
            match = pattern.search(text)
            if match is None:
                continue
            version = _normalise_version(match.group("version"))
            if version is not None:
                found.setdefault(product, version)
    for entry in _technologies(record):
        name, _, version = entry.partition(":")
        mapped = TECHNOLOGY_CPES.get(name)
        if version and mapped is not None:
            found.setdefault(mapped[1], version)
    return found


def _signal_texts(record: dict[str, Any], source: str) -> list[str]:
    if source in {"title", "body"}:
        raw = record.get(source)
    else:
        headers = record.get("header")
        raw = headers.get(source.split(":", 1)[1]) if isinstance(headers, dict) else None
        if isinstance(headers, dict):
            raw = {str(k).lower(): v for k, v in headers.items()}.get(source.split(":", 1)[1])
    text = _join_header(raw)
    return [text] if text else []


def _product_from_technology(record: dict[str, Any]) -> dict[str, Any] | None:
    """`{product, version, cpe}` of the first detected technology with a version, when mapped."""
    for entry in _technologies(record):
        name, _, version = entry.partition(":")
        mapped = TECHNOLOGY_CPES.get(name)
        if not version or mapped is None:
            continue
        vendor, product = mapped
        return {
            "product": product,
            "version": version,
            "cpe": f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*",
        }
    return _product_from_response(record)


def _product_from_response(record: dict[str, Any]) -> dict[str, Any] | None:
    """The product a response prints about itself (title or header), with its version."""
    headers = record.get("header")
    header_map = (
        {str(name).lower(): value for name, value in headers.items()}
        if isinstance(headers, dict)
        else {}
    )
    for source, pattern, vendor, product in PRODUCT_SIGNALS:
        if source in {"title", "body"}:
            raw = record.get(source)
        else:
            raw = header_map.get(source.split(":", 1)[1])
        text = _join_header(raw)
        if text is None:
            continue
        match = pattern.search(text)
        if match is None:
            continue
        version = _normalise_version(match.group("version"))
        if version is None:
            continue
        cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
        return {"product": product, "version": version, "cpe": cpe}
    return None


def _join_header(raw: Any) -> str | None:
    if isinstance(raw, str):
        return raw
    if isinstance(raw, list):
        return ", ".join(str(item) for item in raw)
    return None


def _normalise_version(raw: str) -> str | None:
    text = raw.strip().lstrip("vV")
    text = text.split()[0] if text.split() else ""
    text = re.sub(r"[^0-9A-Za-z._~-]", "", text).rstrip("._-")
    return text or None


def _first_text(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str) and item.strip():
                return item.strip()
    return None


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
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        raise ParserInputError(f"input target {value!r} has no IP address") from None
    shown = f"[{address}]" if address.version == 6 else str(address)
    return f"service:{shown}:{int(port)}/{transport}"
