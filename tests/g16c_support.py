"""Shared fixtures of the G1.6 slice C tests: intel snapshots, a fingerprinted service, candidates.

The intel files under `tests/fixtures/intel/` are slices of the real feed shapes (NVD CVE JSON 2.0,
CISA KEV, FIRST EPSS CSV), so the parsers and the matcher are exercised on the documents they will
see in production; they are committed and small on purpose and no test reaches the network. The
object store is an in-memory stand-in that keeps the same contract as M28's S3 client (`put`,
`head`): the sync must be testable without Seaweedfs, and `test_m18_intel_sync` asserts the key,
the bytes and the sha256 it stored.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psycopg
from psycopg.rows import dict_row

from aegis.m18_intel.sync import FeedSync, SyncReport

FIXTURES = Path(__file__).resolve().parent / "fixtures/intel"
NVD = FIXTURES / "nvd-slice.json"
KEV = FIXTURES / "kev-slice.json"
EPSS = FIXTURES / "epss-slice.csv"

#: Version/date the fixture slices are pinned to; EPSS uses it as its score date.
VERSION = "2026-11-24"
SNAPSHOT_AT = datetime(2026, 11, 24, 6, 0, tzinfo=UTC)

#: The lab services of G1.6 slice A, as its adapters will fingerprint them:
#: Apache 2.4.49 on :80 (an exact-version CVE, in KEV), nginx 1.18.0 on :8080 (a version range,
#: not in KEV) and a Spring application on :8080 (an application-level technology CPE).
SERVICE_KEY = "service:10.114.53.10:80/tcp"
NGINX_SERVICE_KEY = "service:10.114.53.10:8080/tcp"
APP_KEY = "app:http://10.114.53.10:8080"
APACHE_CPE = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
NGINX_CPE = "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"
SPRING_CPE = "cpe:2.3:a:vmware:spring_framework:5.3.17:*:*:*:*:*:*:*"


class MemoryStore:
    """The `put`/`head` half of the object store the sync needs, kept in a dict."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def put(self, key: str, data: bytes, *, content_type: str) -> None:
        self.objects[key] = data

    def head(self, key: str) -> int | None:
        data = self.objects.get(key)
        return None if data is None else len(data)


def service_assets() -> list[dict[str, Any]]:
    from tests.support_ingestion import asset

    return [
        asset("dns:seed.internal.example", "domain"),
        asset(SERVICE_KEY, "service", discovered_from=("dns:seed.internal.example",)),
        asset(NGINX_SERVICE_KEY, "service", discovered_from=("dns:seed.internal.example",)),
        asset(APP_KEY, "application", discovered_from=(SERVICE_KEY,)),
    ]


def coverage() -> list[str]:
    return [SERVICE_KEY, NGINX_SERVICE_KEY, APP_KEY]


#: Every real adapter attaches the raw output it observed to each observation
#: (`evidence_refs: [{local_ref: raw}]`, the fingerprintx result-envelope fixture);
#: the fixture used to omit it, which made a candidate impossible to raise to a finding (G3).
RAW_REF = [{"local_ref": "raw"}]


def service_observations() -> list[dict[str, Any]]:
    from tests.support_ingestion import observation

    return [
        observation(
            SERVICE_KEY,
            "service.product",
            {"product": "Apache httpd", "version": "2.4.49", "cpe": APACHE_CPE},
            evidence_refs=RAW_REF,
        ),
        observation(
            NGINX_SERVICE_KEY,
            "service.product",
            {"product": "nginx", "version": "1.18.0", "cpe": NGINX_CPE},
            evidence_refs=RAW_REF,
        ),
        observation(APP_KEY, "http.technology", [SPRING_CPE, "Spring Boot"], evidence_refs=RAW_REF),
    ]


def connector(dsn: str) -> Any:
    """A `FeedSync`/`Matcher` connection factory: dict rows, contract search_path, autocommit."""

    def open_connection() -> psycopg.Connection[Any]:
        connection: psycopg.Connection[Any] = psycopg.connect(
            dsn, autocommit=True, row_factory=dict_row
        )
        connection.execute("SET search_path = aegis, public")
        return connection

    return open_connection


def seed_intel(
    dsn: str,
    *,
    store: MemoryStore | None = None,
    versions: dict[str, str] | None = None,
) -> tuple[dict[str, SyncReport], MemoryStore]:
    """Load the three fixture slices through the real sync, one snapshot per feed."""
    object_store = store or MemoryStore()
    sync = FeedSync(connector(dsn), object_store)
    reports: dict[str, SyncReport] = {}
    for feed, path in (("nvd", NVD), ("kev", KEV), ("epss", EPSS)):
        version = (versions or {}).get(feed, VERSION)
        reports[feed] = sync.sync(
            feed,
            version,
            path.read_bytes(),
            source_uri=path.name,
            snapshot_at=SNAPSHOT_AT,
        )
    return reports, object_store


def nvd_with_extra_revision() -> bytes:
    """The NVD slice with a new revision of CVE-2021-23017 (its end bound moves to 1.21.0)."""
    import json

    document = json.loads(NVD.read_text(encoding="utf-8"))
    for entry in document["vulnerabilities"]:
        if entry["cve"]["id"] == "CVE-2021-23017":
            entry["cve"]["lastModified"] = "2026-11-25T00:00:00.000"
            entry["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0]["versionEndExcluding"] = (
                "1.21.0"
            )
    return json.dumps(document).encode("utf-8")


def nvd_with_rejected_cve() -> bytes:
    """The NVD slice with CVE-2021-41773 rejected: a new, withdrawn revision of that CVE."""
    import json

    document = json.loads(NVD.read_text(encoding="utf-8"))
    for entry in document["vulnerabilities"]:
        if entry["cve"]["id"] == "CVE-2021-41773":
            entry["cve"]["vulnStatus"] = "Rejected"
            entry["cve"]["lastModified"] = "2026-11-26T00:00:00.000"
    return json.dumps(document).encode("utf-8")


HTTPD = ("a", "apache", "http_server")
WINDOWS = ("o", "microsoft", "windows")


def _cpe(product: tuple[str, str, str], version: str, **bounds: object) -> dict[str, object]:
    """One NVD `cpeMatch` entry for the fixture's `(part, vendor, product)`."""
    part, vendor, name = product
    return {
        "vulnerable": True,
        "criteria": f"cpe:2.3:{part}:{vendor}:{name}:{version}:*:*:*:*:*:*:*",
        **bounds,
    }


def _node(*matches: dict[str, object], operator: str = "OR") -> dict[str, object]:
    return {"operator": operator, "negate": False, "cpeMatch": list(matches)}


def _cve(
    vulnerability_id: str, configurations: list[dict[str, object]], description: str
) -> dict[str, object]:
    return {
        "cve": {
            "id": vulnerability_id,
            "vulnStatus": "Modified",
            "lastModified": "2026-11-26T00:00:00.000",
            "published": "2024-07-01T00:00:00.000",
            "descriptions": [{"lang": "en", "value": description}],
            "configurations": configurations,
        }
    }


def nvd_with_retracted_match() -> bytes:
    """The NVD slice with a revision of CVE-2021-41773 that no longer matches httpd 2.4.49.

    NVD moved the affected range to 2.4.50-2.4.54 (a re-analysis): the candidate the previous
    revision produced is a match at revision N and no match at N+1, which is what a retraction is.
    """
    import json

    document = json.loads(NVD.read_text(encoding="utf-8"))
    for entry in document["vulnerabilities"]:
        if entry["cve"]["id"] != "CVE-2021-41773":
            continue
        entry["cve"]["lastModified"] = "2026-11-27T00:00:00.000"
        entry["cve"]["configurations"] = [
            {
                "nodes": [
                    _node(
                        _cpe(
                            HTTPD,
                            "*",
                            versionStartIncluding="2.4.50",
                            versionEndExcluding="2.4.55",
                        )
                    )
                ]
            }
        ]
    return json.dumps(document).encode("utf-8")


def nvd_without_the_product() -> bytes:
    """The NVD slice with CVE-2021-41773 re-analysed so it no longer mentions httpd at all.

    The flattened catalogue narrows by product, so this revision never reaches the matcher's
    catalogue for the httpd service; a retraction must still happen (full run only).
    """
    import json

    document = json.loads(NVD.read_text(encoding="utf-8"))
    for entry in document["vulnerabilities"]:
        if entry["cve"]["id"] != "CVE-2021-41773":
            continue
        entry["cve"]["lastModified"] = "2026-11-27T01:00:00.000"
        entry["cve"]["configurations"] = [
            {"nodes": [_node(_cpe(("o", "fedoraproject", "fedora"), "34"))]}
        ]
    return json.dumps(document).encode("utf-8")


def nvd_with_configuration_cases() -> bytes:
    """The NVD slice plus three real httpd configurations the matcher must tell apart (item 61).

    * `CVE-2024-40898` - "SSRF in Apache HTTP Server on Windows": an `AND` configuration of
      "http_server < 2.4.62" and the platform `microsoft:windows` (`vulnerable: false`). The
      flattened reading made every httpd under 2.4.62 a candidate;
    * `CVE-1999-0289` - `cpe:2.3:a:apache:http_server:-`, NVD published no version at all;
    * `CVE-2021-42013` - an ordinary bounded range (2.4.49 and 2.4.50), which must still match.
    """
    import json

    document = json.loads(NVD.read_text(encoding="utf-8"))
    windows_platform = _cpe(WINDOWS, "-")
    windows_platform["vulnerable"] = False
    document["vulnerabilities"].extend(
        [
            _cve(
                "CVE-2024-40898",
                [
                    {
                        "operator": "AND",
                        "nodes": [
                            _node(_cpe(HTTPD, "*", versionEndExcluding="2.4.62")),
                            _node(windows_platform),
                        ],
                    }
                ],
                "SSRF in Apache HTTP Server on Windows with mod_rewrite",
            ),
            _cve(
                "CVE-1999-0289",
                [{"nodes": [_node(_cpe(HTTPD, "-"))]}],
                "A default configuration of Apache on Win32 may provide access to restricted files",
            ),
            _cve(
                "CVE-2021-42013",
                [
                    {
                        "nodes": [
                            _node(
                                _cpe(
                                    HTTPD,
                                    "*",
                                    versionStartIncluding="2.4.49",
                                    versionEndIncluding="2.4.50",
                                )
                            )
                        ]
                    }
                ],
                "Path traversal in httpd 2.4.49 and 2.4.50",
            ),
        ]
    )
    return json.dumps(document).encode("utf-8")


def matches(connection: psycopg.Connection[Any]) -> list[dict[str, Any]]:
    rows = connection.execute(
        "SELECT m.vulnerability_id, a.canonical_key, m.match_method, m.confidence,"
        "       m.affected_range, m.snapshot_id, m.campaign_id"
        "  FROM package_vuln_match m JOIN asset a ON a.asset_id = m.package_asset_id"
        " ORDER BY m.vulnerability_id, a.canonical_key"
    ).fetchall()
    return [dict(row) for row in rows]


def events(connection: psycopg.Connection[Any], event_type: str) -> list[dict[str, Any]]:
    rows = connection.execute(
        "SELECT seq, type, producer, dedup_key, payload FROM outbox_event"
        " WHERE type = %s ORDER BY seq",
        (event_type,),
    ).fetchall()
    return [dict(row) for row in rows]
