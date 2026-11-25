"""G1.6b parser rules: the mapping and CPE/technology decisions the fixtures cannot cover.

The lab fixture proves the happy path with real bytes. These tests pin the rules that only appear
on other inputs - both parsers are pure functions over the tool's JSONL, so a synthetic file is an
honest unit of the decision they make.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from adapters.m08.fingerprintx import parser as fingerprintx
from adapters.m08.httpx import parser as httpx

FINGERPRINT_TASK = {
    "input": {"targets": ["service:10.1.2.3:8080/tcp"], "ports": [8080], "timeout_ms": 2000}
}


def _write(directory: Path, records: list[dict[str, Any]]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "result.jsonl").write_text(
        "\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8"
    )
    return directory


def _record(**overrides: object) -> dict[str, Any]:
    record = {
        "ip": "10.1.2.3",
        "port": 8080,
        "protocol": "http",
        "transport": "tcp",
        "version": "nginx/1.29.8",
        "metadata": {"cpes": ["cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"]},
    }
    record.update(overrides)
    return record


def _observations(parsed: dict[str, Any], predicate: str) -> list[dict[str, Any]]:
    return [item for item in parsed["observations"] if item["predicate"] == predicate]


def test_fingerprintx_enriches_a_wildcard_cpe_with_the_version_it_read(tmp_path: Path) -> None:
    parsed = fingerprintx.parse(_write(tmp_path, [_record()]), FINGERPRINT_TASK, [])
    product = _observations(parsed, "service.product")[0]["value"]
    # The tool's own vendor/product wins; the version comes from the banner. A `*` CPE would feed
    # CVE matching a product it cannot pin, so it is never emitted as-is.
    assert product == {
        "product": "nginx",
        "version": "1.29.8",
        "cpe": "cpe:2.3:a:f5:nginx:1.29.8:*:*:*:*:*:*:*",
    }
    assert _observations(parsed, "service.banner")[0]["value"] == "nginx/1.29.8"
    assert _observations(parsed, "service.protocol")[0]["value"] == "http"


def test_fingerprintx_keeps_a_concrete_cpe_and_omits_a_versionless_one(tmp_path: Path) -> None:
    concrete = _record(
        protocol="ssh",
        version="SSH-2.0-OpenSSH_9.9p1",
        metadata={
            "banner": "SSH-2.0-OpenSSH_9.9p1",
            "cpes": ["cpe:2.3:a:openbsd:openssh:9.9p1:*:*:*:*:*:*:*"],
        },
    )
    parsed = fingerprintx.parse(_write(tmp_path / "a", [concrete]), FINGERPRINT_TASK, [])
    assert _observations(parsed, "service.product")[0]["value"] == {
        "product": "openssh",
        "version": "9.9p1",
        "cpe": "cpe:2.3:a:openbsd:openssh:9.9p1:*:*:*:*:*:*:*",
    }

    bare = _record(protocol="ssh", version=None, metadata={})
    parsed = fingerprintx.parse(_write(tmp_path / "b", [bare]), FINGERPRINT_TASK, [])
    assert _observations(parsed, "service.product") == []  # no product claim without evidence
    assert _observations(parsed, "service.banner") == []


def test_fingerprintx_refuses_a_record_for_a_service_the_job_did_not_target(tmp_path: Path) -> None:
    other = _record(ip="10.9.9.9")
    with pytest.raises(fingerprintx.ParserInputError, match="did not target"):
        fingerprintx.parse(_write(tmp_path, [other]), FINGERPRINT_TASK, [])


def test_fingerprintx_refuses_a_udp_record(tmp_path: Path) -> None:
    with pytest.raises(fingerprintx.ParserInputError, match="only scans TCP"):
        fingerprintx.parse(_write(tmp_path, [_record(transport="udp")]), FINGERPRINT_TASK, [])


HTTPX_TASK = {
    "input": {
        "targets": ["service:10.1.2.3:8080/tcp", "service:10.1.2.3:443/tcp"],
        "ports": [8080, 443],
        "concurrency": 4,
        "timeout_seconds": 10,
    }
}


def test_httpx_names_the_default_port_and_normalises_technology(tmp_path: Path) -> None:
    record = {
        "input": "10.1.2.3:443",
        "url": "https://10.1.2.3:443",
        "status_code": 200,
        "tech": ["Nginx:1.29.8", "jQuery", "nginx:1.29.8"],
        "header": {"Server": ["nginx/1.29.8"], "X-Long": ["x" * 600]},
        "tls": {
            "subject_cn": "10.1.2.3",
            "not_before": "2026-11-25T00:00:00+07:00",
            "not_after": "2026-12-25T00:00:00Z",
            "fingerprint_hash": {"sha256": "A" * 64},
        },
    }
    parsed = httpx.parse(_write(tmp_path, [record]), HTTPX_TASK, [])
    assert parsed["assets"][0]["canonical_key"] == "app:https://10.1.2.3:443"
    technology = _observations(parsed, "http.technology")[0]["value"]
    assert technology == ["nginx:1.29.8", "jquery"]
    headers = _observations(parsed, "http.headers")[0]["value"]
    assert headers["server"] == "nginx/1.29.8"
    assert len(headers["x-long"]) == 512  # the full value stays in the raw evidence file
    certificate = _observations(parsed, "tls.certificate")[0]["value"]
    assert certificate["not_before"] == "2026-11-24T17:00:00Z"  # normalised to UTC Z
    assert certificate["sha256"] == "a" * 64
    assert parsed["relationships"][0]["type"] == "SERVES"


def test_httpx_reads_a_product_the_response_prints(tmp_path: Path) -> None:
    """Tomcat's title and Jenkins' header are the origin's own claims, with versions."""
    tomcat = {
        "input": "10.1.2.3:8080",
        "url": "http://10.1.2.3:8080",
        "status_code": 200,
        "title": "Apache Tomcat/8.5.19",
        "header": {},
    }
    parsed = httpx.parse(_write(tmp_path / "tomcat", [tomcat]), HTTPX_TASK, [])
    product = _observations(parsed, "service.product")[0]["value"]
    assert product == {
        "product": "tomcat",
        "version": "8.5.19",
        "cpe": "cpe:2.3:a:apache:tomcat:8.5.19:*:*:*:*:*:*:*",
    }

    jenkins = {
        "input": "10.1.2.3:8080",
        "url": "http://10.1.2.3:8080",
        "status_code": 403,
        "header": {"X-Jenkins": "2.138", "Server": "Jetty(9.4.z-SNAPSHOT)"},
    }
    parsed = httpx.parse(_write(tmp_path / "jenkins", [jenkins]), HTTPX_TASK, [])
    product = _observations(parsed, "service.product")[0]["value"]
    assert product == {
        "product": "jenkins",
        "version": "2.138",
        "cpe": "cpe:2.3:a:jenkins:jenkins:2.138:*:*:*:*:*:*:*",
    }


def test_httpx_does_not_guess_a_product_from_an_unrelated_page(tmp_path: Path) -> None:
    plain = {
        "input": "10.1.2.3:8080",
        "url": "http://10.1.2.3:8080",
        "status_code": 200,
        "title": "Hello, my name is , I am  years old.",
        "header": {},
    }
    parsed = httpx.parse(_write(tmp_path, [plain]), HTTPX_TASK, [])
    assert _observations(parsed, "service.product") == []


def test_httpx_refuses_a_result_that_names_another_input(tmp_path: Path) -> None:
    record = {"input": "10.9.9.9:8080", "url": "http://10.9.9.9:8080", "status_code": 200}
    with pytest.raises(httpx.ParserInputError, match="did not target"):
        httpx.parse(_write(tmp_path, [record]), HTTPX_TASK, [])
