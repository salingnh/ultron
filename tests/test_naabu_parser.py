"""The naabu parser (G1.6a): port records -> `service` assets, `EXPOSES` edges, port observations.

The lab fixture suite (`tests/test_adapters_conformance.py`) proves the parser reproduces a real
run. This suite proves the refusals and the identity details that a lab run does not exercise: a
record with no parseable address, an out-of-range port, an unknown transport, a port the job never
bound (a binding violation reported by the tool), and the IPv6/IPv4-mapped canonical forms.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from adapters.m09.naabu.parser import ParserInputError, parse

TASK: dict[str, Any] = {
    "input": {
        "targets": ["ip:10.114.53.211"],
        "ports": [80, 443],
        "packets_per_second": 100,
        "concurrency": 1,
    }
}


def _output(tmp_path: Path, *records: dict[str, Any]) -> Path:
    (tmp_path / "result.jsonl").write_text(
        "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
    )
    return tmp_path


def _record(**overrides: Any) -> dict[str, Any]:
    record = {"ip": "10.114.53.211", "port": 443, "protocol": "tcp", "tls": True}
    record.update(overrides)
    return record


def test_one_open_port_is_a_service_an_edge_and_three_observations(tmp_path: Path) -> None:
    directory = _output(tmp_path, _record())

    parsed = parse(directory, TASK, [{"local_ref": "raw"}])

    assert [asset["canonical_key"] for asset in parsed["assets"]] == [
        "service:10.114.53.211:443/tcp"
    ]
    assert parsed["assets"][0]["kind"] == "service"
    assert parsed["assets"][0]["discovered_from"] == ["ip:10.114.53.211"]
    assert parsed["relationships"] == [
        {
            "type": "EXPOSES",
            "from": "ip:10.114.53.211",
            "to": "service:10.114.53.211:443/tcp",
            "confidence": 1.0,
            "evidence_refs": [{"local_ref": "raw"}],
        }
    ]
    observed = {(item["predicate"], item["value"]) for item in parsed["observations"]}
    assert observed == {
        ("asset.seen", True),
        ("net.port_state", "open"),
        ("service.protocol", "tcp"),
    }
    assert parsed["coverage_subjects"] == ["ip:10.114.53.211"]
    assert parsed["findings"] == []


def test_the_same_open_port_twice_is_one_service(tmp_path: Path) -> None:
    directory = _output(tmp_path, _record(), _record())

    parsed = parse(directory, TASK, [])

    assert len(parsed["assets"]) == 1
    assert len(parsed["relationships"]) == 1
    assert len(parsed["observations"]) == 3


def test_an_ipv6_address_is_bracketed_in_the_service_key(tmp_path: Path) -> None:
    directory = _output(tmp_path, _record(ip="2001:DB8::211", port=80))

    parsed = parse(directory, {"input": {"targets": ["ip:2001:db8::211"], "ports": [80]}}, [])

    assert parsed["assets"][0]["canonical_key"] == "service:[2001:db8::211]:80/tcp"
    assert parsed["relationships"][0]["from"] == "ip:2001:db8::211"


def test_an_ipv4_mapped_address_collapses_to_its_ipv4_identity(tmp_path: Path) -> None:
    directory = _output(tmp_path, _record(ip="::ffff:10.114.53.211"))

    parsed = parse(directory, TASK, [])

    assert parsed["assets"][0]["canonical_key"] == "service:10.114.53.211:443/tcp"


@pytest.mark.parametrize(
    "record, reason",
    [
        (_record(ip="not-an-address"), "not an IP address"),
        (_record(port="443"), "non-integer port"),
        (_record(port=0), "out of range"),
        (_record(port=65536), "out of range"),
        (_record(port=True), "non-integer port"),
        (_record(protocol="sctp"), "unknown transport"),
        (_record(protocol=None), "unknown transport"),
        ({"host": "www.lab.aegis.test", "port": 80, "protocol": "tcp"}, "without an address"),
        ({"port": 80, "protocol": "tcp"}, "neither an 'ip' nor a 'host'"),
    ],
)
def test_a_record_outside_the_pinned_shape_is_refused(
    tmp_path: Path, record: dict[str, Any], reason: str
) -> None:
    directory = _output(tmp_path, record)

    with pytest.raises(ParserInputError, match=reason):
        parse(directory, {"input": {"targets": ["ip:10.114.53.211"]}}, [])


def test_a_port_the_job_did_not_bind_is_refused(tmp_path: Path) -> None:
    """The signed binding opens exactly `input.ports`; a report outside it is not this job."""
    directory = _output(tmp_path, _record(port=3306))

    with pytest.raises(ParserInputError, match="did not bind"):
        parse(directory, TASK, [])


def test_a_missing_or_corrupt_output_file_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ParserInputError, match="missing"):
        parse(tmp_path, TASK, [])
    (tmp_path / "result.jsonl").write_text('{"ip": "10.114.53.211", "port": 80\n', encoding="utf-8")
    with pytest.raises(ParserInputError, match="not JSON"):
        parse(tmp_path, TASK, [])


def test_input_targets_must_be_addresses(tmp_path: Path) -> None:
    directory = _output(tmp_path)

    with pytest.raises(ParserInputError, match="not an IP address"):
        parse(directory, {"input": {"targets": ["dns:lab.aegis.test"]}}, [])
