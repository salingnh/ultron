"""Parser isolation tests: no network, no inherited env, contained failures."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from aegis_g02.parser_host import ParserLimits, run_parser


@pytest.fixture()
def output_dir(tmp_path: Path) -> Path:
    out = tmp_path / "out"
    out.mkdir()
    (out / "result.jsonl").write_text('{"type":"DNS_NAME","data":"a.example"}\n')
    return out


def test_parser_cannot_open_a_socket(output_dir: Path):
    run = run_parser("aegis_g02.probes:net_probe", output_dir, {"input": {}})
    assert run.ok, run.error
    result = run.result["parsed"]
    assert result["tcp_connect"].startswith(("OSError", "Connect")), result
    assert "CONNECTED" not in result["tcp_connect"]
    assert result["udp_send"].startswith("OSError"), result
    assert result["dns"] != "93.184.216.34"
    assert result["bind"] == "OK"  # loopback inside the child namespace still works


def test_parser_sees_no_inherited_environment(output_dir: Path, monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "do-not-leak")
    monkeypatch.setenv("HTTPS_PROXY", "http://broker:3128")
    monkeypatch.setenv("AEGIS_OPERATING_CREDENTIAL", "do-not-leak")
    run = run_parser("aegis_g02.probes:env_probe", output_dir, {"input": {}})
    assert run.ok, run.error
    parsed = run.result["parsed"]
    assert set(parsed["env"]) == {"PATH", "PYTHONPATH", "PYTHONHASHSEED", "LC_ALL", "HOME", "TMPDIR"}
    assert "do-not-leak" not in json.dumps(parsed)
    assert parsed["files"] == ["result.jsonl"]


def test_parser_timeout_is_contained(tmp_path: Path):
    out = tmp_path / "out"
    out.mkdir()
    run = run_parser(
        "aegis_g02.probes:sleep_probe",
        out,
        {},
        limits=ParserLimits(timeout_seconds=2),
    )
    assert not run.ok
    assert run.timed_out and run.error == "PARSER_TIMEOUT"


def test_parser_memory_limit_is_contained(tmp_path: Path):
    out = tmp_path / "out"
    out.mkdir()
    run = run_parser(
        "aegis_g02.probes:oom_probe",
        out,
        {},
        limits=ParserLimits(memory_mb=128, timeout_seconds=30),
    )
    assert not run.ok
    assert "MemoryError" in (run.error or "")


def test_parser_crash_does_not_kill_the_runner(output_dir: Path):
    run = run_parser("aegis_g02.probes:crash_probe", output_dir, {})
    assert not run.ok
    assert "parser exploded" in (run.error or "")
    assert run.exit_code == 1


def test_parser_is_deterministic(output_dir: Path):
    first = run_parser("aegis_g02.probes:deterministic_probe", output_dir, {"input": {"domain": "a.example"}})
    second = run_parser("aegis_g02.probes:deterministic_probe", output_dir, {"input": {"domain": "a.example"}})
    assert first.ok and second.ok
    assert first.result["parsed"] == second.result["parsed"]


def test_entrypoint_allowlist_pattern():
    from aegis_g02.parser_host import _is_allowed_entrypoint

    assert _is_allowed_entrypoint("adapters.m08.subfinder.parser:parse")
    assert not _is_allowed_entrypoint("os.system:system")
    assert not _is_allowed_entrypoint("adapters.m08.subfinder.parser")
    assert not _is_allowed_entrypoint("adapters.bad-name.parser:parse")
