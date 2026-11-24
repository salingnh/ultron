"""Parser subprocess isolation (G0.2 suite, ported to the M06 parser host).

The parser runs under `unshare` with a user+network namespace, an allowlisted environment and
rlimits. Every assertion is on what the child observed, not on flags we passed: the probes report
what they could reach.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.m06_runner.parser_host import (
    ENV_ALLOWLIST,
    ParserLimits,
    ParserRun,
    is_allowed_entrypoint,
    run_parser,
)

from . import m06_support

PROBE_PATH = [str(m06_support.CONTAINER_DIR)]
PROBE_PREFIXES = ("aegis_probe.",)


def _run(name: str, tmp_path: Path, *, limits: ParserLimits | None = None) -> ParserRun:
    return run_parser(
        f"aegis_probe.parser:{name}",
        tmp_path,
        {"targets": [{"canonical_key": "dns:internal.example"}]},
        [{"local_ref": "raw", "sha256": "0" * 64}],
        limits=limits,
        extra_prefixes=PROBE_PREFIXES,
        extra_python_path=PROBE_PATH,
    )


def test_parser_entrypoint_pattern_is_enforced() -> None:
    assert is_allowed_entrypoint("adapters.m08.subfinder.parser:parse")
    assert not is_allowed_entrypoint("aegis.m06_runner.job:execute")
    assert not is_allowed_entrypoint("adapters.m08.subfinder")
    assert not is_allowed_entrypoint("adapters.m08.subfinder:parse; rm -rf /")
    assert not is_allowed_entrypoint("os.system:run")
    assert is_allowed_entrypoint("aegis_probe.parser:parse", extra_prefixes=PROBE_PREFIXES)
    with pytest.raises(ValueError):
        run_parser("os.system:run", Path("."), {}, [])


def test_parser_cannot_open_a_socket(tmp_path: Path) -> None:
    run = _run("net_probe", tmp_path)
    assert run.ok, run.error
    assert run.result is not None
    assert run.result["socket"] != "CONNECTED"
    assert run.sandbox["netns"] is True


def test_only_allowlisted_environment_reaches_the_parser(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "never-in-the-child")
    monkeypatch.setenv("HTTPS_PROXY", "http://should-not-leak:3128")
    run = _run("env_probe", tmp_path)
    assert run.ok, run.error
    assert run.result is not None
    env = run.result["env"]
    assert set(env) <= set(ENV_ALLOWLIST)
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "HTTPS_PROXY" not in env


def test_parser_timeout_is_contained(tmp_path: Path) -> None:
    run = _run("sleep_probe", tmp_path, limits=ParserLimits(timeout_seconds=2))
    assert not run.ok
    assert run.error == "PARSER_TIMEOUT"
    assert run.timed_out is True
    assert run.duration_seconds < 20


def test_parser_memory_limit_is_contained(tmp_path: Path) -> None:
    run = _run("oom_probe", tmp_path, limits=ParserLimits(memory_mb=128, timeout_seconds=30))
    assert not run.ok
    assert "MemoryError" in (run.error or "")


def test_parser_crash_does_not_escape(tmp_path: Path) -> None:
    run = _run("crash_probe", tmp_path)
    assert not run.ok
    assert "parser exploded on hostile input" in (run.error or "")


def test_parser_is_deterministic(tmp_path: Path) -> None:
    (tmp_path / "b.txt").write_text("b")
    (tmp_path / "a.txt").write_text("a")
    first = _run("deterministic_probe", tmp_path)
    second = _run("deterministic_probe", tmp_path)
    assert first.ok and second.ok
    assert first.result == second.result


def test_result_is_written_as_json(tmp_path: Path) -> None:
    (tmp_path / "result.jsonl").write_text(json.dumps({"host": "a.internal.example"}) + "\n")
    run = run_parser(
        "aegis_probe.parser:parse",
        tmp_path,
        {"targets": [{"canonical_key": "dns:internal.example"}]},
        [{"local_ref": "result-jsonl"}],
        extra_prefixes=PROBE_PREFIXES,
        extra_python_path=PROBE_PATH,
    )
    assert run.ok, run.error
    assert run.result is not None
    assert run.result["coverage"]["subjects"] == ["dns:a.internal.example"]
