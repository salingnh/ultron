"""Probe adapter parser (test-only) used by the M06 parser-host and collector tests.

Contract shape: `parse(output_dir, task, evidence) -> ParsedResults`. The name is
`aegis_probe.parser:parse`; the production allowlist only admits `adapters.*`, so the tests pass
this module explicitly. The real adapters land with G1.3b.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def parse(output_dir: Path, task: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    hosts: list[str] = []
    result_file = output_dir / "result.jsonl"
    if result_file.exists():
        for line in result_file.read_text(encoding="utf-8").splitlines():
            if line.strip():
                hosts.append(str(json.loads(line)["host"]))
    seed = next(iter(task.get("targets", [])), None)
    seed_key = None
    if isinstance(seed, dict) and "canonical_key" in seed:
        seed_key = str(seed["canonical_key"])
    evidence_refs = [{"local_ref": item["local_ref"]} for item in evidence]
    return {
        "assets": [
            {
                "kind": "domain",
                "canonical_key": f"dns:{host}",
                "discovered_from": [seed_key] if seed_key else [],
                "confidence": 0.6,
                "evidence_refs": evidence_refs,
            }
            for host in hosts
        ],
        "observations": [
            {
                "subject": f"dns:{host}",
                "predicate": "asset.seen",
                "value": True,
                "observed_at": "2026-11-24T00:00:00Z",
                "confidence": 0.6,
                "evidence_refs": evidence_refs,
            }
            for host in hosts
        ],
        "relationships": [],
        "findings": [],
        "coverage": {"subjects": sorted({f"dns:{host}" for host in hosts}), "complete": True},
    }


# --- probes used by the parser-host isolation tests -----------------------------------------


def net_probe(
    output_dir: Path, task: dict[str, Any], evidence: list[dict[str, Any]]
) -> dict[str, Any]:
    """Try to open an outbound socket; the network namespace must refuse it."""
    import socket

    outcome = "CONNECTED"
    try:
        socket.create_connection(("1.1.1.1", 53), timeout=3).close()
    except OSError as error:
        outcome = error.__class__.__name__
    return _result({"socket": outcome})


def env_probe(
    output_dir: Path, task: dict[str, Any], evidence: list[dict[str, Any]]
) -> dict[str, Any]:
    """Report the child's whole environment: no parent variable may leak in."""
    import os

    return _result({"env": dict(os.environ)})


def sleep_probe(
    output_dir: Path, task: dict[str, Any], evidence: list[dict[str, Any]]
) -> dict[str, Any]:
    import time

    time.sleep(30)
    return _result({"slept": True})


def oom_probe(
    output_dir: Path, task: dict[str, Any], evidence: list[dict[str, Any]]
) -> dict[str, Any]:
    blocks = []
    while True:
        blocks.append(bytearray(4 * 1024 * 1024))


def crash_probe(
    output_dir: Path, task: dict[str, Any], evidence: list[dict[str, Any]]
) -> dict[str, Any]:
    raise RuntimeError("parser exploded on hostile input")


def deterministic_probe(
    output_dir: Path, task: dict[str, Any], evidence: list[dict[str, Any]]
) -> dict[str, Any]:
    names = sorted(path.name for path in output_dir.iterdir())
    return _result({"names": names, "task_keys": sorted(task)})


def _result(values: dict[str, Any]) -> dict[str, Any]:
    return {
        "assets": [],
        "observations": [],
        "relationships": [],
        "findings": [],
        "coverage": {"subjects": [], "complete": True},
        **values,
    }
