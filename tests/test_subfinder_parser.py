"""The Subfinder parser's scope check (F3/N6): tool output is untrusted.

A name outside every input domain must never become an asset, even when Subfinder's own regex
produced it: discovery feeds the active capabilities, so an injected third-party name would become
a scan target. The lab fixture suite covers the normal mapping.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adapters.m08.subfinder.parser import parse

TASK: dict[str, Any] = {"input": {"targets": ["dns:lab.aegis.test"]}}


def _output(tmp_path: Path, *hosts: str) -> Path:
    (tmp_path / "result.jsonl").write_text(
        "".join(json.dumps({"host": host, "input": "lab.aegis.test"}) + "\n" for host in hosts),
        encoding="utf-8",
    )
    return tmp_path


def test_a_name_outside_the_input_domains_is_not_an_asset(tmp_path: Path) -> None:
    parsed = parse(
        _output(tmp_path, "www.lab.aegis.test", "evil.example", "lab.aegis.test.evil.example"),
        TASK,
        [],
    )
    keys = {asset["canonical_key"] for asset in parsed["assets"]}
    assert keys == {"dns:www.lab.aegis.test"}
    # The seed itself, and the injected names, are not observations either.
    assert {item["subject"] for item in parsed["observations"]} == {"dns:www.lab.aegis.test"}
    assert parsed["relationships"] == [
        {
            "type": "SUBDOMAIN_OF",
            "from": "dns:www.lab.aegis.test",
            "to": "dns:lab.aegis.test",
            "confidence": 1.0,
            "evidence_refs": [{"local_ref": "raw"}],
        }
    ]


def test_a_seed_is_accepted_as_its_own_name(tmp_path: Path) -> None:
    parsed = parse(_output(tmp_path, "www.lab.aegis.test"), TASK, [])
    assert len(parsed["assets"]) == 1
