#!/usr/bin/env python3
"""Build the committed verification result documents from the recorded lab captures.

The captures under `nuclei/` are byte-for-byte what the pinned Nuclei image wrote during the
feasibility run (item 87, `g2-b-lab/`); `index.json` pins their sha256. This script runs the
reviewed conversion (`adapters/m21/nuclei_verify/parser.py:result_document`) over them and writes
the contract documents M21 decides on. The variants that the lab never produced (an unexpectedly
vulnerable twin, a benign path that holds the canary) are derived by *reassigning roles* in the
signed task, never by editing bytes: the captures stay the evidence.

    python tests/fixtures/verify/build_results.py           rewrite result/*.json + index.json
    python tests/fixtures/verify/build_results.py --check   fail when they differ

The canary is the feasibility token (`canary-token.txt`, whose value is in every capture); the lab
map (`controls.json`) pins its sha256 as M21 compares it, over the extracted token value (no
trailing newline - `deploy/lab/verify-canary.txt` is written exactly that way).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[2]
sys.path.insert(0, str(REPO))

from adapters.m21.nuclei_verify.parser import result_document  # noqa: E402

PACK_SHA = "0" * 64  # the result document echoes the task's pack pin; the replay does not check it
CHECK = "cve-2021-41773-traversal"
CANARY_PATH = "/static/.%2e/.%2e/srv/canary/canary.txt"
BENIGN_PATH = "/static/.%2e/.%2e/srv/canary/absent.txt"


def task(
    positive: str,
    twin: str,
    *,
    benign_path: str = BENIGN_PATH,
) -> dict[str, Any]:
    return {
        "provider": "nuclei-verify",
        "provider_version": "v3.11.1",
        "image_digest": "sha256:" + "5" * 64,
        "network_profile": "lab",
        "input": {
            "check_id": CHECK,
            "check_pack_sha256": PACK_SHA,
            "request_cap": 4,
            "expected_seq": 1,
            "targets": [f"service:{positive}/tcp"],
            "controls": [{"role": "patched_twin", "target": f"service:{twin}/tcp"}],
            "benign_path": benign_path,
        },
    }


#: name -> (captures, task, hosts kept). One capture is the lab's own run; a composed case keeps
#: only the rows of the run's addresses, because the capture file may hold a second target.
CASES: dict[str, tuple[tuple[str, ...], dict[str, Any], tuple[str, ...] | None]] = {
    # The recorded pair: 2.4.49 + Alias reads the canary, 2.4.51 does not, the absent path 404s.
    "verified": (("nuclei/pair.jsonl",), task("10.114.59.31:80", "10.114.59.32:80"), None),
    # The stock 2.4.49 target answers 403 on both paths (version match, no exploit); its "twin" is
    # the recorded patched 2.4.51, which also does not read the canary. Row 6.
    "not_reproduced": (
        ("nuclei/stock.jsonl", "nuclei/pair.jsonl"),
        task("10.114.59.33:80", "10.114.59.32:80"),
        ("10.114.59.33", "10.114.59.32"),
    ),
    # Derived: the patched twin's answers are signed as the positive. Row 2 (the twin reproduced).
    "twin_reproduced": (
        ("nuclei/pair.jsonl",),
        task("10.114.59.32:80", "10.114.59.31:80"),
        None,
    ),
    # Derived: the benign control is signed as the canary path itself, so it matches. Row 3.
    "benign_matched": (
        ("nuclei/pair.jsonl",),
        task("10.114.59.31:80", "10.114.59.32:80", benign_path=CANARY_PATH),
        None,
    ),
    # The plain catch-all: a real page for every path, same 200 body. Row 1a.
    "catch_all": (
        ("nuclei/catchall.jsonl",),
        # The plain catch-all answers every path identically; the twin is that same server so the
        # case isolates the same-body guard (the evil server's fake canary is the next case).
        task("10.114.59.90:8090", "10.114.59.90:8090"),
        None,
    ),
    # The adversarial catch-all: canary-shaped value that is not this run's canary. Row 1b.
    "foreign_canary": (
        ("nuclei/catchall.jsonl",),
        task("10.114.59.90:8091", "10.114.59.90:8090"),
        None,
    ),
}


def _capture(captures: tuple[str, ...], keep: tuple[str, ...] | None) -> bytes:
    chunks: list[bytes] = []
    for capture in captures:
        raw = (ROOT / capture).read_bytes()
        if keep is None:
            chunks.append(raw)
            continue
        for line in raw.splitlines():
            if line.strip() and json.loads(line).get("host") in keep:
                chunks.append(line)
    return b"\n".join(chunks) + b"\n"


def build() -> dict[Path, bytes]:
    written: dict[Path, bytes] = {}
    for name, (captures, task_document, keep) in CASES.items():
        document = result_document(_capture(captures, keep), task_document)
        written[ROOT / "result" / f"{name}.json"] = (
            json.dumps(document, indent=2, sort_keys=True) + "\n"
        ).encode()
    index: dict[str, Any] = {"captures": {}, "results": {}, "task": {}}
    for path in sorted((ROOT / "nuclei").glob("*.jsonl")):
        index["captures"][f"nuclei/{path.name}"] = hashlib.sha256(path.read_bytes()).hexdigest()
    for name, (captures, task_document, _keep) in CASES.items():
        key = f"result/{name}.json"
        index["results"][key] = hashlib.sha256(
            written[ROOT / "result" / f"{name}.json"]
        ).hexdigest()
        index.setdefault("task", {})[key] = {
            "captures": list(captures),
            "positive": task_document["input"]["targets"][0],
            "twin": task_document["input"]["controls"][0]["target"],
            "benign_path": task_document["input"]["benign_path"],
        }
    written[ROOT / "index.json"] = (json.dumps(index, indent=2, sort_keys=True) + "\n").encode()
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="do not write; fail on drift")
    arguments = parser.parse_args(argv)
    written = build()
    if arguments.check:
        problems = [
            f"{path.relative_to(REPO)}: missing or differs"
            for path, content in written.items()
            if not path.is_file() or path.read_bytes() != content
        ]
        if problems:
            for problem in problems:
                print(f"verify-fixtures: {problem}", file=sys.stderr)
            return 1
        print("verify-fixtures: OK")
        return 0
    for path, content in written.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        print(f"verify-fixtures: wrote {path.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
