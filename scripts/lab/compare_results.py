#!/usr/bin/env python3
"""Fixture comparison for the authorized lab runs (G0.4c).

Turns "dnsx run against the lab returns expected records" into a check the command can fail:
the expected records are committed fixtures (`deploy/lab/fixtures/*.expected.json`), the
actual output is the raw JSONL the pinned image produced. Nothing here reads the clock,
network or zone file, so a mismatch is always a mismatch between the two artifacts.
"""

import argparse
import json
import sys
from pathlib import Path


def load_jsonl(path: Path) -> list[dict]:
    records = []
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise SystemExit(f"{path}:{number}: not JSONL: {error}") from error
    return records


def compare_dnsx(expected: dict, actual: list[dict]) -> list[str]:
    problems: list[str] = []
    probes = {probe["host"]: probe for probe in expected["probes"]}
    seen: dict[str, dict] = {}
    for record in actual:
        host = record.get("host")
        if host in seen:
            problems.append(f"{host}: more than one result line")
        seen[host] = record
    for host, probe in probes.items():
        record = seen.get(host)
        if record is None:
            problems.append(f"{host}: missing from dnsx output")
            continue
        if record.get("status_code") != probe["status_code"]:
            problems.append(
                f"{host}: status {record.get('status_code')!r}, expected {probe['status_code']!r}"
            )
        for kind in ("a", "aaaa", "cname"):
            want = sorted(probe.get(kind) or [])
            got = sorted(record.get(kind) or [])
            if want != got:
                problems.append(f"{host} {kind}: expected {want}, got {got}")
        print(
            f"  {host}: {record.get('status_code')} "
            f"a={sorted(record.get('a') or [])} "
            f"aaaa={sorted(record.get('aaaa') or [])} "
            f"cname={sorted(record.get('cname') or [])}"
        )
    for host in sorted(seen):
        if host not in probes:
            problems.append(f"{host}: not in the expected probe list")
    if not actual:
        problems.append("dnsx produced no output")
    return problems


def compare_subfinder(expected: dict, actual: list[dict]) -> list[str]:
    problems: list[str] = []
    want = sorted(expected["hosts"])
    got = sorted({record.get("host", "") for record in actual})
    for record in actual:
        if record.get("input") != expected["zone"]:
            problems.append(f"{record.get('host')}: input {record.get('input')!r}, expected {expected['zone']!r}")
        if record.get("source") != expected["source"]:
            problems.append(f"{record.get('host')}: source {record.get('source')!r}, expected {expected['source']!r}")
    if got != want:
        missing = sorted(set(want) - set(got))
        extra = sorted(set(got) - set(want))
        problems.append(f"hosts differ: missing={missing} extra={extra}")
    for host in got:
        print(f"  {host}")
    return problems


def compare_naabu(expected: dict, actual: list[dict]) -> list[str]:
    """Open (address, port, transport) triples against the inventory-derived expectation."""
    problems: list[str] = []
    want = {(str(item["ip"]), int(item["port"]), str(item["protocol"])) for item in expected["open"]}
    got: set[tuple[str, int, str]] = set()
    targets = set(expected["targets"])
    for record in actual:
        ip = str(record.get("ip", ""))
        if ip and ip not in targets:
            problems.append(f"{ip}: scanned address is not a lab service address")
            continue
        try:
            triple = (ip, int(record.get("port")), str(record.get("protocol")))
        except (TypeError, ValueError):
            problems.append(f"{record!r}: not an open-port record")
            continue
        if triple in got:
            problems.append(f"{triple}: reported twice")
        got.add(triple)
        allowed = {(item["ip"], int(item["port"])) for item in expected["open"]}
        if (triple[0], triple[1]) not in allowed:
            problems.append(f"{triple}: open port the inventory does not declare")
    missing = sorted(want - got)
    extra = sorted(got - want)
    if missing:
        problems.append(f"open ports missing from the run: {missing}")
    if extra:
        problems.append(f"open ports the run found but the inventory does not declare: {extra}")
    for item in sorted(got):
        print(f"  {item[0]}:{item[1]}/{item[2]}")
    if not actual:
        problems.append("naabu produced no output")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=["dnsx", "subfinder", "naabu"])
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--actual", type=Path, required=True)
    args = parser.parse_args()

    if not args.actual.exists():
        raise SystemExit(f"actual output is missing: {args.actual}")
    expected = json.loads(args.expected.read_text(encoding="utf-8"))
    actual = load_jsonl(args.actual)
    if args.kind == "dnsx":
        problems = compare_dnsx(expected, actual)
    elif args.kind == "subfinder":
        problems = compare_subfinder(expected, actual)
    else:
        problems = compare_naabu(expected, actual)
    if problems:
        print(f"{args.kind}: FAIL ({len(problems)} problem(s))", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    checked = {"dnsx": lambda: len(expected["probes"]), "subfinder": lambda: len(expected["hosts"]),
               "naabu": lambda: len(expected["open"])}[args.kind]()
    print(f"{args.kind}: PASS ({checked} expected entries match {args.actual})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
