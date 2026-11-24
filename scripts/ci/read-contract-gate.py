#!/usr/bin/env python3
"""Prints the contract gate plan described in contracts/README.md section "Kiểm tra".

That section is the single source of truth for what the gate runs: the python suites, the
PostgreSQL clean chain (the `psql -f ...` command) and the upgrade chain order (the
`... → ... → ...` sentence). This script only reads it - it keeps no second copy - and fails
loudly when the section cannot be parsed or when a file on disk is not covered by it.

Usage: read-contract-gate.py <repo root>
Output, one item per line:
    requirement <repo-relative path>
    python <repo-relative path>
    clean <repo-relative path>
    upgrade <repo-relative path>
Exit status 1 with an `error:` line on stderr when the plan cannot be trusted.
"""
from __future__ import annotations

import re
import shlex
import sys
from pathlib import Path

SECTION = "## Kiểm tra"
ARROW = "\u2192"  # the README writes the upgrade chain as `a` → `b` → `c`
README = "contracts/README.md"


def fail(message: str) -> "NoReturn":  # noqa: F821 - typing only
    print(f"read-contract-gate: error: {message}", file=sys.stderr)
    raise SystemExit(1)


def section(text: str) -> list[str]:
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line.strip() == SECTION), None)
    if start is None:
        fail(f'{README} has no "{SECTION}" section')
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    return lines[start + 1:end]


def split_fences(lines: list[str]) -> tuple[list[str], list[str], bool]:
    """Returns the fenced code lines, the prose lines and whether a fence is left open."""
    code: list[str] = []
    prose: list[str] = []
    in_fence = False
    for line in lines:
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        (code if in_fence else prose).append(line)
    return code, prose, in_fence


def code_plan(code: list[str]) -> tuple[list[str], list[str], list[str]]:
    requirements: list[str] = []
    python_checks: list[str] = []
    clean: list[str] = []
    psql_commands = 0
    for raw in code:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("psql "):
            psql_commands += 1
            try:
                tokens = shlex.split(line)
            except ValueError as exc:
                fail(f"cannot parse the psql command ({exc}): {line}")
            clean += [tokens[i + 1] for i, token in enumerate(tokens[:-1]) if token == "-f"]
            continue
        match = re.search(r"-m pip install\s+-r\s+(\S+)", line)
        if match:
            requirements.append(match.group(1))
            continue
        match = re.search(r"python3\s+-I\s+(\S+)(?:\s|$)", line)
        if match:
            python_checks.append(match.group(1))
            continue
        fail(f"unrecognised line in the {SECTION} code block: {line!r}")
    if psql_commands != 1:
        fail(f"expected exactly one psql command in the code block of {SECTION}, found {psql_commands}")
    return requirements, python_checks, clean


def upgrade_plan(prose: list[str], root: Path) -> list[str]:
    candidates: list[list[str]] = []
    for raw in prose:
        if ARROW not in raw:
            continue
        tokens = [token for token in re.findall(r"`([^`]+)`", raw) if token.endswith(".sql")]
        if len(tokens) >= 2:
            candidates.append(tokens)
    if not candidates:
        fail(f'no "{ARROW}"-separated .sql chain in the prose of {SECTION}')
    chain = max(candidates, key=len)
    resolved = []
    for token in chain:
        if token.startswith("contracts/"):
            resolved.append(token)
        elif (root / "contracts/db/postgres" / token).exists():
            resolved.append(f"contracts/db/postgres/{token}")
        else:
            fail(f"upgrade chain entry {token!r} does not exist under contracts/db/postgres")
    return resolved


def migrations(root: Path) -> list[str]:
    return sorted(p.relative_to(root).as_posix()
                  for p in (root / "contracts/db/postgres").glob("0*.sql"))


def require_exists(root: Path, paths: list[str], what: str) -> None:
    for path in paths:
        if not (root / path).is_file():
            fail(f"{what} entry {path!r} from {README} does not exist")


def main() -> int:
    if len(sys.argv) != 2:
        fail("usage: read-contract-gate.py <repo root>")
    root = Path(sys.argv[1]).resolve()
    readme = root / README
    if not readme.is_file():
        fail(f"{README} not found under {root}")
    code, prose, fenced = split_fences(section(readme.read_text(encoding="utf-8")))
    if fenced:
        fail(f"unclosed code fence in the {SECTION} section of {README}")

    requirements, python_checks, clean = code_plan(code)
    upgrade = upgrade_plan(prose, root)
    if not python_checks:
        fail(f"no `python3 -I ...` suite in the {SECTION} code block of {README}")
    if not clean:
        fail(f'no `psql ... -f ...` clean chain in the {SECTION} code block of {README}')
    if not upgrade:
        fail(f"empty upgrade chain in {README}")

    require_exists(root, requirements, "requirements")
    require_exists(root, python_checks, "python suite")
    require_exists(root, clean, "clean chain")
    require_exists(root, upgrade, "upgrade chain")

    # The plan must cover everything the branch ships, otherwise a new file would run
    # nowhere and the gate would look green without exercising it.
    on_disk = migrations(root)
    missing_clean = [m for m in on_disk if m not in clean]
    if missing_clean:
        fail(f"{README} clean chain does not run: {', '.join(missing_clean)}")
    missing_upgrade = [m for m in on_disk if m not in upgrade]
    if missing_upgrade:
        fail(f"{README} upgrade chain does not run: {', '.join(missing_upgrade)}")
    if [m for m in clean if m in on_disk] != on_disk:
        fail(f"{README} clean chain runs the migrations out of order")
    if [m for m in upgrade if m in on_disk] != on_disk:
        fail(f"{README} upgrade chain runs the migrations out of order")

    suites = sorted(p.relative_to(root).as_posix()
                    for p in (root / "contracts/tests").glob("test_*.py"))
    missing_suites = [s for s in suites if s not in python_checks]
    if missing_suites:
        fail(f"{README} does not run: {', '.join(missing_suites)}")

    sql_tests = sorted(p.relative_to(root).as_posix()
                       for p in (root / "contracts/db/postgres/tests").glob("*.sql"))
    for test_file in sql_tests:
        if test_file not in clean and test_file not in upgrade:
            fail(f"{README} runs neither the clean nor the upgrade chain with {test_file}")
    fixtures = sorted(p.relative_to(root).as_posix()
                      for p in (root / "contracts/db/postgres/tests/fixtures").glob("*.sql"))
    for fixture in fixtures:
        if fixture not in upgrade:
            fail(f"{README} upgrade chain does not place the fixture {fixture}")

    for path in requirements:
        print(f"requirement {path}")
    for path in python_checks:
        print(f"python {path}")
    for path in clean:
        print(f"clean {path}")
    for path in upgrade:
        print(f"upgrade {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
