"""`make help` is the repository's own index: it must run, and it must name every target.

The bug this test exists for: the help text was a chain of single-quoted `printf` arguments, and
one description contained `checkout\\'s`. A backslash cannot escape a quote inside single quotes, so
that quote ended the string, the rest of the line became shell code, and `make help` died with
`syntax error near unexpected token '('` - before printing a single line. Nothing caught it, because
no check ever ran the target.

The text is now data (`define HELP`, printed with `$(info)`), so a description cannot break the
recipe again. What can still go wrong is the list drifting away from the targets, so this test runs
`make help` and compares it with the Makefile's `.PHONY` line in both directions: every target has
an entry, and every entry is a target.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MAKEFILE = REPO / "Makefile"

#: `make target   description` - the one form an entry takes. One space is enough: the longest
#: names cannot be padded to one column, and a continuation line never starts at column 0.
ENTRY = re.compile(r"^make (?P<target>[a-z0-9][a-z0-9-]*)\s+\S")


def phony_targets() -> set[str]:
    text = MAKEFILE.read_text(encoding="utf-8")
    match = re.search(r"^\.PHONY:(?P<names>.*?)(?=^\S)", text, re.MULTILINE | re.DOTALL)
    assert match is not None, "the Makefile has no .PHONY list"
    return set(match.group("names").replace("\\", " ").split())


def help_output() -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    # Another make must not be able to steer this one (a parent gate exports its own flags).
    for name in ("MAKEFLAGS", "MFLAGS", "MAKELEVEL"):
        environment.pop(name, None)
    return subprocess.run(
        ["make", "--no-print-directory", "help"],
        cwd=REPO,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def test_make_help_runs_cleanly() -> None:
    result = help_output()
    assert result.returncode == 0, f"make help failed:\n{result.stderr}"
    assert result.stderr == "", f"make help wrote to stderr:\n{result.stderr}"
    assert result.stdout.strip(), "make help printed nothing"


def test_make_help_names_every_phony_target_and_nothing_else() -> None:
    result = help_output()
    assert result.returncode == 0, result.stderr
    entries = {
        match.group("target")
        for line in result.stdout.splitlines()
        if (match := ENTRY.match(line)) is not None
    }
    targets = phony_targets()
    assert not targets - entries, f"make help does not list: {sorted(targets - entries)}"
    assert not entries - targets, f"make help lists unknown targets: {sorted(entries - targets)}"
