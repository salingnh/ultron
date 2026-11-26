"""M06 input staging: the files a tool reads, and the values that must never reach argv.

`tests/test_spec.py` covers the argv rule (OI-12). This suite covers the other half of the same
contract: `input.targets` is written to `/in/targets.txt` as the tool's own value (no `dns:`/`ip:`
prefix), and an integer `ports` array is written to `/in/ports.txt` one port per line - the form
the pinned `network.discover_services` manifest reads with `-ports-file`, because the rendering rule
forbids joining a list into a single argv element.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aegis.m06_runner.job import JobRunner
from tests import m06_support


def _write(
    directory: Path, input_values: dict[str, Any], manifest_name: str = "manifest.naabu.yaml"
) -> None:
    # The pinned manifest decides the target rendering (`runtime.targetsFormat`); the default here
    # is the port scanner's, whose `canonical` format is the one this suite checks.
    manifest, _ = m06_support.manifest(manifest_name)
    JobRunner._write_inputs(  # noqa: SLF001 - the seam under test
        directory, input_values, manifest
    )


def test_targets_are_written_without_the_canonical_key_prefix(tmp_path: Path) -> None:
    _write(tmp_path, {"targets": ["dns:lab.aegis.test", "ip:10.114.53.211", "plain.example"]})

    assert (tmp_path / "targets.txt").read_text(encoding="utf-8") == (
        "lab.aegis.test\n10.114.53.211\nplain.example\n"
    )


def test_an_integer_port_array_becomes_one_port_per_line(tmp_path: Path) -> None:
    _write(tmp_path, {"targets": ["ip:10.114.53.211"], "ports": [22, 443, 8080]})

    assert (tmp_path / "ports.txt").read_text(encoding="utf-8") == "22\n443\n8080\n"


def test_no_ports_file_is_staged_without_an_integer_ports_input(tmp_path: Path) -> None:
    # A capability without a `ports` field must not get a file it never asked for, and a value that
    # is not an integer list is never coerced into one.
    for input_values in (
        {"targets": ["dns:lab.aegis.test"]},
        {"targets": ["dns:lab.aegis.test"], "ports": []},
        {"targets": ["dns:lab.aegis.test"], "ports": ["80", "443"]},
        {"targets": ["dns:lab.aegis.test"], "ports": [80, True]},
    ):
        directory = tmp_path / f"case-{len(list(tmp_path.iterdir()))}"
        directory.mkdir()
        _write(directory, input_values)
        assert not (directory / "ports.txt").exists(), input_values


def test_job_layout_sets_input_modes_independent_of_umask(tmp_path: Path) -> None:
    import os
    import stat

    from aegis.m06_runner.podman import JobLayout

    previous = os.umask(0o077)
    try:
        layout = JobLayout(tmp_path / "job-077").create()
        _write(layout.input, {"targets": ["dns:lab.aegis.test"], "ports": [80, 443]})
    finally:
        os.umask(previous)

    assert stat.S_IMODE(layout.input.stat().st_mode) == 0o755
    assert stat.S_IMODE((layout.input / "targets.txt").stat().st_mode) == 0o644
    assert stat.S_IMODE((layout.input / "ports.txt").stat().st_mode) == 0o644
