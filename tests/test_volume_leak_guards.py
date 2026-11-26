"""Regression tests for Podman anonymous-volume leak fixes and the CI dangling-volume guard."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
CHECK_SCRIPT = REPO / "scripts/ci/check-volume-leak.sh"

PODMAN_STUB = """#!/usr/bin/env bash
if [ "$1" = "volume" ] && [ "$2" = "ls" ]; then
  if [ -n "${STUB_DANGLING_VOLUMES:-}" ]; then
    printf '%s\\n' ${STUB_DANGLING_VOLUMES}
  fi
  exit 0
fi
exit 0
"""


def _run_guard(
    tmp_path: Path, args: list[str], *, env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    stub = bin_dir / "podman"
    stub.write_text(PODMAN_STUB, encoding="utf-8")
    stub.chmod(0o755)
    environment = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", **env}
    return subprocess.run(  # noqa: S603 - repository CI script under a stubbed podman
        ["bash", str(CHECK_SCRIPT), *args],
        capture_output=True,
        text=True,
        env=environment,
        timeout=30,
        check=False,
    )


def test_ci_volume_guard_records_and_allows_equal_or_fewer_dangling_volumes(
    tmp_path: Path,
) -> None:
    env_file = tmp_path / "github_env"
    recorded = _run_guard(
        tmp_path,
        ["--record"],
        env={"GITHUB_ENV": str(env_file), "STUB_DANGLING_VOLUMES": "vol1 vol2"},
    )
    assert recorded.returncode == 0, recorded.stderr
    assert env_file.read_text(encoding="utf-8").strip() == "DANGLING_VOLUMES_BEFORE=2"

    same = _run_guard(
        tmp_path,
        ["2"],
        env={"STUB_DANGLING_VOLUMES": "vol1 vol2"},
    )
    assert same.returncode == 0, same.stderr
    assert "2 -> 2" in same.stdout

    fewer = _run_guard(
        tmp_path,
        ["2"],
        env={"STUB_DANGLING_VOLUMES": "vol1"},
    )
    assert fewer.returncode == 0, fewer.stderr


def test_ci_volume_guard_fails_when_dangling_volumes_grow(tmp_path: Path) -> None:
    grew = _run_guard(
        tmp_path,
        [],
        env={"DANGLING_VOLUMES_BEFORE": "1", "STUB_DANGLING_VOLUMES": "vol1 leaked_anon"},
    )
    assert grew.returncode == 1
    assert "1 -> 2" in grew.stderr
    assert "leaked_anon" in grew.stderr


@pytest.mark.parametrize(
    ("path", "required_tmpfs"),
    [
        ("scripts/ci/python-gate.sh", ("/data:", "/logs:")),
        ("scripts/ci/neo4j-smoke.sh", ("/data:", "/logs:")),
        ("tests/test_evidence_store_seaweedfs.py", ("/data:",)),
    ],
)
def test_throwaway_stateful_containers_mount_tmpfs_on_image_volumes(
    path: str, required_tmpfs: tuple[str, ...]
) -> None:
    content = (REPO / path).read_text(encoding="utf-8")
    for target in required_tmpfs:
        assert target in content, (
            f"{path} must mount tmpfs on {target} to prevent anonymous volumes"
        )


def test_ci_and_test_container_removals_always_pass_volume_flag() -> None:
    bare_rm = re.compile(
        r"""(?:podman|_podman)\s*\(?\s*["']rm["']\s*,\s*["']-f["']\s*,(?!\s*["']-v["'])"""
    )
    bare_shell_rm = re.compile(r"""\bpodman\s+rm\s+-f(?!\s+-v\b)""")
    paths = [
        REPO / "scripts/ci/lib.sh",
        REPO / "scripts/ci/cleanup.sh",
        REPO / "scripts/temporal/run-live.sh",
        REPO / "scripts/lab/httpx-proxy-check.sh",
        REPO / "scripts/lab/lab-down.sh",
        REPO / "scripts/vulnlab/vulnlab-down.sh",
        REPO / "scripts/vulnlab/vulnlab-up.sh",
        REPO / "src/aegis/m06_runner/podman.py",
        REPO / "tests/graph_support.py",
        REPO / "tests/llm_gateway_support.py",
        REPO / "tests/m06_support.py",
        REPO / "tests/test_evidence_store_seaweedfs.py",
    ]
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert not bare_rm.search(text), f"{path} calls podman rm -f without -v"
        assert not bare_shell_rm.search(text), f"{path} calls podman rm -f without -v"
