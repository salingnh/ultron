"""Regression tests for Podman anonymous-volume leak fixes and the job-scoped CI guard."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
CHECK_SCRIPT = REPO / "scripts/ci/check-volume-leak.sh"

PODMAN_STUB = """#!/usr/bin/env bash
case "$1:$2" in
  ps:*)
    if [[ "$*" == *"label=aegis.ci-job="* ]]; then
      printf '%s\\n' ${STUB_JOB_CONTAINERS:-}
    fi
    ;;
  volume:ls)
    if [[ "$*" == *"label=aegis.ci-job="* ]]; then
      printf '%s\\n' ${STUB_JOB_VOLUMES:-}
    fi
    ;;
  volume:exists)
    for v in ${STUB_EXISTING_VOLUMES:-}; do
      if [ "$v" = "$3" ]; then
        exit 0
      fi
    done
    exit 1
    ;;
  container:inspect)
    printf '%s\\n' ${STUB_INSPECT_MOUNTS:-}
    ;;
esac
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
    environment = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "AEGIS_CI_JOB": "job-42",
        "AEGIS_CI_VOLUME_LOG": str(tmp_path / "volumes.txt"),
        **env,
    }
    return subprocess.run(  # noqa: S603 - repository CI script under a stubbed podman
        ["bash", str(CHECK_SCRIPT), *args],
        capture_output=True,
        text=True,
        env=environment,
        timeout=30,
        check=False,
    )


def test_job_scoped_guard_records_env_and_ignores_unrelated_host_volumes(
    tmp_path: Path,
) -> None:
    env_file = tmp_path / "github_env"
    log_file = tmp_path / "volumes.txt"
    recorded = _run_guard(
        tmp_path,
        ["--record"],
        env={
            "GITHUB_ENV": str(env_file),
            "AEGIS_CI_JOB": "python-99-1",
            "AEGIS_CI_VOLUME_LOG": str(log_file),
        },
    )
    assert recorded.returncode == 0, recorded.stderr
    env_text = env_file.read_text(encoding="utf-8")
    assert "AEGIS_CI_JOB=python-99-1" in env_text
    assert f"AEGIS_CI_VOLUME_LOG={log_file}" in env_text

    # Unrelated volumes from other jobs on the shared host exist, but none belong to this job.
    clean = _run_guard(
        tmp_path,
        [],
        env={
            "AEGIS_CI_JOB": "python-99-1",
            "AEGIS_CI_VOLUME_LOG": str(log_file),
            "STUB_EXISTING_VOLUMES": "other-job-anon-vol",
        },
    )
    assert clean.returncode == 0, clean.stderr
    assert "0 leaked podman volumes for aegis.ci-job=python-99-1" in clean.stdout


def test_job_scoped_guard_fails_on_labelled_volume_or_container(tmp_path: Path) -> None:
    leaked_vol = _run_guard(
        tmp_path,
        [],
        env={"STUB_JOB_VOLUMES": "ci-job-42-vol"},
    )
    assert leaked_vol.returncode == 1
    assert "labelled:ci-job-42-vol" in leaked_vol.stderr

    leaked_ctr = _run_guard(
        tmp_path,
        [],
        env={
            "STUB_JOB_CONTAINERS": "ctr-123",
            "STUB_INSPECT_MOUNTS": "anon-vol-from-ctr",
            "STUB_EXISTING_VOLUMES": "anon-vol-from-ctr",
        },
    )
    assert leaked_ctr.returncode == 1
    assert "container:ctr-123" in leaked_ctr.stderr
    assert "container-volume:anon-vol-from-ctr" in leaked_ctr.stderr


def test_job_scoped_guard_fails_when_recorded_anonymous_volume_survived_removal(
    tmp_path: Path,
) -> None:
    log_file = tmp_path / "volumes.txt"
    log_file.write_text("leaked-anon-abc\nremoved-anon-xyz\n", encoding="utf-8")
    result = _run_guard(
        tmp_path,
        [],
        env={
            "AEGIS_CI_VOLUME_LOG": str(log_file),
            "STUB_EXISTING_VOLUMES": "leaked-anon-abc",
        },
    )
    assert result.returncode == 1
    assert "container-volume:leaked-anon-abc" in result.stderr
    assert "removed-anon-xyz" not in result.stderr


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
