"""Shared pytest configuration for the G1 skeleton tests.

`AEGIS_NO_SKIPS=1` (set by scripts/ci/python-gate.sh) turns every skip into a failure: a check the
CI job did not actually run is not evidence, the same rule the contract gate applies to
contracts/tests/*.py.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, cast

import pytest

_LOCAL_JOB_ID: str | None = None
_LOCAL_VOLUME_LOG: Path | None = None
if not os.environ.get("AEGIS_CI_JOB"):
    _LOCAL_JOB_ID = f"local-pytest-{os.getpid()}"
    os.environ["AEGIS_CI_JOB"] = _LOCAL_JOB_ID
    if not os.environ.get("AEGIS_CI_VOLUME_LOG"):
        _LOCAL_VOLUME_LOG = Path(tempfile.gettempdir()) / f"aegis-ci-volumes-{_LOCAL_JOB_ID}.txt"
        _LOCAL_VOLUME_LOG.write_text("", encoding="utf-8")
        os.environ["AEGIS_CI_VOLUME_LOG"] = str(_LOCAL_VOLUME_LOG)

#: `tests/live` needs a Temporal server; the CI `python` job has none, and a skipped check is not
#: evidence (AEGIS_NO_SKIPS). It is collected only when a target is configured, and the live runner
#: sets that variable. The committed replay fixture is what the default gate replays instead.
#:
#: The gateway rotation test runs the digest-pinned LiteLLM image (a ~1.3 GB pull on a cold runner)
#: against two fake upstreams; `scripts/ci/python-gate.sh` sets AEGIS_TEST_LLM_GATEWAY=1 and pulls
#: the image first, and `make llm-gateway-test` is the same test for one checkout. Anywhere else it
#: is not collected at all, so a plain `make test` never pulls an image on someone's laptop.
collect_ignore: list[str] = []
if not os.environ.get("AEGIS_TEMPORAL_TARGET"):
    collect_ignore.append("live")
if os.environ.get("AEGIS_TEST_LLM_GATEWAY") != "1":
    collect_ignore.append("test_llm_gateway_rotation.py")


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[object]) -> Any:
    report: Any = cast(Any, (yield))
    if (
        os.environ.get("AEGIS_NO_SKIPS") == "1"
        and getattr(report, "skipped", False)
        and report.when in {"setup", "call"}
    ):
        report.outcome = "failed"
        report.longrepr = (
            f"{report.nodeid}: skipped, but AEGIS_NO_SKIPS=1 requires every check to run"
        )
    return report


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Ensure any throwaway Neo4j container started during this pytest session is removed."""
    del exitstatus
    module = sys.modules.get("tests.graph_support")
    if module is not None:
        module.stop_test_graph()
    if _LOCAL_JOB_ID is None:
        return
    try:
        if shutil.which("podman") is not None:
            script = Path(__file__).resolve().parents[1] / "scripts" / "ci" / "check-volume-leak.sh"
            if script.is_file():
                checked = subprocess.run(
                    ["bash", str(script)],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=60,
                )
                if checked.returncode != 0:
                    session.exitstatus = pytest.ExitCode.TESTS_FAILED
                    sys.stderr.write(checked.stderr)
    finally:
        if _LOCAL_VOLUME_LOG is not None:
            _LOCAL_VOLUME_LOG.unlink(missing_ok=True)
