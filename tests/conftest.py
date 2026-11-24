"""Shared pytest configuration for the G1 skeleton tests.

`AEGIS_NO_SKIPS=1` (set by scripts/ci/python-gate.sh) turns every skip into a failure: a check the
CI job did not actually run is not evidence, the same rule the contract gate applies to
contracts/tests/*.py.
"""

from __future__ import annotations

import os
from typing import Any, cast

import pytest


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
