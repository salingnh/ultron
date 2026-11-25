"""Shared pytest configuration for the G1 skeleton tests.

`AEGIS_NO_SKIPS=1` (set by scripts/ci/python-gate.sh) turns every skip into a failure: a check the
CI job did not actually run is not evidence, the same rule the contract gate applies to
contracts/tests/*.py.
"""

from __future__ import annotations

import os
from typing import Any, cast

import pytest

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
