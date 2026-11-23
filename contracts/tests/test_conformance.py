#!/usr/bin/env python3
"""Chạy bộ conformance registry/adapter trên fixture Subfinder + DNSx (S1.5b).

Bộ kiểm nằm ở contracts/tests/conformance/harness.py và là kiểm contract tham chiếu, không phải
runtime sản phẩm: adapter thật thay `FixtureAdapter` nhưng phải qua đúng bộ kiểm này. Chi tiết
luật được kiểm ở docstring của harness; lý do (caps, target binding, pin, provenance) ở
contracts/capabilities/README.md và contracts/interfaces/README.md §1.
"""
from __future__ import annotations

import runpy
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HARNESS = runpy.run_path(str(ROOT / "tests/conformance/harness.py"))
CONTEXT = HARNESS["load"](ROOT / "tests/conformance/fixtures/context.json")


class ProviderConformance(unittest.TestCase):
    """Mỗi provider chạy trọn bảy handler trên fixture đã pin."""

    def _run(self, provider: str, minimum_checks: int) -> None:
        failures, checks = HARNESS["run_provider_suite"](provider, CONTEXT)
        self.assertGreaterEqual(checks, minimum_checks, f"{provider}: số check giảm")
        self.assertEqual(failures, [], "\n".join(failures))

    def test_subfinder_fixtures(self) -> None:
        self._run("subfinder", 9)

    def test_dnsx_fixtures(self) -> None:
        self._run("dnsx", 9)


class RegistryPolicyConformance(unittest.TestCase):
    """Negative fixture cấp registry: unknown capability và input vượt trần phải POLICY_DENIED."""

    def test_policy_fixtures_are_refused_by_the_registry(self) -> None:
        failures, checks = HARNESS["run_policy_suite"](CONTEXT)
        self.assertGreaterEqual(checks, 9)
        self.assertEqual(failures, [], "\n".join(failures))


if __name__ == "__main__":
    unittest.main()
