#!/usr/bin/env python3
"""Chạy bộ conformance registry/adapter trên fixture Subfinder + DNSx + fingerprintx + httpx (S1.5b, G1.6b).

Bộ kiểm nằm ở contracts/tests/conformance/harness.py và là kiểm contract tham chiếu, không phải
runtime sản phẩm: adapter thật thay `FixtureAdapter` nhưng phải qua đúng bộ kiểm này. Chi tiết
luật được kiểm ở docstring của harness; lý do (caps, target binding, pin, provenance) ở
contracts/capabilities/README.md và contracts/interfaces/README.md §1.

G1.6b: hai adapter service chạy parser thật của gói `adapters/m08/<tool>/parser.py` (nạp bằng
đường dẫn, không import package), nên cùng một fixture/luật với DNS nhưng đầu vào là khóa
`service:<ip>:<port>/tcp` và đầu ra là observation service.http/tls.
"""

from __future__ import annotations

import runpy
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HARNESS = runpy.run_path(str(ROOT / "tests/conformance/harness.py"))
CONTEXT = HARNESS["load"](ROOT / "tests/conformance/fixtures/context.json")
REPO = ROOT.parent


def _real_parser(provider: str):
    """The adapter's own parser, loaded by path (contracts/ never imports product code)."""
    package = REPO / "adapters/m08" / provider / "parser.py"
    return runpy.run_path(str(package))["parse"]


class ProviderConformance(unittest.TestCase):
    """Mỗi provider chạy trọn bảy handler trên fixture đã pin."""

    def _run(self, provider: str, minimum_checks: int, parser=None) -> None:
        failures, checks = HARNESS["run_provider_suite"](provider, CONTEXT, parser=parser)
        self.assertGreaterEqual(checks, minimum_checks, f"{provider}: số check giảm")
        self.assertEqual(failures, [], "\n".join(failures))

    def test_subfinder_fixtures(self) -> None:
        self._run("subfinder", 9)

    def test_dnsx_fixtures(self) -> None:
        self._run("dnsx", 9)

    def test_fingerprintx_fixtures(self) -> None:
        self._run("fingerprintx", 9, parser=_real_parser("fingerprintx"))

    def test_httpx_fixtures(self) -> None:
        self._run("httpx", 9, parser=_real_parser("httpx"))


class RegistryPolicyConformance(unittest.TestCase):
    """Negative fixture cấp registry: unknown capability và input vượt trần phải POLICY_DENIED."""

    def test_policy_fixtures_are_refused_by_the_registry(self) -> None:
        failures, checks = HARNESS["run_policy_suite"](CONTEXT)
        self.assertGreaterEqual(checks, 9)
        self.assertEqual(failures, [], "\n".join(failures))


if __name__ == "__main__":
    unittest.main()
