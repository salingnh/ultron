"""The internet smoke compares the audit against the *rendered* structured authorization.

`scripts/internet/smoke.py:202` compared the broker audit line to the free-text campaign label
(`"owner, item 61, 2026-11-25"`), but the broker records the rendered structured authorization
(`owner | reference | date | suffixes`), so a correct run failed that check (item #61 follow-up).

Importing the script is safe: it only defines functions/constants at module level and its `main()`
runs under `__main__`. No DNS, no HTTP: the checked records are plain dicts.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SMOKE = REPO_ROOT / "scripts" / "internet" / "smoke.py"


def _smoke() -> ModuleType:
    name = "aegis_internet_smoke_under_test"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, SMOKE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _record(**overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "kind": "egress",
        "decision": "allow",
        "reason": "OK",
        "host": "crt.sh",
        "port": 443,
        "network_profile": "internet",
        "authorization": _smoke().authorization_line(),
    }
    record.update(overrides)
    return record


def test_the_audit_line_is_the_rendered_structured_authorization() -> None:
    smoke = _smoke()
    assert smoke.authorization_line() == (
        "owner | owner, item 61, 2026-11-25 | 2026-11-25 | icomm.vn, salingnh.com"
    )
    # The free-text label is a different value: that mismatch is what failed the smoke.
    assert smoke.authorization_line() != smoke.AUTHORIZATION


def test_check_audit_accepts_the_signed_rendering() -> None:
    smoke = _smoke()
    assert smoke.check_audit([_record()]) == {"OK": 1}


def test_check_audit_refuses_the_free_text_label() -> None:
    smoke = _smoke()
    with pytest.raises(SystemExit):
        smoke.check_audit([_record(authorization=smoke.AUTHORIZATION)])


def test_check_audit_refuses_a_missing_authorization() -> None:
    smoke = _smoke()
    with pytest.raises(SystemExit):
        smoke.check_audit([_record(authorization=None)])


def test_the_smoke_roe_authorization_is_what_m06_accepts() -> None:
    # authorization_line() validates through M06's own check; a drift in the script's RoE fails here
    # instead of during the owner's run.
    smoke = _smoke()
    assert smoke.SMOKE_POLICY["network_profile"] == "internet"
    assert smoke.SMOKE_POLICY["authorization"]["authorized_suffixes"] == list(smoke.AUTHORIZED)
