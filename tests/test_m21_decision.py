"""M21's decision table replayed over the recorded lab captures (item 87, G2-B).

The fixtures are the exact output of the pinned Nuclei image during the feasibility run
(`tests/fixtures/verify/nuclei/*.jsonl`, sha-pinned in `index.json`), converted by the reviewed
`adapters/m21/nuclei_verify/parser.py:result_document` into the contract's result documents
(`tests/fixtures/verify/result/*.json`, rebuilt by `build_results.py --check`).

What this test pins:

* the recorded pair **verifies**: the canary is read on 2.4.49 + Alias, the patched 2.4.51 and the
  absent path do not read it;
* the stock 2.4.49 (`403`, version match without the vulnerable configuration) is
  **NOT_REPRODUCED** - never a fix;
* both catch-alls (a page for every path, and a fake canary-shaped value) are **INCONCLUSIVE**;
* a replayed twin and a benign path that matches are **INCONCLUSIVE**, never VERIFIED (the "do not
  weaken the oracle" rows);
* a run whose document is not this run's (cap, roles, target, pack) is INCONCLUSIVE with the
  reason, and the verdicts agree with the recorded feasibility matrix.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from aegis.common import verification
from aegis.m21_verify import controls as control_map
from aegis.m21_verify import oracle
from aegis.m21_verify.result import load_result

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "verify"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _index() -> dict[str, Any]:
    index: dict[str, Any] = json.loads((FIXTURES / "index.json").read_text(encoding="utf-8"))
    return index


def _task(name: str) -> dict[str, Any]:
    task: dict[str, Any] = _index()["task"][f"result/{name}.json"]
    return task


CHECK_ID = "cve-2021-41773-traversal"


def _inputs(name: str) -> dict[str, Any]:
    meta = _task(name)
    return {
        "check_id": CHECK_ID,
        "check_pack_sha256": "0" * 64,
        "request_cap": 4,
        "target": meta["positive"].removeprefix("service:").removesuffix("/tcp"),
        "twin": meta["twin"].removeprefix("service:").removesuffix("/tcp"),
        "benign_path": meta["benign_path"],
    }


def _expectation(name: str, **overrides: Any) -> oracle.Expectation:
    inputs = _inputs(name)
    check_id = inputs["check_id"]
    check = verification.load_checks().by_id(check_id)
    assert check is not None
    mapping = control_map.load_controls(FIXTURES / "controls.json")
    entry = control_map.controls_for(mapping, check_id)
    assert entry is not None
    address, port = inputs["target"].rsplit(":", 1)
    twin_address, twin_port = inputs["twin"].rsplit(":", 1)
    expectation = oracle.Expectation(
        check=check,
        network_profile="lab",
        expected_seq=1,
        target=oracle.RoleTarget("positive", address, int(port)),
        controls=(oracle.RoleTarget("patched_twin", twin_address, int(twin_port)),),
        check_pack_sha256=inputs["check_pack_sha256"],
        canary_sha256=mapping.canary_sha256,
        canary_name_sha256=mapping.canary_name_sha256,
        canary_path=entry.canary_path,
        benign_path=inputs["benign_path"],
    )
    return expectation


def _document(name: str) -> Any:
    return load_result((FIXTURES / "result" / f"{name}.json").read_bytes())


CASES = {
    "verified": "VERIFIED",
    "not_reproduced": "NOT_REPRODUCED",
    "twin_reproduced": "INCONCLUSIVE",
    "benign_matched": "INCONCLUSIVE",
    "catch_all": "INCONCLUSIVE",
    "foreign_canary": "INCONCLUSIVE",
}


@pytest.mark.parametrize(("name", "outcome"), sorted(CASES.items()))
def test_the_recorded_cases_get_the_table_outcome(name: str, outcome: str) -> None:
    decision = oracle.decide(_document(name), _expectation(name))
    assert decision.outcome == outcome, decision.reason


def test_only_a_positive_with_both_controls_negative_is_verified() -> None:
    decision = oracle.decide(_document("verified"), _expectation("verified"))
    assert decision.outcome == "VERIFIED"
    assert decision.matched() == {
        "positive": True,
        "control_a": False,
        "control_b": False,
        "discriminating": True,
        "reason": decision.reason,
    }


def test_not_reproduced_is_not_a_fix_and_says_so() -> None:
    decision = oracle.decide(_document("not_reproduced"), _expectation("not_reproduced"))
    assert decision.outcome == "NOT_REPRODUCED"
    assert "not a fix" in decision.reason


@pytest.mark.parametrize(
    "name", ["twin_reproduced", "benign_matched", "catch_all", "foreign_canary"]
)
def test_a_guard_never_verifies(name: str) -> None:
    decision = oracle.decide(_document(name), _expectation(name))
    assert decision.outcome == "INCONCLUSIVE"
    assert decision.discriminating is False or decision.control_a or decision.control_b


def test_the_catch_all_and_the_fake_canary_are_named() -> None:
    catch_all = oracle.decide(_document("catch_all"), _expectation("catch_all"))
    assert "catch-all" in catch_all.reason
    fake = oracle.decide(_document("foreign_canary"), _expectation("foreign_canary"))
    assert "canary-shaped" in fake.reason


def test_the_verdicts_agree_with_the_recorded_feasibility_matrix() -> None:
    matrix = json.loads((FIXTURES / "matrix.json").read_text(encoding="utf-8"))["httpd"]
    recorded = {
        "verified": matrix["decision"]["outcome"].upper(),
        "not_reproduced": matrix["stock_decision"]["outcome"].upper(),
        "catch_all": matrix["catchall_decision"]["plain"]["outcome"].upper(),
        "foreign_canary": matrix["catchall_decision"]["evil"]["outcome"].upper(),
    }
    for name, expected in recorded.items():
        assert oracle.decide(_document(name), _expectation(name)).outcome == expected, name


@pytest.mark.parametrize(
    ("mutation", "needle"),
    [
        ({"check_id": "config.tls.certificate"}, "check"),
        ({"request_cap": 3}, "cap"),
        ({"requests_sent": 9}, "cap"),
        ({"check_pack_sha256": "1" * 64}, "pack"),
    ],
)
def test_a_document_that_is_not_this_run_is_inconclusive(
    mutation: dict[str, Any], needle: str
) -> None:
    document = _document("verified")
    raw = dict(document.raw)
    raw.update(mutation)
    decision = oracle.decide(load_result(json.dumps(raw).encode()), _expectation("verified"))
    assert decision.outcome == "INCONCLUSIVE"
    assert needle in decision.reason


def test_a_target_that_does_not_match_the_finding_is_refused() -> None:
    document = _document("verified")
    expectation = _expectation("verified")
    other = oracle.Expectation(
        check=expectation.check,
        network_profile="lab",
        expected_seq=1,
        target=oracle.RoleTarget("positive", "10.114.59.99", 80),
        controls=expectation.controls,
        check_pack_sha256=expectation.check_pack_sha256,
        canary_sha256=expectation.canary_sha256,
        canary_path=expectation.canary_path,
        benign_path=expectation.benign_path,
    )
    decision = oracle.decide(document, other)
    assert decision.outcome == "INCONCLUSIVE"
    assert "signed task names" in decision.reason


def test_a_silent_target_is_not_a_negative() -> None:
    raw = json.loads((FIXTURES / "result" / "verified.json").read_text(encoding="utf-8"))
    for target in raw["targets"]:
        if target["role"] == "patched_twin":
            target["answered"] = False
            target["requests"] = []
    raw["requests_sent"] = 2
    decision = oracle.decide(load_result(json.dumps(raw).encode()), _expectation("verified"))
    assert decision.outcome == "INCONCLUSIVE"
    assert "did not answer" in decision.reason


def test_an_oracle_without_an_implementation_is_refused_by_name() -> None:
    # The E1 oracles arrive with the config-verify provider (slice S4); until then a config check
    # raises by name instead of producing a weaker verdict.
    expectation = _expectation("verified")
    with pytest.raises(oracle.OracleError, match="not implemented"):
        oracle._e1(_document("verified"), expectation)


def test_the_fixtures_are_pinned_and_current() -> None:
    index = _index()
    for relative, digest in index["captures"].items():
        assert _sha256(FIXTURES / relative) == digest, relative
    for relative, digest in index["results"].items():
        assert _sha256(FIXTURES / relative) == digest, relative
    import importlib.util

    path = FIXTURES / "build_results.py"
    spec = importlib.util.spec_from_file_location("aegis_verify_fixture_builder", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.main(["--check"]) == 0
