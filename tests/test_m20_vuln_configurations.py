"""NVD configuration semantics of the M20 matcher (G1.6, item 61): pure tests, no database.

The shapes below are copied from real NVD CVE JSON 2.0 documents (`configurations[]` with
`operator`, `nodes[]`, `negate`, `children` and `vulnerable`), because the decision these tests pin
is exactly the decision the trial found broken: the flattened criteria list made an httpd 2.4.49
service a candidate for 14 CVEs that are either "httpd on Windows" or "NVD published no version".

Each test states the wrong candidate the old flat reading produced, so a regression is readable
from the failure alone.
"""

from __future__ import annotations

from typing import Any

import pytest

from aegis.m20_vuln.configurations import (
    PLATFORM_UNCONFIRMED_CODE,
    VERSION_UNSPECIFIED_CODE,
    Configuration,
    Criterion,
    Decision,
    Verdict,
    decide,
    observe,
    parse_configurations,
    products,
)
from aegis.m20_vuln.cpe import parse_cpe

HTTPD = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
HTTPD_ALL = "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
HTTPD_NA = "cpe:2.3:a:apache:http_server:-:*:*:*:*:*:*:*"
WINDOWS = "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"
FEDORA = "cpe:2.3:o:fedoraproject:fedora:34:*:*:*:*:*:*:*"


def criterion(criteria: str, *, vulnerable: bool = True, **bounds: object) -> dict[str, Any]:
    """One NVD `cpeMatch` entry, in NVD's own camelCase spelling."""
    stored: dict[str, Any] = {"criteria": criteria, "vulnerable": vulnerable}
    for key, value in bounds.items():
        stored[key] = value
    return stored


def node(
    *criteria: dict[str, Any],
    operator: str = "OR",
    negate: bool = False,
    children: tuple[dict[str, Any], ...] = (),
) -> dict[str, Any]:
    entry: dict[str, Any] = {"operator": operator, "negate": negate, "cpeMatch": list(criteria)}
    if children:
        entry["children"] = list(children)
    return entry


def configuration(*nodes: dict[str, Any], operator: str | None = None) -> dict[str, Any]:
    entry: dict[str, Any] = {"nodes": list(nodes)}
    if operator is not None:
        entry["operator"] = operator
    return entry


def _stored_criterion(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "criteria": entry["criteria"],
        "vulnerable": bool(entry.get("vulnerable", False)),
        "version_start_including": entry.get("versionStartIncluding"),
        "version_start_excluding": entry.get("versionStartExcluding"),
        "version_end_including": entry.get("versionEndIncluding"),
        "version_end_excluding": entry.get("versionEndExcluding"),
        "match_criteria_id": None,
    }


def _stored_node(entry: dict[str, Any]) -> dict[str, Any]:
    stored: dict[str, Any] = {
        "operator": entry.get("operator") or "OR",
        "negate": bool(entry.get("negate")),
        "cpe_match": [_stored_criterion(item) for item in entry.get("cpeMatch") or ()],
    }
    if entry.get("children"):
        stored["children"] = [_stored_node(child) for child in entry["children"]]
    return stored


def _collect(entry: dict[str, Any], flat: list[dict[str, Any]]) -> None:
    flat.extend(entry.get("cpe_match") or [])
    for child in entry.get("children") or ():
        _collect(child, flat)


def affected(*configurations: dict[str, Any]) -> dict[str, Any]:
    """An `affected` document in the shape M18 stores: the flat list and the tree."""
    stored: list[dict[str, Any]] = [
        {
            "operator": entry.get("operator") or "OR",
            "nodes": [_stored_node(item) for item in entry.get("nodes") or ()],
        }
        for entry in configurations
    ]
    flat: list[dict[str, Any]] = []
    for entry in stored:
        for item in entry["nodes"]:
            _collect(item, flat)
    return {"cpe_match": flat, "configurations": stored}


def decision_for(document: dict[str, Any], *cpes: str) -> Decision:
    return decide(parse_configurations(document), observe(parse_cpe(cpe) for cpe in cpes))


def matched_criterion(decision: Decision) -> Criterion:
    """The confirming criterion of a decision that matched (a candidate always carries one)."""
    assert decision.criterion is not None
    return decision.criterion


def test_an_and_configuration_needs_the_platform_it_names() -> None:
    """CVE-2024-40898: "SSRF in Apache HTTP Server on Windows" - httpd < 2.4.62 AND windows."""
    document = affected(
        configuration(
            node(criterion(HTTPD_ALL, versionEndExcluding="2.4.62")),
            node(criterion(WINDOWS, vulnerable=False)),
            operator="AND",
        )
    )

    decision = decision_for(document, HTTPD)
    assert decision.matched is False
    assert decision.verdict is Verdict.UNKNOWN
    assert decision.reason == PLATFORM_UNCONFIRMED_CODE

    # With the platform observed (an asset that carries both CPEs) the same CVE does apply.
    observed_platform = decision_for(document, HTTPD, WINDOWS)
    assert observed_platform.matched is True
    assert matched_criterion(observed_platform).range_text == "< 2.4.62"


def test_an_or_configuration_is_satisfied_by_one_of_its_nodes() -> None:
    """CVE-2021-41773's shape: httpd 2.4.49, plus unrelated platform configurations."""
    document = affected(
        configuration(node(criterion(HTTPD), criterion(HTTPD_ALL, versionEndExcluding="2.4.50"))),
        configuration(node(criterion(FEDORA))),
    )

    decision = decision_for(document, HTTPD)
    assert decision.matched is True
    assert matched_criterion(decision).exact is True
    assert decision.reason is None


def test_a_criterion_with_no_version_is_not_a_version_match() -> None:
    """CVE-1999-0289's shape: `http_server:-` matches no version; the product is unconfirmed."""
    document = affected(configuration(node(criterion(HTTPD_NA))))

    assert decision_for(document, HTTPD).matched is False
    decision = decision_for(document, HTTPD)
    assert decision.verdict is Verdict.UNKNOWN
    assert decision.reason == VERSION_UNSPECIFIED_CODE

    # An exact-version criterion for another version is a decision, not an unknown.
    exact_other = affected(
        configuration(node(criterion("cpe:2.3:a:apache:http_server:2.2:*:*:*:*:*:*:*")))
    )
    assert decision_for(exact_other, HTTPD).matched is False
    assert decision_for(exact_other, HTTPD).reason is None


def test_a_bounded_range_on_a_wildcard_product_still_matches() -> None:
    document = affected(
        configuration(
            node(criterion(HTTPD_ALL, versionStartIncluding="2.4.0", versionEndExcluding="2.4.62"))
        )
    )

    decision = decision_for(document, HTTPD)
    assert decision.matched is True
    assert matched_criterion(decision).range_text == ">= 2.4.0, < 2.4.62"
    assert matched_criterion(decision).exact is False


def test_a_versionless_criterion_does_not_rescue_a_platform_requirement() -> None:
    """CVE-1999-0289 again, with the Windows node: both reasons apply, the version is the first."""
    document = affected(
        configuration(
            node(criterion(HTTPD_NA)),
            node(criterion(WINDOWS, vulnerable=False)),
            operator="AND",
        )
    )

    assert decision_for(document, HTTPD).reason == VERSION_UNSPECIFIED_CODE


def test_a_negated_node_never_confirms() -> None:
    negated = node(negate=True, children=(node(criterion(HTTPD)),))
    document = affected(configuration(negated))

    assert negated["negate"] is True
    decision = decision_for(document, HTTPD)
    assert decision.matched is False
    assert decision.verdict is Verdict.FALSE


def test_a_not_vulnerable_criterion_is_never_a_candidate() -> None:
    """A `vulnerable: false` platform node on its own says "present, not the vulnerable part"."""
    document = affected(configuration(node(criterion(WINDOWS, vulnerable=False))))

    assert decision_for(document, HTTPD, WINDOWS).matched is False


def test_children_follow_their_parent_operator() -> None:
    parent = node(
        criterion(HTTPD_ALL, versionEndExcluding="2.4.62"),
        operator="AND",
        children=(node(criterion(WINDOWS, vulnerable=False)),),
    )
    document = affected(configuration(parent))

    assert decision_for(document, HTTPD).reason == PLATFORM_UNCONFIRMED_CODE
    assert decision_for(document, HTTPD, WINDOWS).matched is True


def test_a_legacy_flat_revision_still_decides_without_the_tree() -> None:
    """Rows synced before the tree was stored keep the flat OR semantics, minus the wildcard."""
    legacy = {
        "cpe_match": [
            {"criteria": HTTPD_NA, "vulnerable": True},
            {
                "criteria": HTTPD_ALL,
                "vulnerable": True,
                "version_start_including": "2.4.0",
                "version_end_excluding": "2.4.62",
            },
        ]
    }

    decision = decide(parse_configurations(legacy), observe([parse_cpe(HTTPD)]))
    assert decision.matched is True
    assert matched_criterion(decision).range_text == ">= 2.4.0, < 2.4.62"

    only_wildcard = {"cpe_match": [{"criteria": HTTPD_NA, "vulnerable": True}]}
    assert decide(parse_configurations(only_wildcard), observe([parse_cpe(HTTPD)])).matched is False


def test_the_exact_criterion_wins_over_the_range_for_confidence() -> None:
    document = affected(
        configuration(
            node(
                criterion(HTTPD_ALL, versionStartIncluding="2.4.0", versionEndExcluding="2.4.62"),
                criterion(HTTPD),
            )
        )
    )

    decision = decide(parse_configurations(document), observe([parse_cpe(HTTPD)]))
    assert matched_criterion(decision).exact is True
    assert matched_criterion(decision).range_text is None


def test_a_configuration_without_nodes_is_ignored_and_an_empty_document_matches_nothing() -> None:
    assert parse_configurations({"configurations": [{"operator": "AND", "nodes": []}]}) == ()
    assert parse_configurations(None) == ()
    assert parse_configurations({"cpe_match": []}) == ()
    assert decide((), observe([parse_cpe(HTTPD)])).matched is False


def test_the_products_of_a_revision_are_its_narrowing_buckets() -> None:
    document = affected(
        configuration(node(criterion(HTTPD_ALL, versionEndExcluding="2.4.62"))),
        configuration(node(criterion(FEDORA))),
    )

    assert products(parse_configurations(document)) == {
        ("apache", "http_server"),
        ("fedoraproject", "fedora"),
    }


@pytest.mark.parametrize(
    "document",
    [
        {"cpe_match": "not a list", "configurations": "not a list"},
        {"cpe_match": [None, 3, {"no": "criteria"}]},
        {"configurations": [{"nodes": [{"cpeMatch": [{"criteria": 3}]}]}]},
    ],
)
def test_a_malformed_document_is_skipped_not_guessed(document: dict[str, object]) -> None:
    assert decide(parse_configurations(document), observe([parse_cpe(HTTPD)])).matched is False


def test_the_tree_and_the_flat_list_name_the_same_products() -> None:
    """M18 stores both; a revision whose tree lost a product would mis-bucket it."""
    document = affected(
        configuration(
            node(criterion(HTTPD_ALL, versionEndExcluding="2.4.62")),
            node(criterion(WINDOWS, vulnerable=False)),
            operator="AND",
        )
    )
    stored = document["configurations"]
    assert [entry["operator"] for entry in stored] == ["AND"]
    assert {entry["criteria"] for entry in document["cpe_match"]} == {HTTPD_ALL, WINDOWS}
    assert isinstance(parse_configurations(document)[0], Configuration)
