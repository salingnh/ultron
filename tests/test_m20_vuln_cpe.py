"""CPE parsing and version bounds of the M20 matcher (G1.6 slice C): pure tests, no database.

These pin the only decision the matcher really makes: is this observation's CPE+version inside a
published NVD criterion? A false positive becomes a wrong AFFECTED_BY edge in the graph, so every
bound form (exact, start/end including and excluding, wrong product, no version) is asserted from
both sides.
"""

from __future__ import annotations

import pytest

from aegis.m20_vuln.cpe import (
    CpeError,
    CpeMatch,
    compare_versions,
    parse_cpe,
    parse_version,
)

NGINX = "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"


def test_a_cpe_2_3_string_is_split_into_its_parts() -> None:
    cpe = parse_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
    assert (cpe.part, cpe.vendor, cpe.product, cpe.version) == (
        "a",
        "apache",
        "http_server",
        "2.4.49",
    )
    assert cpe.has_version is True
    assert cpe.product_key == ("apache", "http_server")
    assert parse_cpe(NGINX).has_version is False


def test_the_2_2_uri_form_is_read_as_the_same_product() -> None:
    legacy = parse_cpe("cpe:/a:f5:nginx:1.18.0")
    assert legacy.product_key == ("f5", "nginx")
    assert legacy.version == "1.18.0"


def test_an_escaped_colon_stays_inside_its_part() -> None:
    cpe = parse_cpe(r"cpe:2.3:a:vendor\:with\:colons:product:1.0:*:*:*:*:*:*:*")
    assert cpe.vendor == "vendor:with:colons"
    assert cpe.product == "product"


@pytest.mark.parametrize("value", ["", "nginx", "cpe:2.3:a:f5", "http://example.test"])
def test_a_non_cpe_string_is_refused(value: str) -> None:
    with pytest.raises(CpeError):
        parse_cpe(value)


@pytest.mark.parametrize(
    "left, right, expected",
    [
        ("1.0", "1.0", 0),
        ("1.24", "1.24.0", 0),
        ("1.24", "1.24.1", -1),
        ("1.20.0", "1.20.1", -1),
        ("2.15.0", "2.4.49", 1),
        ("5.3.17", "5.3.18", -1),
        ("1.0a", "1.0", 1),
        ("1.0-rc1", "1.0", -1),
    ],
)
def test_versions_order_like_the_ranges_nvd_publishes(left: str, right: str, expected: int) -> None:
    assert compare_versions(left, right) == expected
    assert compare_versions(right, left) == -expected


def test_an_empty_version_is_refused() -> None:
    with pytest.raises(CpeError):
        parse_version("  ")


def match(**bounds: object) -> CpeMatch:
    return CpeMatch.from_json({"criteria": NGINX, "vulnerable": True, **bounds})


def match_wildcard(criteria: str, **bounds: object) -> CpeMatch:
    return CpeMatch.from_json({"criteria": criteria, "vulnerable": True, **bounds})


def test_a_range_matches_inside_and_outside_its_bounds() -> None:
    criterion = match(version_start_including="0.6.18", version_end_excluding="1.20.1")
    assert criterion.matches(parse_cpe("cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"))
    assert criterion.matches(parse_cpe("cpe:2.3:a:f5:nginx:0.6.18:*:*:*:*:*:*:*"))
    assert not criterion.matches(parse_cpe("cpe:2.3:a:f5:nginx:1.20.1:*:*:*:*:*:*:*"))
    assert not criterion.matches(parse_cpe("cpe:2.3:a:f5:nginx:0.6.17:*:*:*:*:*:*:*"))
    assert criterion.range_text() == ">= 0.6.18, < 1.20.1"


def test_excluding_start_and_including_end_are_honoured() -> None:
    criterion = match(version_start_excluding="1.0", version_end_including="2.0")
    assert not criterion.matches(parse_cpe("cpe:2.3:a:f5:nginx:1.0:*:*:*:*:*:*:*"))
    assert criterion.matches(parse_cpe("cpe:2.3:a:f5:nginx:2.0:*:*:*:*:*:*:*"))
    assert not criterion.matches(parse_cpe("cpe:2.3:a:f5:nginx:2.0.1:*:*:*:*:*:*:*"))


def test_an_exact_criterion_requires_that_version() -> None:
    criterion = CpeMatch.from_json(
        {"criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", "vulnerable": True}
    )
    assert criterion.matches(parse_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"))
    assert not criterion.matches(parse_cpe("cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*"))
    assert criterion.exact is True
    assert criterion.range_text() is None


def test_another_product_or_no_version_never_matches() -> None:
    criterion = match(version_end_excluding="1.20.1")
    assert not criterion.matches(parse_cpe("cpe:2.3:a:apache:http_server:1.18.0:*:*:*:*:*:*:*"))
    assert not criterion.matches(parse_cpe("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"))
    assert not criterion.matches(parse_cpe(NGINX))


def test_a_wildcard_criterion_is_not_a_version_match() -> None:
    """`*` is CPE's "any" and `-` its "not applicable": NVD published no version to match.

    The trial of item 61 showed the cost of the old reading: `cpe:2.3:a:apache:http_server:-`
    matched every Apache version, which is where 11 of the 99 candidates on httpd 2.4.49 came from.
    """
    criterion = match()
    assert criterion.has_version_evidence is False
    assert not criterion.matches(parse_cpe("cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"))
    assert criterion.range_text() is None
    not_applicable = match_wildcard("cpe:2.3:a:f5:nginx:-:*:*:*:*:*:*:*")
    assert not_applicable.has_version_evidence is False
    assert not not_applicable.matches(parse_cpe("cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"))
    # A wildcard product *with* a bound is a range and still matches.
    bounded = match(version_end_excluding="1.20.1")
    assert bounded.has_version_evidence is True
    assert bounded.matches(parse_cpe("cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"))


def test_a_malformed_entry_is_refused() -> None:
    with pytest.raises(CpeError):
        CpeMatch.from_json({"vulnerable": True})
    with pytest.raises(CpeError):
        CpeMatch.from_json("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*")


def test_cpe_update_component_and_compiled_match_handle_openssh_versions() -> None:
    from aegis.m20_vuln.cpe import CompiledCpeMatch

    exact_89p1 = CpeMatch.from_json(
        {"criteria": "cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*", "vulnerable": True}
    )
    exact_93_base = CpeMatch.from_json(
        {"criteria": "cpe:2.3:a:openbsd:openssh:9.3:-:*:*:*:*:*:*", "vulnerable": True}
    )
    range_89_to_93 = CpeMatch.from_json(
        {
            "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
            "vulnerable": True,
            "version_start_including": "8.9",
            "version_end_excluding": "9.3",
        }
    )

    banner_89p1 = parse_cpe("cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*")
    split_89p1 = parse_cpe("cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*")
    banner_93p1 = parse_cpe("cpe:2.3:a:openbsd:openssh:9.3p1:*:*:*:*:*:*:*")
    base_93 = parse_cpe("cpe:2.3:a:openbsd:openssh:9.3:*:*:*:*:*:*:*")

    for criterion in (exact_89p1, exact_93_base, range_89_to_93):
        compiled = CompiledCpeMatch.compile(criterion)
        for target in (banner_89p1, split_89p1, banner_93p1, base_93):
            parsed_ver = parse_version(target.effective_version)
            assert compiled.matches_parsed(target, parsed_ver) == criterion.matches(target)

    assert exact_89p1.matches(banner_89p1)
    assert exact_89p1.matches(split_89p1)
    assert not exact_93_base.matches(banner_93p1)
    assert exact_93_base.matches(base_93)
    assert range_89_to_93.matches(banner_89p1)
    assert not range_89_to_93.matches(banner_93p1)
