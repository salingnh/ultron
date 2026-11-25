"""Feed parsers of M18 (G1.6 slice C): the real NVD/KEV/EPSS document shapes, no network.

Every parser is driven by a committed slice of the published feed (see `tests/fixtures/intel/`), so
a change in the feed's shape fails here instead of silently storing nothing. The content hash is
what makes "unchanged bytes are not a new revision" true, so it is asserted from the other side
too: the same record parsed twice has the same hash, a changed field has a different one.
"""

from __future__ import annotations

import json

import pytest

from aegis.m18_intel import feeds
from tests import g16c_support as fixtures


def test_nvd_slice_parses_every_cve_with_cvss_and_cpe_ranges() -> None:
    records = feeds.parse_nvd(json.loads(fixtures.NVD.read_text(encoding="utf-8")))
    assert [record.vulnerability_id for record in records] == [
        "CVE-2021-41773",
        "CVE-2021-23017",
        "CVE-2022-22965",
        # G1.6b detection-gap slice: the real CVE-2020-1938 (Ghostcat) record, needed because the
        # lab's Tomcat 9.0.30 is now identified and must match NVD's 9.0.0-<9.0.31 range.
        "CVE-2020-1938",
    ]
    apache = records[0]
    assert apache.cvss == {
        "version": "3.1",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "base_score": 9.8,
        "base_severity": "CRITICAL",
    }
    assert apache.affected == {
        "cpe_match": [
            {
                "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
                "vulnerable": True,
                "version_start_including": None,
                "version_start_excluding": None,
                "version_end_including": None,
                "version_end_excluding": None,
                "match_criteria_id": "9F1E4F4C-1111-4A00-8000-000000000001",
            }
        ]
    }
    assert apache.published_at is not None and apache.published_at.isoformat().startswith(
        "2021-10-05T14:15:10"
    )
    assert apache.withdrawn is False
    nginx = records[1]
    assert nginx.affected is not None
    match = nginx.affected["cpe_match"][0]
    assert match["version_start_including"] == "0.6.18"
    assert match["version_end_excluding"] == "1.20.1"
    # Two configurations of one CVE are flattened into one list, in document order.
    spring = records[2].affected
    assert spring is not None
    assert len(spring["cpe_match"]) == 2


def test_nvd_rejected_status_is_withdrawn() -> None:
    document = json.loads(fixtures.NVD.read_text(encoding="utf-8"))
    document["vulnerabilities"][0]["cve"]["vulnStatus"] = "Rejected"
    assert feeds.parse_nvd(document)[0].withdrawn is True


def test_kev_slice_is_a_boolean_catalogue_with_due_dates() -> None:
    records = feeds.parse_kev(json.loads(fixtures.KEV.read_text(encoding="utf-8")))
    assert [record.vulnerability_id for record in records] == [
        "CVE-2021-41773",
        "CVE-2022-22965",
        "CVE-2020-1938",
    ]
    log4j = records[0].kev
    assert log4j is not None
    assert log4j["due_date"] == "2021-11-17"
    assert log4j["catalog_version"] == "2026.11.24"
    assert log4j["required_action"].startswith("Apply updates")
    assert records[0].cvss is None and records[0].affected is None


def test_epss_csv_and_json_are_the_same_scores() -> None:
    csv_records = feeds.parse_epss(fixtures.EPSS.read_bytes(), score_date=fixtures.VERSION)
    assert [record.vulnerability_id for record in csv_records][:2] == [
        "CVE-2021-41773",
        "CVE-2021-23017",
    ]
    assert csv_records[0].epss == {
        "score": 0.97431,
        "percentile": 0.99971,
        "score_date": fixtures.VERSION,
    }
    payload = json.dumps(
        {
            "data": [
                {"cve": "CVE-2021-41773", "epss": "0.97431", "percentile": "0.99971"},
                {"cve": "CVE-2021-23017", "epss": 0.01342, "percentile": 0.612},
            ]
        }
    ).encode("utf-8")
    json_records = feeds.parse_epss(payload, score_date=fixtures.VERSION)
    assert [record.epss for record in json_records] == [
        csv_records[0].epss,
        csv_records[1].epss,
    ]


def test_content_hash_ignores_the_snapshot_and_tracks_the_revision() -> None:
    records = feeds.parse_nvd(json.loads(fixtures.NVD.read_text(encoding="utf-8")))
    again = feeds.parse_nvd(json.loads(fixtures.NVD.read_text(encoding="utf-8")))
    assert records[0].content_hash() == again[0].content_hash()
    document = json.loads(fixtures.NVD.read_text(encoding="utf-8"))
    document["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"][
        "baseScore"
    ] = 9.9
    changed = feeds.parse_nvd(document)
    assert changed[0].content_hash() != records[0].content_hash()


@pytest.mark.parametrize(
    "feed, payload",
    [
        ("nvd", {"vulnerabilities": [{"cve": {"id": "CVE-21-1"}}]}),
        ("nvd", {"vulnerabilities": [{"cve": {"id": "CVE-2021-41773", "configurations": {}}}]}),
        ("kev", {"vulnerabilities": [{"cveID": "not-a-cve"}]}),
    ],
)
def test_a_malformed_feed_is_refused(feed: str, payload: dict[str, object]) -> None:
    with pytest.raises(feeds.FeedError):
        feeds.parse(feed, json.dumps(payload).encode("utf-8"), version=fixtures.VERSION)


def test_epss_scores_outside_the_unit_interval_are_refused() -> None:
    with pytest.raises(feeds.FeedError):
        feeds.parse_epss("cve,epss,percentile\nCVE-2021-41773,1.4,0.9\n")


def test_the_snapshot_moment_comes_from_the_feed_when_it_publishes_one() -> None:
    fallback = fixtures.SNAPSHOT_AT
    kev = feeds.snapshot_at_from("kev", fixtures.KEV.read_bytes(), fallback=fallback)
    assert kev.isoformat() == "2026-11-24T00:00:00+00:00"
    # NVD's export carries no publication moment of its own: the caller's value is kept.
    assert feeds.snapshot_at_from("nvd", fixtures.NVD.read_bytes(), fallback=fallback) == fallback
    assert feeds.snapshot_at_from("epss", fixtures.EPSS.read_bytes(), fallback=fallback) == fallback
