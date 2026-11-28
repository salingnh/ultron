"""G2-D: scanner candidates -> one finding with N provider sources (M20).

The acceptance this suite proves, on a throwaway PostgreSQL:

* the same package+CVE reported by Trivy, Grype and a third provider is **one** finding with three
  `finding_source` rows and three `finding_run` rows (the plan's "3 providers, 1 finding");
* a replay of the same scan adds no finding, run, source, transition or event;
* the producer never decides more than CANDIDATE and never FIXED from absence;
* an operator's FALSE_POSITIVE is not reopened by a re-run, while a re-report after FIXED is
  REGRESSED;
* every raised finding is assessed (C07), and without a model the record is UNRATED with its reason.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any, cast

import psycopg
from psycopg.rows import dict_row

from aegis.m20_vuln.candidates import CandidateFindingsEngine
from aegis.m20_vuln.findings import finding_fingerprint
from aegis.m27_ingestion.service import IngestionService
from aegis.migrations import apply_contract_migrations
from tests.pg import requires_postgres, throwaway_database
from tests.support_ingestion import (
    CAMPAIGN_ID,
    FINISHED_AT,
    SEED_ASSET_KEY,
    asset,
    build_envelope,
    observation,
    seed_campaign,
    seed_evidence,
    seed_job,
)

PKG_KEY = "purl:pkg:apk/alpine/krb5-libs@1.22.2-r1"
PURL = "pkg:apk/alpine/krb5-libs@1.22.2-r1"
CVE = "cve:CVE-2026-107364"
LATER = "2026-11-26T10:00:00Z"


def _migrate(dsn: str) -> None:
    with psycopg.connect(dsn, autocommit=True) as connection:
        apply_contract_migrations(connection)


def _connect(dsn: str) -> psycopg.Connection[tuple[object, ...]]:
    connection: psycopg.Connection[tuple[object, ...]] = psycopg.connect(dsn, autocommit=True)
    connection.execute("SET search_path = aegis, public")
    return connection


def _dict(dsn: str) -> psycopg.Connection[dict[str, Any]]:
    """The M20 producer's connection shape: autocommit and dict rows (`matching.connect`)."""
    connection: psycopg.Connection[dict[str, Any]] = psycopg.connect(
        dsn, autocommit=True, row_factory=dict_row
    )
    connection.execute("SET search_path = aegis, public")
    return connection


def _job(connection: psycopg.Connection[Any], key: str, provider: str) -> str:
    return seed_job(
        connection,
        key,
        capability="vuln.scan_artifact",
        provider=provider,
        provider_version="v0.76.2",
    )


def _evidence(
    connection: psycopg.Connection[Any], job_id: str, provider: str
) -> tuple[dict[str, Any], str]:
    blob = f"{provider} raw report\n".encode()
    digest = hashlib.sha256(blob).hexdigest()
    seed_evidence(connection, job_id, sha256=digest, size_bytes=len(blob))
    return (
        {
            "local_ref": "raw",
            "sha256": digest,
            "uri": f"s3://evidence/{CAMPAIGN_ID}/{job_id}/{digest}",
            "size_bytes": len(blob),
            "media_type": "application/json",
            "classification": "INTERNAL",
            "kind": "raw_output",
        },
        digest,
    )


def _envelope(
    job_id: str,
    provider: str,
    evidence: dict[str, Any],
    *,
    finished_at: str = "2026-11-24T10:00:00Z",
    rule_id: str = CVE,
    fixed_version: str = "1.22.3-r0",
) -> dict[str, Any]:
    value: dict[str, Any] = build_envelope(
        job_id,
        assets=[asset(PKG_KEY, "package", discovered_from=[SEED_ASSET_KEY])],
        observations=[
            observation(
                PKG_KEY,
                "package.installed",
                {"version": "1.22.2-r1", "ecosystem": "apk"},
                evidence_refs=[{"local_ref": "raw"}],
            )
        ],
        findings=[
            {
                "subject": PKG_KEY,
                "rule_id": rule_id,
                "category": "vulnerability",
                "title": f"{rule_id} in krb5-libs",
                "location": {
                    "package_purl": PURL,
                    "installed_version": "1.22.2-r1",
                    "fixed_version": fixed_version,
                },
                "vulnerability_ids": [rule_id.split(":", 1)[1]],
                "scanner_severity": "high",
                "fingerprint_context": {"package": "pkg:apk/alpine/krb5-libs"},
                "confidence": 0.9,
                "evidence_refs": [{"local_ref": "raw"}],
            }
        ],
        coverage=[PKG_KEY],
        evidence=[evidence],
        provider_name=provider,
        provider_version="v0.76.2",
        capability="vuln.scan_artifact",
    )
    value["provenance"]["finished_at"] = finished_at
    return value


def _three_providers(dsn: str) -> tuple[dict[str, str], dict[str, dict[str, Any]]]:
    """One campaign, three scans (trivy, grype, osv) reporting the same package+CVE."""
    service = IngestionService.from_dsn(dsn)
    jobs: dict[str, str] = {}
    evidences: dict[str, dict[str, Any]] = {}
    with _connect(dsn) as connection:
        seed_campaign(connection)
        for provider in ("trivy", "grype", "osv"):
            job_id = _job(connection, f"g2d:{provider}", provider)
            evidence, _digest = _evidence(connection, job_id, provider)
            jobs[provider] = job_id
            evidences[provider] = evidence
            service.submit_payload(_envelope(job_id, provider, evidence))
    return jobs, evidences


@requires_postgres
def test_three_providers_make_one_finding_with_three_sources() -> None:
    with throwaway_database() as dsn:
        _migrate(dsn)
        jobs, evidences = _three_providers(dsn)
        with _connect(dsn) as connection:
            assert _count(connection, "SELECT count(*) FROM finding_candidate") == 3
            assert _count(connection, "SELECT count(*) FROM finding") == 0

            with _dict(dsn) as engine:
                report = CandidateFindingsEngine(engine).run(campaign_id=CAMPAIGN_ID)
            assert (report.groups, report.findings_created) == (1, 1)
            assert (report.runs, report.sources) == (3, 3)
            assert (report.transitions, report.events) == (1, 1)
            assert report.assessments == 1 and report.unrated == 1

            row = cast(
                tuple[Any, ...],
                connection.execute(
                    "SELECT finding_id, fingerprint, asset_id, rule_id, category, title, location,"
                    " match_method, status, severity, confidence, first_seen, last_seen,"
                    " first_job_id, first_campaign_id, vulnerability_ids FROM finding"
                ).fetchone(),
            )
            (
                finding_id,
                fingerprint,
                asset_id,
                rule_id,
                category,
                title,
                location,
                match_method,
                status,
                severity,
                confidence,
                first_seen,
                last_seen,
                first_job_id,
                first_campaign_id,
                vulnerability_ids,
            ) = row
            assert (rule_id, category, match_method, status, severity) == (
                CVE,
                "vulnerability",
                "scanner_direct",
                "CANDIDATE",
                "UNRATED",
            )
            assert str(title).startswith(CVE)
            assert location == {"package_purl": PURL}
            assert str(fingerprint) == finding_fingerprint(
                str(asset_id), CVE, {"package_purl": PURL}
            )
            assert vulnerability_ids == ["CVE-2026-107364"]
            assert float(cast(float, confidence)) == 0.9
            assert str(first_campaign_id) == CAMPAIGN_ID

            providers = {
                str(item[0])
                for item in connection.execute(
                    "SELECT provider FROM finding_source WHERE finding_id = %s", (finding_id,)
                ).fetchall()
            }
            assert providers == {"trivy", "grype", "osv"}
            assert (
                cast(
                    tuple[Any, ...],
                    connection.execute(
                        "SELECT count(*) FROM finding_run WHERE finding_id = %s", (finding_id,)
                    ).fetchone(),
                )[0]
                == 3
            )
            transition = cast(
                tuple[Any, ...],
                connection.execute(
                    "SELECT seq, from_status, to_status, cause, actor, evidence_id"
                    " FROM finding_transition WHERE finding_id = %s",
                    (finding_id,),
                ).fetchone(),
            )
            assert transition[0] == 1 and transition[1] is None and transition[2] == "CANDIDATE"
            assert transition[3] == "scan" and transition[5] is not None
            assert transition[4] == {"kind": "module", "id": "M20"}
            events = connection.execute(
                "SELECT payload FROM outbox_event WHERE type = 'finding.changed.v2'"
            ).fetchall()
            assert len(events) == 1
            event_payload = cast(dict[str, Any], events[0][0])
            assert event_payload["new_status"] == "CANDIDATE"
            assert event_payload["finding_id"] == str(finding_id)

            assessment = cast(
                tuple[Any, ...],
                connection.execute(
                    "SELECT severity, kind, assessment FROM severity_assessment"
                ).fetchone(),
            )
            assert assessment[0] == "UNRATED" and assessment[1] == "rule"
            failure = cast(dict[str, Any], assessment[2]).get("failure") or {}
            assert failure.get("code") == "DEPENDENCY_MISSING"

            # A re-run of the same evidence buys nothing: no row, no event, no assessment.
            with _dict(dsn) as engine:
                again = CandidateFindingsEngine(engine).run(campaign_id=CAMPAIGN_ID)
            assert (again.findings_created, again.runs, again.sources) == (0, 0, 0)
            assert (again.transitions, again.events) == (0, 0)
            # The queue is `severity.assess_pending` (G2-C): nothing is pending at the same input
            # revision, so a retry does not assess again.
            assert (again.assessments, again.assessments_created) == (0, 0)
            assert _count(connection, "SELECT count(*) FROM finding") == 1

            # Re-submitting a stored envelope (same dedup key) is a duplicate receipt, not data.
            service = IngestionService.from_dsn(dsn)
            replay = service.submit_payload(_envelope(jobs["trivy"], "trivy", evidences["trivy"]))
            assert replay.duplicate is True
            assert _count(connection, "SELECT count(*) FROM finding_candidate") == 3


@requires_postgres
def test_an_operator_decision_is_not_reopened_by_a_new_scan() -> None:
    with throwaway_database() as dsn:
        _migrate(dsn)
        _three_providers(dsn)
        with _connect(dsn) as connection:
            with _dict(dsn) as engine:
                CandidateFindingsEngine(engine).run(campaign_id=CAMPAIGN_ID, assess=False)
            finding_id = str(
                cast(
                    tuple[Any, ...],
                    connection.execute("SELECT finding_id FROM finding").fetchone(),
                )[0]
            )
            connection.execute(
                "UPDATE finding SET status = 'FALSE_POSITIVE', transition_seq = 2"
                " WHERE finding_id = %s",
                (finding_id,),
            )
            connection.execute(
                "INSERT INTO finding_transition (finding_id, seq, from_status, to_status, reason,"
                " actor, cause) VALUES (%s, 2, 'CANDIDATE', 'FALSE_POSITIVE', 'operator says so',"
                " %s, 'operator')",
                (finding_id, json.dumps({"kind": "operator", "id": "op-local"})),
            )
            job_id = _job(connection, "g2d:after-fp", "trivy")
            evidence, _digest = _evidence(connection, job_id, "trivy")
        service = IngestionService.from_dsn(dsn)
        service.submit_payload(_envelope(job_id, "trivy", evidence))
        with _connect(dsn) as connection:
            with _dict(dsn) as engine:
                report = CandidateFindingsEngine(engine).run(campaign_id=CAMPAIGN_ID, assess=False)
            assert report.suppressed == 1
            assert report.transitions == 0
            status = cast(
                tuple[Any, ...],
                connection.execute(
                    "SELECT status, transition_seq FROM finding WHERE finding_id = %s",
                    (finding_id,),
                ).fetchone(),
            )
            assert status == ("FALSE_POSITIVE", 2)
            # The scan is still recorded as a covering run/source: no data is lost, only no reopen.
            assert report.sources == 1


@requires_postgres
def test_a_report_after_fixed_is_a_regression_not_a_silent_ignore() -> None:
    with throwaway_database() as dsn:
        _migrate(dsn)
        _three_providers(dsn)
        with _connect(dsn) as connection:
            with _dict(dsn) as engine:
                CandidateFindingsEngine(engine).run(campaign_id=CAMPAIGN_ID, assess=False)
            finding_id = str(
                cast(
                    tuple[Any, ...],
                    connection.execute("SELECT finding_id FROM finding").fetchone(),
                )[0]
            )
            evidence_id = cast(
                tuple[Any, ...],
                connection.execute(
                    "SELECT evidence_id FROM finding_run WHERE finding_id = %s"
                    " ORDER BY observed_at LIMIT 1",
                    (finding_id,),
                ).fetchone(),
            )[0]
            connection.execute(
                "UPDATE finding SET status = 'FIXED', transition_seq = 2 WHERE finding_id = %s",
                (finding_id,),
            )
            connection.execute(
                "INSERT INTO finding_transition (finding_id, seq, from_status, to_status, reason,"
                " evidence_id, actor, cause) VALUES (%s, 2, 'CANDIDATE', 'FIXED',"
                " 'new image outside the affected range', %s, %s, 'scan')",
                (finding_id, evidence_id, json.dumps({"kind": "module", "id": "M21"})),
            )
            job_id = _job(connection, "g2d:regression", "trivy")
            evidence, _digest = _evidence(connection, job_id, "trivy")
        service = IngestionService.from_dsn(dsn)
        service.submit_payload(_envelope(job_id, "trivy", evidence, finished_at=LATER))
        with _connect(dsn) as connection:
            with _dict(dsn) as engine:
                report = CandidateFindingsEngine(engine).run(campaign_id=CAMPAIGN_ID, assess=False)
            assert report.reappeared == 1
            assert report.transitions == 1
            row = cast(
                tuple[Any, ...],
                connection.execute(
                    "SELECT status, transition_seq FROM finding WHERE finding_id = %s",
                    (finding_id,),
                ).fetchone(),
            )
            assert row == ("REGRESSED", 3)
            last = cast(
                tuple[Any, ...],
                connection.execute(
                    "SELECT from_status, to_status, cause FROM finding_transition"
                    " WHERE finding_id = %s ORDER BY seq DESC LIMIT 1",
                    (finding_id,),
                ).fetchone(),
            )
            assert last == ("FIXED", "REGRESSED", "scan")


@requires_postgres
def test_a_second_rule_is_a_second_finding_and_dry_run_writes_nothing() -> None:
    with throwaway_database() as dsn:
        _migrate(dsn)
        with _connect(dsn) as connection:
            seed_campaign(connection)
            for index, rule in enumerate((CVE, "cve:CVE-2020-0002")):
                job_id = _job(connection, f"g2d:rule{index}", "trivy")
                evidence, _digest = _evidence(connection, job_id, "trivy")
                IngestionService.from_dsn(dsn).submit_payload(
                    _envelope(job_id, "trivy", evidence, rule_id=rule)
                )
        with _connect(dsn) as connection:
            with _dict(dsn) as engine:
                dry = CandidateFindingsEngine(engine).run(campaign_id=CAMPAIGN_ID, dry_run=True)
            assert (dry.groups, dry.findings_created) == (2, 0)
            assert _count(connection, "SELECT count(*) FROM finding") == 0
            with _dict(dsn) as engine:
                report = CandidateFindingsEngine(engine).run(campaign_id=CAMPAIGN_ID, assess=False)
            assert (report.groups, report.findings_created) == (2, 2)
            assert _count(connection, "SELECT count(*) FROM finding") == 2


def _count(connection: psycopg.Connection[Any], sql: str) -> int:
    row = connection.execute(sql).fetchone()
    assert row is not None
    return int(row[0])


ROOT = Path(__file__).resolve().parents[1]
IMAGE_KEY = "oci:sha256:a61cbd76a882645de7f91423329fe43a67eed60d7da24f9e5331414bb3618b20"
SHARED_PURL = "purl:pkg:apk/alpine/krb5-libs@1.22.2-r1"
SHARED_CVE = "cve:CVE-2026-107364"
TRIVY_RAW = ROOT / "contracts/tests/conformance/fixtures/trivy/raw/result.json"
GRYPE_RAW = ROOT / "contracts/tests/conformance/fixtures/grype/raw/result.json"


def _image_asset(connection: psycopg.Connection[Any], image_key: str) -> str:
    """M01 creates the image seed asset with the campaign; the test creates the same rows."""
    connection.execute(
        "INSERT INTO asset (asset_id, canonical_key, kind, first_seen, last_seen,"
        " normalization_version) VALUES (%s, %s, 'oci_image', now(), now(), 'aegis-norm/1')",
        (str(uuid.uuid4()), image_key),
    )
    asset_id = str(
        cast(
            tuple[Any, ...],
            connection.execute(
                "SELECT asset_id FROM asset WHERE canonical_key = %s", (image_key,)
            ).fetchone(),
        )[0]
    )
    connection.execute(
        "INSERT INTO asset_campaign (asset_id, campaign_id, first_seen) VALUES (%s, %s, now())",
        (asset_id, CAMPAIGN_ID),
    )
    return asset_id


def _parsed_envelope(
    connection: psycopg.Connection[Any],
    dsn: str,
    job_id: str,
    provider: str,
    version: str,
    raw: Path,
    parsed: dict[str, Any],
) -> dict[str, Any]:
    blob = raw.read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    seed_evidence(connection, job_id, sha256=digest, size_bytes=len(blob))
    entry = {
        "local_ref": "raw",
        "sha256": digest,
        "uri": f"s3://evidence/{CAMPAIGN_ID}/{job_id}/{digest}",
        "size_bytes": len(blob),
        "media_type": "application/json",
        "classification": "INTERNAL",
        "kind": "raw_output",
    }
    # M06 stamps observation/relationship time; a parser never reads a clock.
    observations = [{**item, "observed_at": FINISHED_AT} for item in parsed["observations"]]
    relationships = [{**item, "observed_at": FINISHED_AT} for item in parsed["relationships"]]
    return build_envelope(
        job_id,
        assets=parsed["assets"],
        observations=observations,
        relationships=relationships,
        findings=parsed["findings"],
        coverage=parsed["coverage_subjects"],
        evidence=[entry],
        provider_name=provider,
        provider_version=version,
        capability="vuln.scan_artifact",
    )


@requires_postgres
def test_the_real_trivy_and_grype_reports_merge_into_one_finding() -> None:
    """G2-D acceptance: two *real* providers on one image -> one finding with two sources.

    The conformance raw files are one run each on the same digest-pinned image. Parsed by the real
    adapters and ingested through M27, the candidate engine groups the same package+CVE: the
    fingerprint is provider-independent and `finding_source` keeps one row per tool.
    """
    from adapters.m13.grype.parser import parse as parse_grype
    from adapters.m13.trivy.parser import parse as parse_trivy

    with throwaway_database() as dsn:
        _migrate(dsn)
        service = IngestionService.from_dsn(dsn)
        with _connect(dsn) as connection:
            seed_campaign(connection)
            _image_asset(connection, IMAGE_KEY)
            jobs = {
                provider: seed_job(
                    connection,
                    f"g2d-real:{provider}",
                    capability="vuln.scan_artifact",
                    provider=provider,
                    provider_version=version,
                )
                for provider, version in (("trivy", "v0.76.2"), ("grype", "v0.121.3"))
            }
            trivy = parse_trivy(
                TRIVY_RAW.parent,
                {"input": {"targets": [IMAGE_KEY]}, "provider_version": "v0.76.2"},
                [{"local_ref": "raw"}],
            )
            grype = parse_grype(
                GRYPE_RAW.parent,
                {"input": {"targets": [IMAGE_KEY]}, "provider_version": "v0.121.3"},
                [{"local_ref": "raw"}],
            )
            for provider, version, raw, parsed in (
                ("trivy", "v0.76.2", TRIVY_RAW, trivy),
                ("grype", "v0.121.3", GRYPE_RAW, grype),
            ):
                service.submit_payload(
                    _parsed_envelope(
                        connection, dsn, jobs[provider], provider, version, raw, parsed
                    )
                )

        with _dict(dsn) as engine:
            report = CandidateFindingsEngine(engine).run(campaign_id=CAMPAIGN_ID, assess=False)
        assert report.findings_created > 0

        with _connect(dsn) as connection:
            row = cast(
                tuple[Any, ...],
                connection.execute(
                    "SELECT finding_id, fingerprint, asset_id FROM finding"
                    " WHERE asset_id = (SELECT asset_id FROM asset WHERE canonical_key = %s)"
                    "   AND rule_id = %s",
                    (SHARED_PURL, SHARED_CVE),
                ).fetchone(),
            )
            finding_id, fingerprint, asset_id = row
            assert str(fingerprint) == finding_fingerprint(
                str(asset_id), SHARED_CVE, {"package_purl": SHARED_PURL[5:]}
            )
            providers = {
                str(item[0])
                for item in connection.execute(
                    "SELECT provider FROM finding_source WHERE finding_id = %s", (finding_id,)
                ).fetchall()
            }
            assert providers == {"trivy", "grype"}
            runs = cast(
                tuple[Any, ...],
                connection.execute(
                    "SELECT count(*) FROM finding_run WHERE finding_id = %s", (finding_id,)
                ).fetchone(),
            )[0]
            assert runs == 2
