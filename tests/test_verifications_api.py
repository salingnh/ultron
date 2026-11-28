"""M26 verification routes: what the UI may ask, what it gets back, and what it cannot choose.

The route is deliberately thin (the work is M05/M21), and this suite pins the three contract facts:

* the request body is only `check_id` + `expected_seq` - the OpenAPI operation, the enum and the
  idempotency header are the contract's, and the job M05 receives already carries the *derived*
  input (target, controls, pack hash, cap), so no target or URL ever comes from the caller;
* the checks list is the intersection of the registry, the deployment's approvals and the campaign's
  signed profile, with the reason a check is unavailable (a lab-only check on an internet campaign);
* a run page is `verification-run.v2` items, newest first, keyset-paged.

The job service is a fake here: the real M05 path is covered end-to-end in
`tests/test_verification_layers.py`; this suite is about the HTTP surface.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient

from aegis import validation
from aegis.common.repo import repository_root
from aegis.m05_registry.service import SubmitOutcome
from aegis.m26_api.app import API_PREFIX, create_app
from aegis.m26_api.jobs import install_job_service
from aegis.m26_api.operator import TokenAuthenticator
from aegis.m26_api.registry import RouterRegistry
from aegis.m26_api.verifications import register
from tests import campaign_support as support
from tests import db_support
from tests.test_verification_layers import (
    APPROVED,
    POSITIVE,
    TWIN,
    _campaign,
    _derived,
    _seed_job,
    _uuid7,
)

pytestmark = db_support.requires_postgres

REPO = repository_root()
LAB_APPROVALS = str(REPO / "deploy/lab/verify-approvals.json")


class FakeJobService:
    """Records submitted jobs; replays the same key + same body the way M05 does."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.answers: dict[str, SubmitOutcome] = {}

    def submit(
        self,
        request: Any,
        *,
        requested_by: dict[str, str],
        idempotency_key: str,
        proposed_by: dict[str, str] | None = None,
        trace_id: str | None = None,
    ) -> SubmitOutcome:
        del proposed_by, trace_id
        body = request.model_dump(mode="json", exclude_none=True)
        stored = self.answers.get(idempotency_key)
        if stored is not None:
            return SubmitOutcome(job=stored.job, replayed=True, decision_id=stored.decision_id)
        job = {
            "job_id": str(_uuid7()),
            "campaign_id": body["campaign_id"],
            "capability": body["capability"],
            "provider": body["provider"],
            "status": "QUEUED",
            "attempt": 1,
            "generation": 1,
            "job_fingerprint": "a" * 64,
            "policy_version": "roe-15",
            "scope_id": str(_uuid7()),
            "requested_by": requested_by,
            "created_at": "2026-11-28T00:00:00Z",
            "priority": body.get("priority", 50),
            "adapter_version": "1.0.0",
            "depends_on": [],
        }
        outcome = SubmitOutcome(job=job, replayed=False, decision_id=str(_uuid7()))
        self.answers[idempotency_key] = SubmitOutcome(
            job=job, replayed=True, decision_id=outcome.decision_id
        )
        self.calls.append({"body": body, "key": idempotency_key})
        return outcome

    # the read model used by GET /jobs is not needed here; these keep the protocol quiet
    def get_job(self, job_id: str) -> dict[str, Any]:  # pragma: no cover
        raise AssertionError(job_id)

    def list_jobs(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover
        raise AssertionError("list_jobs")

    def cancel(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover
        raise AssertionError("cancel")


@pytest.fixture()
def database() -> Iterator[dict[str, Any]]:
    with db_support.migrated_database() as dsn:
        seeded, ids = _campaign(dsn)
        yield {
            "dsn": dsn,
            "campaign": seeded,
            "ids": ids,
            "finding": _finding_id(dsn),
            "input": _derived(dsn, seeded),
        }


def _finding_id(dsn: str) -> str:
    with psycopg.connect(dsn, row_factory=psycopg.rows.dict_row) as conn:
        row = conn.execute("SELECT finding_id FROM finding LIMIT 1").fetchone()
    assert row is not None
    return str(row["finding_id"])


def _client(
    dsn: str, monkeypatch: pytest.MonkeyPatch, approvals: str | None = LAB_APPROVALS
) -> tuple[TestClient, FakeJobService]:
    if approvals is None:
        monkeypatch.delenv("AEGIS_VERIFY_APPROVALS", raising=False)
    else:
        monkeypatch.setenv("AEGIS_VERIFY_APPROVALS", approvals)
    service = FakeJobService()
    registry = RouterRegistry()
    register(registry)
    app = create_app(
        registry,
        operator_authenticator=TokenAuthenticator(support.operator_tokens()),
        database_dsn=dsn,
    )
    install_job_service(app, service)  # type: ignore[arg-type]
    return TestClient(app), service


def _get(client: TestClient, path: str, **params: Any) -> Any:
    return client.get(f"{API_PREFIX}{path}", params=params, headers=support.auth())


def _post(client: TestClient, path: str, body: Any, key: str = "verification-key-1") -> Any:
    return client.post(
        f"{API_PREFIX}{path}", json=body, headers={**support.auth(), "Idempotency-Key": key}
    )


def test_the_checks_list_is_the_registry_and_the_approvals(
    database: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _ = _client(database["dsn"], monkeypatch)
    response = _get(client, f"/findings/{database['finding']}/verification-checks")
    assert response.status_code == 200, response.text
    items = response.json()["items"]
    assert [item["check_id"] for item in items] == [APPROVED]
    assert items[0]["available"] is True
    assert items[0]["class"] == "L1" and items[0]["lab_only"] is True


def test_a_check_without_approval_is_listed_with_its_reason(
    database: dict[str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    approvals = tmp_path / "approvals.json"
    approvals.write_text(json.dumps({"lab": [], "internet": []}))
    client, _ = _client(database["dsn"], monkeypatch, str(approvals))
    items = _get(client, f"/findings/{database['finding']}/verification-checks").json()["items"]
    assert items[0]["available"] is False
    assert "not approved" in items[0]["unavailable_reason"]


def test_a_request_derives_the_job_input_and_queues_it(
    database: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, service = _client(database["dsn"], monkeypatch)
    response = _post(
        client,
        f"/findings/{database['finding']}/verifications",
        {"check_id": APPROVED, "expected_seq": 1},
    )
    assert response.status_code == 202, response.text
    job = response.json()
    assert job["capability"] == "verify.check"
    assert job["provider"] == "nuclei-verify"
    assert len(service.calls) == 1
    body = service.calls[0]["body"]
    assert body["input"] == database["input"]
    assert body["input"]["targets"] == [POSITIVE, TWIN]
    assert body["input"]["benign_path"].startswith("/static/")
    assert body["priority"] == 60


def test_the_same_key_and_body_replays_the_job(
    database: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, service = _client(database["dsn"], monkeypatch)
    body = {"check_id": APPROVED, "expected_seq": 1}
    first = _post(client, f"/findings/{database['finding']}/verifications", body)
    second = _post(client, f"/findings/{database['finding']}/verifications", body)
    assert first.status_code == 202 and second.status_code == 200
    assert second.headers.get("Idempotent-Replayed") == "true"
    assert second.json()["job_id"] == first.json()["job_id"]
    assert len(service.calls) == 1


def test_an_unapproved_check_is_a_policy_denial(
    database: dict[str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    approvals = tmp_path / "approvals.json"
    approvals.write_text(json.dumps({"lab": [], "internet": []}))
    client, service = _client(database["dsn"], monkeypatch, str(approvals))
    response = _post(
        client,
        f"/findings/{database['finding']}/verifications",
        {"check_id": APPROVED, "expected_seq": 1},
    )
    assert response.status_code == 403
    assert response.json()["code"] == "POLICY_DENIED"
    assert service.calls == []


def test_a_check_id_outside_the_enum_is_400(
    database: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, service = _client(database["dsn"], monkeypatch)
    response = _post(
        client,
        f"/findings/{database['finding']}/verifications",
        {"check_id": "cve-2222-0001-traversal", "expected_seq": 1},
    )
    assert response.status_code == 400
    assert response.json()["code"] == "INPUT_INVALID"
    assert service.calls == []


def test_a_stale_expected_seq_is_409(
    database: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, service = _client(database["dsn"], monkeypatch)
    response = _post(
        client,
        f"/findings/{database['finding']}/verifications",
        {"check_id": APPROVED, "expected_seq": 7},
    )
    assert response.status_code == 409
    assert response.json()["field"] == "/expected_seq"
    assert service.calls == []


def test_an_unknown_finding_is_404(
    database: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _ = _client(database["dsn"], monkeypatch)
    missing = str(_uuid7())
    assert (
        _post(
            client, f"/findings/{missing}/verifications", {"check_id": APPROVED, "expected_seq": 1}
        ).status_code
        == 404
    )
    assert _get(client, f"/findings/{missing}/verifications").status_code == 404


def _seed_run(database: dict[str, Any]) -> str:
    dsn = database["dsn"]
    finding = database["finding"]
    job = _seed_job_second(dsn, database["campaign"], database["ids"]["positive"])
    evidence = str(_uuid7())
    with psycopg.connect(dsn) as conn, conn.transaction():
        conn.execute(
            "INSERT INTO evidence (evidence_id, sha256, storage_uri, campaign_id, job_id,"
            " size_bytes, media_type, classification, source_tool, verified_at)"
            " VALUES (%s, %s, %s, %s, %s, 10, 'application/x-ndjson', 'INTERNAL',"
            " 'nuclei-verify', now())",
            (
                evidence,
                "a" * 64,
                f"s3://evidence/{database['campaign'].campaign_id}/{job}/{evidence}",
                database["campaign"].campaign_id,
                job,
            ),
        )
        run = str(_uuid7())
        conn.execute(
            "INSERT INTO verification_run (verification_id, finding_id, campaign_id, job_id,"
            " check_id, check_class, network_profile, check_pack_sha256, outcome, requests_sent,"
            " request_cap, target_ref, controls, canary_sha256, positive_evidence_id,"
            " control_a_evidence_id, control_b_evidence_id, matched, requested_by, transition_seq,"
            " started_at, finished_at)"
            " VALUES (%s, %s, %s, %s, %s, 'L1', 'lab', %s, 'VERIFIED', 4, 4, %s, %s, %s, %s,"
            " %s, %s, %s, %s, 2, now(), now())",
            (
                run,
                finding,
                database["campaign"].campaign_id,
                job,
                APPROVED,
                "b" * 64,
                json.dumps(
                    {
                        "asset_id": database["ids"]["positive"],
                        "canonical_key": POSITIVE,
                        "address": "10.114.60.31",
                        "port": 80,
                    }
                ),
                json.dumps(
                    [
                        {
                            "role": "patched_twin",
                            "address": "10.114.60.32",
                            "port": 80,
                            "asset_id": None,
                        }
                    ]
                ),
                "c" * 64,
                evidence,
                evidence,
                evidence,
                json.dumps(
                    {
                        "positive": True,
                        "control_a": False,
                        "control_b": False,
                        "discriminating": True,
                        "reason": "the pair read the canary",
                    }
                ),
                json.dumps({"kind": "operator", "id": "fixture"}),
            ),
        )
    return run


def _seed_job_second(dsn: str, campaign: Any, asset: str) -> str:
    with psycopg.connect(dsn) as conn:
        return _seed_job(conn, campaign, asset)


def test_a_run_page_is_the_contract_item(
    database: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _seed_run(database)
    client, _ = _client(database["dsn"], monkeypatch)
    response = _get(client, f"/findings/{database['finding']}/verifications")
    assert response.status_code == 200, response.text
    body = response.json()
    assert len(body["items"]) == 1
    item = body["items"][0]
    assert validation.problems("verification/verification-run.v2.schema.json", item) == []
    assert item["verification_id"] == run
    assert item["outcome"] == "VERIFIED"
    assert item["network_profile"] == "lab"
    assert item["evidence"]["positive"]
    assert item["canary"]["sha256"] == "c" * 64
    assert item["matched"]["positive"] is True
