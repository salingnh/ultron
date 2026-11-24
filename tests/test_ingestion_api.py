"""`POST /api/v2/ingestion/results`: service-token gate, 202 receipt and typed failures."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest
from fastapi.testclient import TestClient

from aegis import validation
from aegis.contracts_gen.ingestion.ingest_receipt_v2_schema import IngestReceipt
from aegis.m26_api.app import API_PREFIX, create_app
from aegis.m26_api.registry import RouterRegistry
from aegis.m27_ingestion.errors import EnvelopeRejected, IdempotencyConflict
from aegis.m27_ingestion.router import (
    ROUTER_PREFIX,
    SERVICE_TOKEN_ENV,
    SERVICE_TOKEN_HEADER,
    register,
)

TOKEN = "s3cret-service-token"
PATH = f"{API_PREFIX}/ingestion/results"
RECEIPT_PAYLOAD: dict[str, Any] = {
    "event_id": "01900000-0000-7000-8000-00000000d001",
    "dedup_key": "job:01900000-0000-7000-8000-00000000d002:envelope",
    "accepted": True,
    "duplicate": False,
    "revision": 7,
    "quarantined": [{"pointer": "/results/assets/0", "gate": "G1", "reason": "invalid_ip"}],
    "payload_hash": "a" * 64,
    "hash_version": "aegis-c14n/1",
    "decided_at": "2026-11-24T10:00:00Z",
}


class _Service:
    def __init__(self) -> None:
        self.receipt = IngestReceipt.model_validate(RECEIPT_PAYLOAD)
        self.payloads: list[Mapping[str, Any]] = []

    def submit_payload(self, payload: Mapping[str, Any]) -> IngestReceipt:
        mode = payload.get("mode")
        if mode == "conflict":
            raise IdempotencyConflict(RECEIPT_PAYLOAD["dedup_key"], "b" * 64, "hash_mismatch")
        if mode == "reject":
            raise EnvelopeRejected("INPUT_INVALID", "job does not exist", field="/job_id")
        self.payloads.append(payload)
        return self.receipt


def _client(*, service: object | None = None, token: str | None = TOKEN) -> TestClient:
    registry = RouterRegistry()
    register(registry)
    app = create_app(registry)
    app.state.ingestion_service_token = token
    if service is not None:
        app.state.ingestion = service
    return TestClient(app)


def _headers(token: str = TOKEN) -> dict[str, str]:
    return {SERVICE_TOKEN_HEADER: token}


def test_router_is_registered_under_the_ingestion_prefix() -> None:
    registry = RouterRegistry()
    register(registry)
    entry = registry.entries[0]
    assert (entry.name, entry.prefix) == ("ingestion", ROUTER_PREFIX)
    app = create_app(registry)
    assert PATH in app.openapi()["paths"]
    assert app.openapi()["paths"][PATH]["post"]["operationId"] == "ingestResult"


def test_accepted_envelope_returns_the_contract_receipt() -> None:
    service = _Service()
    response = _client(service=service).post(PATH, json={"anything": 1}, headers=_headers())
    assert response.status_code == 202
    body = response.json()
    assert body["duplicate"] is False
    validation.validate("ingestion/ingest-receipt.v2.schema.json", body)
    assert IngestReceipt.model_validate(body) == service.receipt
    assert service.payloads == [{"anything": 1}]


def test_the_service_token_is_required_and_checked() -> None:
    client = _client(service=_Service())
    assert client.post(PATH, json={}).status_code == 401
    assert client.post(PATH, json={}, headers=_headers("wrong")).status_code == 401
    # The header is the contract's security scheme, not a bearer token.
    assert (
        client.post(PATH, json={}, headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 401
    )


def test_the_token_can_come_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(SERVICE_TOKEN_ENV, TOKEN)
    client = _client(service=_Service(), token=None)
    assert client.post(PATH, json={}, headers=_headers()).status_code == 202


def test_an_unconfigured_token_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(SERVICE_TOKEN_ENV, raising=False)
    assert (
        _client(service=_Service(), token=None).post(PATH, json={}, headers=_headers()).status_code
        == 401
    )


def test_an_unwired_service_answers_503_not_a_fake_success() -> None:
    response = _client(service=None).post(PATH, json={}, headers=_headers())
    assert response.status_code == 503
    assert response.json()["code"] == "INTERNAL_ERROR"


def test_a_conflict_is_409_idempotency_conflict() -> None:
    response = _client(service=_Service()).post(PATH, json={"mode": "conflict"}, headers=_headers())
    assert response.status_code == 409
    validation.validate("common/error.v2.schema.json", response.json())
    assert response.json()["code"] == "IDEMPOTENCY_CONFLICT"
    assert response.json()["next_action"] == "FIX_INPUT"


def test_a_refused_envelope_is_400_with_the_field() -> None:
    response = _client(service=_Service()).post(PATH, json={"mode": "reject"}, headers=_headers())
    assert response.status_code == 400
    body = response.json()
    validation.validate("common/error.v2.schema.json", body)
    assert body["code"] == "INPUT_INVALID"
    assert body["field"] == "/job_id"


def test_a_non_object_body_is_refused() -> None:
    response = _client(service=_Service()).post(PATH, json=[1, 2], headers=_headers())
    assert response.status_code in {400, 422}
