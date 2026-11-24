"""REST endpoint of M27: `POST /api/v2/ingestion/results` (OpenAPI `ingestResult`).

The endpoint is served by M27, not M26 (contracts/api/openapi.v2.yaml, tag `ingestion`), and is
reachable with the internal service token (`X-Aegis-Service-Token`, `serviceToken` security
scheme). The token is verified server-side and compared in constant time; when no token is
configured the route fails closed (401) instead of accepting anonymous callers.

The service object is resolved per app (`app.state.ingestion`) so deployment wiring and tests can
replace it without touching the route; without one the route answers 503 rather than pretending to
ingest. Registering the router is explicit (`register(registry)`), like every other module.
"""

from __future__ import annotations

import hmac
import os
from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, Response

from aegis.contracts_gen.ingestion.ingest_receipt_v2_schema import IngestReceipt
from aegis.m26_api.app import API_PREFIX
from aegis.m26_api.registry import RouterRegistry
from aegis.m27_ingestion.errors import EnvelopeRejected, IdempotencyConflict

__all__ = [
    "PayloadIngestion",
    "ROUTER_PREFIX",
    "SERVICE_TOKEN_ENV",
    "SERVICE_TOKEN_HEADER",
    "register",
    "require_service_token",
    "router",
]

SERVICE_TOKEN_HEADER = "X-Aegis-Service-Token"
SERVICE_TOKEN_ENV = "AEGIS_SERVICE_TOKEN"
ROUTER_PREFIX = f"{API_PREFIX}/ingestion"

router = APIRouter(tags=["ingestion"])


@runtime_checkable
class PayloadIngestion(Protocol):
    """The part of `IngestionService` the HTTP route uses."""

    def submit_payload(self, payload: Mapping[str, Any]) -> IngestReceipt: ...


def _configured_token(request: Request) -> str | None:
    configured = getattr(request.app.state, "ingestion_service_token", None)
    if isinstance(configured, str) and configured:
        return configured
    environment = os.environ.get(SERVICE_TOKEN_ENV)
    return environment or None


def require_service_token(request: Request) -> None:
    """Verify the internal service token; fail closed when the token is not configured."""
    configured = _configured_token(request)
    if configured is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="service token is not configured; ingestion refuses anonymous callers",
        )
    provided = request.headers.get(SERVICE_TOKEN_HEADER)
    if provided is None or not hmac.compare_digest(provided, configured):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid service token"
        )


def _error(
    status_code: int,
    code: str,
    message: str,
    *,
    field: str | None = None,
    next_action: str = "FIX_INPUT",
) -> JSONResponse:
    payload: dict[str, Any] = {
        "code": code,
        "message": message[:2000],
        "next_action": next_action,
    }
    if field is not None:
        payload["field"] = field
    return JSONResponse(status_code=status_code, content=payload)


@router.post(
    "/results",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=IngestReceipt,
    operation_id="ingestResult",
    responses={
        400: {"description": "Envelope refused (dead-lettered); see Error.code and Error.field"},
        409: {"description": "IDEMPOTENCY_CONFLICT: same dedup_key, different content"},
    },
)
def ingest_result(
    payload: dict[str, Any],
    request: Request,
    _: None = Depends(require_service_token),
) -> Response:
    """Accept one ResultEnvelope; idempotent by dedup_key + payload_hash (C03)."""
    service = getattr(request.app.state, "ingestion", None)
    if not isinstance(service, PayloadIngestion):
        return _error(
            503,
            "INTERNAL_ERROR",
            "ingestion service is not configured",
            next_action="RETRY_LATER",
        )
    try:
        receipt = service.submit_payload(payload)
    except IdempotencyConflict as conflict:
        return _error(
            409,
            "IDEMPOTENCY_CONFLICT",
            f"dedup_key {conflict.dedup_key!r} already committed different content"
            f" ({conflict.reason}); the committed result is unchanged",
        )
    except EnvelopeRejected as rejected:
        return _error(
            status.HTTP_400_BAD_REQUEST,
            rejected.code,
            rejected.message,
            field=rejected.field,
            next_action=rejected.next_action,
        )
    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED, content=receipt.model_dump(mode="json")
    )


def register(registry: RouterRegistry) -> None:
    """Mount the ingestion router under its own prefix (one prefix per registered module)."""
    registry.register("ingestion", router, prefix=ROUTER_PREFIX)
