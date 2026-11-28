"""`/api/v2/intel/status` - is the intel this deployment matches against still fresh?

The daily refresh (`aegis.m02_orchestrator.intel`) records every attempt in `intel_sync_run`
(migration 0009), and M18's `intel_snapshot` says what is loaded. This endpoint is the operator's
one read of both: the newest snapshot per feed with its age, whether it is stale, and the last
attempt (running, succeeded or failed, with the failing leg's error). It never triggers a sync and
never writes.

A feed is stale when its newest **fetched** snapshot is older than the feed's bound
(`aegis.m18_intel.runs.STALE_AFTER_SECONDS`); a feed with no snapshot is stale and says so with
`snapshot: null`. `stale_feeds` is never empty-by-omission: every feed `sync-intel` refreshes is in
`feeds`, so a broken schedule is visible as a growing age, not as a missing row.

Contract: `contracts/api/openapi.v2.yaml` -> `getIntelStatus` (`security: operatorToken`, `401`).
The response is validated against the contract's inline schema per request (500 rather than an
invalid 200), like the capability catalogue.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request, Response

from aegis import validation
from aegis.m18_intel import runs
from aegis.m26_api.db import ConnectionDep
from aegis.m26_api.errors import ApiError
from aegis.m26_api.operator import Principal, require_principal
from aegis.m26_api.registry import RouterRegistry
from aegis.m26_api.tracing import TRACEPARENT_HEADER, current_trace_id, traceparent

__all__ = ["INTEL_OPERATIONS", "get_intel_status", "register", "router"]

#: Operations this router implements; the conformance test compares it with the contract.
INTEL_OPERATIONS = ("getIntelStatus",)

API_PREFIX = "/api/v2"
ERROR_401 = {"description": "Lỗi chuẩn (error.v2): thiếu hoặc sai operator token"}

router = APIRouter(tags=["intel"])


def _trace(request: Request, response: Response) -> str:
    trace_id = current_trace_id(request)
    response.headers[TRACEPARENT_HEADER] = traceparent(trace_id)
    return trace_id


def _validated(document: dict[str, Any]) -> dict[str, Any]:
    """A status document that does not satisfy the published schema is a bug, not a 200."""
    validator = validation.openapi_response_validator("/intel/status")
    problems = sorted(validator.iter_errors(document), key=str)
    if problems:
        first = problems[0]
        pointer = "/" + "/".join(str(part) for part in first.absolute_path)
        raise ApiError(
            500,
            "INTERNAL_ERROR",
            f"intel status violates getIntelStatus at {pointer or '/'}: {first.message[:300]}",
        )
    return document


@router.get(
    "/intel/status",
    operation_id="getIntelStatus",
    summary="Độ tươi của intel và lần đồng bộ gần nhất (NVD/EPSS/KEV)",
    responses={401: ERROR_401},
)
def get_intel_status(
    request: Request,
    response: Response,
    principal: Annotated[Principal, Depends(require_principal)],
    db: ConnectionDep,
) -> dict[str, Any]:
    """Newest snapshot per feed, its age and staleness, and the last refresh attempt."""
    _trace(request, response)
    return _validated(runs.feed_status(db))


def register(registry: RouterRegistry, *, prefix: str = "") -> Any:
    """Mount the intel router on the app registry (called by `main.build_registry`)."""
    return registry.register("intel", router, prefix=prefix or API_PREFIX)
