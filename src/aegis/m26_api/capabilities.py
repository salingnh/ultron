"""`/api/v2/capabilities` - the admitted M05 provider catalogue (card G1.5a, follow-up).

The tool catalogue screen asks the registry one question: which capabilities can this deployment run
right now, with which providers, and what does the campaign's RoE forbid? The answer is the M05
registry itself (`aegis.provider_manifest`, 0016) and nothing else:

* one item per **capability**; `providers` are the manifests M05 would resolve a new job to - the
  most recently admitted manifest per `(capability, provider)` (`PostgresManifestRegistry.all()` is
  ordered by `registered_at`, and `resolve()` picks the newest, so an older adapter version of the
  same provider is history, not a second provider);
* every record is re-derived from its stored bytes on read (`PostgresManifestRegistry`, 0016's
  `manifest_sha256 = sha256(manifest_utf8)` CHECK), so a listed provider is exactly a manifest whose
  pins agree with its document - a disagreement is a loud error, never a silent entry;
* `campaign_id` (optional) filters by the campaign's **current** RoE `capability_denylist`; an
  unknown or malformed campaign id is 404, because a catalogue filtered by a campaign that does not
  exist would be a lie.

`health` is `healthy` for every listed provider: the registry only serves manifests it can re-admit
from their stored bytes, i.e. what a new job resolves. A container/adapter probe (and therefore
`degraded`/`unavailable`) is M06/M02 work; inventing a probe result here would be worse than saying
nothing (see the G1.5a report, proposal).

Contract: `contracts/api/openapi.v2.yaml` -> `listCapabilities` (`security: operatorToken`, `401`,
`404`, `campaign_id`). The response is validated against the contract's inline schema per request
(500 rather than an invalid 200), like `getCampaignFlow`.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Annotated, Any

import psycopg
from fastapi import APIRouter, Depends, Query, Request, Response

from aegis import validation
from aegis.m05_registry.manifest import ManifestRecord
from aegis.m05_registry.registry import ManifestRegistry, PostgresManifestRegistry
from aegis.m26_api.db import ConnectionDep, database_dsn_of
from aegis.m26_api.errors import INPUT_INVALID, ApiError
from aegis.m26_api.operator import Principal, require_principal
from aegis.m26_api.registry import RouterRegistry
from aegis.m26_api.tracing import TRACEPARENT_HEADER, current_trace_id, traceparent

__all__ = ["CAPABILITIES_OPERATIONS", "catalogue", "register", "router"]

#: Operations this router implements; the conformance test compares it with the contract.
CAPABILITIES_OPERATIONS = ("listCapabilities",)

API_PREFIX = "/api/v2"
ID_REFERENCE = "common/ids.v2.schema.json#/$defs/Id"
ERROR_401 = {"description": "Lỗi chuẩn (error.v2): thiếu hoặc sai operator token"}
ERROR_404 = {"description": "Lỗi chuẩn (error.v2): campaign không tồn tại"}

HEALTHY = "healthy"

router = APIRouter(tags=["jobs"])


# --------------------------------------------------------------------------- helpers


def _is_id(value: str) -> bool:
    return not validation.errors(ID_REFERENCE, value)


def _trace(request: Request, response: Response) -> str:
    trace_id = current_trace_id(request)
    response.headers[TRACEPARENT_HEADER] = traceparent(trace_id)
    return trace_id


def _not_found(campaign_id: str) -> ApiError:
    return ApiError(
        404,
        INPUT_INVALID,
        f"campaign {campaign_id} does not exist",
        next_action="FIX_INPUT",
    )


def _validated(document: dict[str, Any]) -> dict[str, Any]:
    """A catalogue that does not satisfy the published schema is a bug, not a 200."""
    validator = validation.openapi_response_validator("/capabilities")
    problems = sorted(validator.iter_errors(document), key=str)
    if problems:
        first = problems[0]
        pointer = "/" + "/".join(str(part) for part in first.absolute_path)
        raise ApiError(
            500,
            "INTERNAL_ERROR",
            f"capability catalogue violates listCapabilities at {pointer or '/'}: "
            f"{first.message[:300]}",
        )
    return document


def _module(record: ManifestRecord) -> str | None:
    metadata = record.document.get("metadata")
    if not isinstance(metadata, dict):
        return None
    module = metadata.get("module")
    return None if module is None else str(module)


def catalogue(
    records: Iterable[ManifestRecord], *, denied: frozenset[str] = frozenset()
) -> list[dict[str, Any]]:
    """One item per capability, providers newest-first-per-name, denied capabilities removed."""
    latest: dict[tuple[str, str], ManifestRecord] = {}
    for record in records:  # `all()` is registered_at ASC, so the last write wins per key
        latest[(record.capability, record.provider)] = record

    items: dict[str, dict[str, Any]] = {}
    for (capability, _provider), record in latest.items():
        if capability in denied:
            continue
        item = items.setdefault(
            capability,
            {
                "capability": capability,
                "input_schema_ref": record.input_schema_ref,
                "providers": [],
            },
        )
        item["input_schema_ref"] = record.input_schema_ref
        provider: dict[str, Any] = {
            "name": record.provider,
            "version": record.provider_version,
            "health": HEALTHY,
        }
        module = _module(record)
        if module is not None:
            provider["module"] = module
        item["providers"].append(provider)

    for item in items.values():
        item["providers"].sort(key=lambda provider: provider["name"])
    return [items[capability] for capability in sorted(items)]


def get_manifest_registry(request: Request) -> ManifestRegistry:
    """The M05 registry over the app's database (the same table a job submission resolves)."""
    dsn = database_dsn_of(request)
    return PostgresManifestRegistry(lambda: psycopg.connect(dsn))


def _denylist(connection: psycopg.Connection[Any], campaign_id: str) -> frozenset[str] | None:
    """The campaign's current `capability_denylist`, or None when the campaign does not exist."""
    row = connection.execute(
        """
        SELECT p.policy -> 'capability_denylist' AS denylist
          FROM aegis.campaign c
          JOIN aegis.policy_snapshot p ON p.policy_version = c.current_policy_version
         WHERE c.campaign_id = %s
        """,
        (campaign_id,),
    ).fetchone()
    if row is None:
        return None
    value = row["denylist"]
    return frozenset(str(entry) for entry in (value or []))


# --------------------------------------------------------------------------- routes


@router.get(
    "/capabilities",
    operation_id="listCapabilities",
    summary="Danh sách capability và provider (Registry M05)",
    responses={401: ERROR_401, 404: ERROR_404},
)
def list_capabilities(
    request: Request,
    response: Response,
    principal: Annotated[Principal, Depends(require_principal)],
    registry: Annotated[ManifestRegistry, Depends(get_manifest_registry)],
    db: ConnectionDep,
    campaign_id: Annotated[str | None, Query()] = None,
) -> dict[str, Any]:
    """Admitted capabilities with their current providers, filtered by a campaign's RoE."""
    _trace(request, response)
    denied: frozenset[str] = frozenset()
    if campaign_id is not None:
        observed = _denylist(db, campaign_id) if _is_id(campaign_id) else None
        if observed is None:
            raise _not_found(campaign_id)
        denied = observed
    return _validated({"items": catalogue(registry.all(), denied=denied)})


def register(registry: RouterRegistry, *, prefix: str = "") -> Any:
    """Mount the capabilities router on the app registry (called by `main.build_registry`)."""
    return registry.register("capabilities", router, prefix=prefix or API_PREFIX)
