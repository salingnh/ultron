"""M26 asset graph REST (card G1.4b): `getAssetGraph` and `getAssetHistory`.

Contract: `contracts/api/openapi.v2.yaml` operations `getAssetGraph` and `getAssetHistory`, plus the
output schema of `contracts/mcp/graph-queries.v2.schema.json#/$defs/get_asset_neighbors` (the REST
graph endpoint returns exactly that document — "Dùng chung cho Web UI qua REST") and the inline
`Asset` component of the OpenAPI document.

Deliberate choices:

* `GET /assets` stays `deferred` in the contract (`x-aegis-status: deferred`, "asset/cursor query
  not locked"), so this module does **not** implement it: an endpoint the contract forbids writing
  code against is not a gap to fill here.
* These two operations document only `200` in the contract; a malformed id/parameter and an unknown
  asset still answer the contract's `error.v2` (`400 INPUT_INVALID`, `404`), because a UI cannot
  render a missing asset as an empty graph. That deviation is reported, not hidden.
* The graph endpoint is read-only and operator-authenticated like every other operator call; the
  contract lists `security` only on the campaign/job operations, so the guard here follows the
  general convention in the OpenAPI description ("Người vận hành xác thực bằng bearer token riêng
  của mình"), not a per-operation entry.
* Output is validated with `aegis.validation` before it leaves the process, so a projector/query
  change that breaks the wire shape fails loudly instead of shipping.
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime
from typing import Annotated, Any

import psycopg
from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi import status as http_status

from aegis import validation
from aegis.m23_graph import queries
from aegis.m26_api.app import API_PREFIX
from aegis.m26_api.db import connection as db_connection
from aegis.m26_api.errors import INPUT_INVALID, ApiError
from aegis.m26_api.operator import Principal, require_principal
from aegis.m26_api.registry import RouterEntry, RouterRegistry
from aegis.m26_api.tracing import TRACEPARENT_HEADER, current_trace_id, traceparent

__all__ = [
    "ASSET_OPERATIONS",
    "ID_REFERENCE",
    "NEIGHBORS_OUTPUT",
    "decode_cursor",
    "encode_cursor",
    "register",
    "router",
]

ID_REFERENCE = "common/ids.v2.schema.json#/$defs/Id"
NEIGHBORS_OUTPUT = "mcp/graph-queries.v2.schema.json#/$defs/get_asset_neighbors/properties/output"

#: Operations this router implements; the conformance test compares it with the contract.
ASSET_OPERATIONS = ("getAssetGraph", "getAssetHistory")

_ERROR_400 = {"description": "Lỗi chuẩn (error.v2): tham số sai"}
_ERROR_401 = {"description": "Lỗi chuẩn (error.v2): thiếu hoặc sai operator token"}
_ERROR_404 = {"description": "Lỗi chuẩn (error.v2): tài sản không tồn tại"}

router = APIRouter(tags=["graph"])

ALIAS_LIMIT = 50


def _is_id(value: str) -> bool:
    return not validation.errors(ID_REFERENCE, value)


def _trace(request: Request, response: Response) -> str:
    trace_id = current_trace_id(request)
    response.headers[TRACEPARENT_HEADER] = traceparent(trace_id)
    return trace_id


def _bad_request(message: str, field: str) -> ApiError:
    return ApiError(
        http_status.HTTP_400_BAD_REQUEST,
        INPUT_INVALID,
        message,
        next_action="FIX_INPUT",
        field=field,
    )


def _not_found(asset_id: str) -> ApiError:
    return ApiError(
        http_status.HTTP_404_NOT_FOUND,
        INPUT_INVALID,
        f"asset {asset_id} does not exist",
        next_action="FIX_INPUT",
    )


def encode_cursor(observed_at: datetime, observation_id: str) -> str:
    """Opaque keyset cursor of `(observed_at, observation_id)`, newest first."""
    raw = f"{queries.iso_z(observed_at)}|{observation_id}"
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, str]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        observed_at_text, separator, observation_id = raw.partition("|")
        if not separator:
            raise ValueError("cursor has no separator")
        observed_at = datetime.fromisoformat(observed_at_text.replace("Z", "+00:00"))
    except (ValueError, UnicodeError, binascii.Error) as error:
        raise _bad_request("cursor is not one this endpoint issued", "/cursor") from error
    if not _is_id(observation_id):
        raise _bad_request("cursor does not carry an observation id", "/cursor")
    return observed_at, observation_id


def _driver(request: Request) -> Any:
    driver = getattr(request.app.state, "graph_driver", None)
    if driver is None:
        raise RuntimeError(
            "the app has no graph driver: build it with create_app(graph_driver=...) or set "
            "AEGIS_NEO4J_PASSWORD for create_production_app()"
        )
    return driver


def _asset_row(db: psycopg.Connection[Any], asset_id: str) -> dict[str, Any] | None:
    row = db.execute(
        "SELECT asset_id, canonical_key, kind, owner, exposure, criticality, first_seen, last_seen"
        "  FROM asset WHERE asset_id = %s",
        (asset_id,),
    ).fetchone()
    return None if row is None else dict(row)


def _asset_view(db: psycopg.Connection[Any], row: dict[str, Any]) -> dict[str, Any]:
    """The OpenAPI `Asset` component: the PG row plus aliases and the provenance keys."""
    asset_id = str(row["asset_id"])
    aliases = db.execute(
        "SELECT namespace, alias_value FROM asset_alias WHERE asset_id = %s"
        " ORDER BY observed_at DESC LIMIT %s",
        (asset_id, ALIAS_LIMIT),
    ).fetchall()
    origins = db.execute(
        "SELECT DISTINCT a.canonical_key FROM asset_provenance p"
        "  JOIN asset a ON a.asset_id = p.from_asset_id"
        " WHERE p.asset_id = %s",
        (asset_id,),
    ).fetchall()
    return {
        "asset_id": asset_id,
        "canonical_key": row["canonical_key"],
        "kind": row["kind"],
        "owner": row["owner"],
        "exposure": row["exposure"],
        "criticality": row["criticality"],
        "first_seen": queries.iso_z(row["first_seen"]),
        "last_seen": queries.iso_z(row["last_seen"]),
        "aliases": [
            {"namespace": alias["namespace"], "value": alias["alias_value"]} for alias in aliases
        ],
        "discovered_from": sorted(str(origin["canonical_key"]) for origin in origins),
    }


@router.get(
    "/assets/{asset_id}/graph",
    operation_id="getAssetGraph",
    summary="Vùng lân cận có giới hạn (cùng truy vấn get_asset_neighbors của agent)",
    responses={400: _ERROR_400, 401: _ERROR_401, 404: _ERROR_404},
)
def get_asset_graph(
    request: Request,
    response: Response,
    asset_id: str,
    campaign_id: Annotated[str, Query(alias="campaign_id")],
    principal: Annotated[Principal, Depends(require_principal)],
    db: Annotated[psycopg.Connection[Any], Depends(db_connection)],
    max_hops: Annotated[int, Query(ge=1, le=2)] = 1,
    as_of: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> dict[str, Any]:
    _trace(request, response)
    if not _is_id(campaign_id):
        raise _bad_request("campaign_id is not a valid id", "/campaign_id")
    if not _is_id(asset_id):
        raise _not_found(asset_id)
    if as_of is not None:
        try:
            datetime.fromisoformat(as_of.replace("Z", "+00:00"))
        except ValueError as error:
            raise _bad_request("as_of is not an RFC 3339 timestamp", "/as_of") from error
    row = _asset_row(db, asset_id)
    if row is None:
        raise _not_found(asset_id)
    result = queries.get_asset_neighbors(
        _driver(request),
        campaign_id=campaign_id,
        canonical_key=str(row["canonical_key"]),
        limit=limit,
        max_hops=max_hops,
        as_of=as_of,
    )
    try:
        validation.validate(NEIGHBORS_OUTPUT, result)
    except validation.ContractViolation as error:
        raise ApiError(
            http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            f"graph read model violates {NEIGHBORS_OUTPUT}: {error}",
        ) from error
    return result


@router.get(
    "/assets/{asset_id}/history",
    operation_id="getAssetHistory",
    summary="Dòng thời gian tài sản theo từng lần chạy (observation gắn scan_id)",
    responses={400: _ERROR_400, 401: _ERROR_401, 404: _ERROR_404},
)
def get_asset_history(
    request: Request,
    response: Response,
    asset_id: str,
    principal: Annotated[Principal, Depends(require_principal)],
    db: Annotated[psycopg.Connection[Any], Depends(db_connection)],
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> dict[str, Any]:
    _trace(request, response)
    if not _is_id(asset_id):
        raise _not_found(asset_id)
    row = _asset_row(db, asset_id)
    if row is None:
        raise _not_found(asset_id)
    after = decode_cursor(cursor) if cursor else None
    rows = db.execute(
        "SELECT o.observation_id, o.scan_id, j.capability, j.provider, o.observed_at,"
        "       o.predicate, o.value, o.polarity, o.evidence_ids"
        "  FROM observation o JOIN scan_job j ON j.job_id = o.scan_id"
        " WHERE o.subject_asset_id = %s"
        "   AND (%s::timestamptz IS NULL OR (o.observed_at, o.observation_id)"
        "        < (%s::timestamptz, %s::uuid))"
        " ORDER BY o.observed_at DESC, o.observation_id DESC LIMIT %s",
        (
            asset_id,
            after[0] if after else None,
            after[0] if after else None,
            after[1] if after else None,
            limit + 1,
        ),
    ).fetchall()
    page = rows[:limit]
    items: list[dict[str, Any]] = []
    for observation in page:
        item: dict[str, Any] = {
            "scan_id": str(observation["scan_id"]),
            "capability": observation["capability"],
            "provider": observation["provider"],
            "observed_at": queries.iso_z(observation["observed_at"]),
            "predicate": observation["predicate"],
            "polarity": observation["polarity"],
        }
        if observation["value"] is not None:
            item["value"] = observation["value"]
        evidence = list(observation["evidence_ids"] or ())
        if evidence:
            item["evidence_ids"] = [str(evidence_id) for evidence_id in evidence]
        items.append(item)
    body: dict[str, Any] = {"asset": _asset_view(db, row), "items": items}
    if len(rows) > limit and page:
        body["next_cursor"] = encode_cursor(
            page[-1]["observed_at"], str(page[-1]["observation_id"])
        )
    return body


def register(registry: RouterRegistry, *, prefix: str = API_PREFIX) -> RouterEntry:
    """Mount the asset graph router on an app registry (called by the app entrypoint)."""
    return registry.register("assets", router, prefix=prefix)
