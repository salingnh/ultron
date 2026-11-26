"""M26 read API of candidate vulnerabilities (G1.6 slice C): `listAssetVulnerabilities`.

Contract: `contracts/api/openapi.v2.yaml` operation `listAssetVulnerabilities` (path
`/assets/{asset_id}/vulnerabilities`, `security: operatorToken`, `401`, `404`) and the inline
`VulnerabilityCandidate` component.

The candidates are M20's `package_vuln_match` rows, one per `(asset, vulnerability)` - the newest
decision, because the table is append-only. A newest decision can be a retraction (`matched =
false`, migration 0008: the intel changed and the CPE no longer matches), which is why the query
filters `latest.matched`: the same rule the graph read model applies (`m23_graph/queries.py`), so
the API and the graph never disagree about whether a pair is a candidate. CVSS/KEV/EPSS are read
from `vulnerability_current` per source, so the API never shows a value the graph or the catalogue
do not have. Nothing here raises a candidate to a finding: an operator reading "candidate + KEV"
still has to verify.
"""

from __future__ import annotations

import base64
import binascii
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi import status as http_status

from aegis import validation
from aegis.m20_vuln.matching import (
    TARGET_PREDICATES,
    VERSION_UNKNOWN_CODE,
    VERSION_UNKNOWN_MESSAGE,
    inspect_product_observations,
)
from aegis.m23_graph import queries
from aegis.m26_api.app import API_PREFIX
from aegis.m26_api.assets import _asset_row
from aegis.m26_api.db import ConnectionDep
from aegis.m26_api.errors import INPUT_INVALID, ApiError
from aegis.m26_api.operator import Principal, require_principal
from aegis.m26_api.registry import RouterEntry, RouterRegistry
from aegis.m26_api.tracing import TRACEPARENT_HEADER, current_trace_id, traceparent

__all__ = [
    "VULNERABILITY_OPERATIONS",
    "decode_cursor",
    "encode_cursor",
    "register",
    "router",
]

CONTRACT_PATH = "/assets/{asset_id}/vulnerabilities"
RESPONSE_SCHEMA = "vulnerability/asset-vulnerabilities.v2.schema.json"
#: Operations this router implements; the tests compare it with the contract.
VULNERABILITY_OPERATIONS = ("listAssetVulnerabilities",)

_ERROR_400 = {"description": "Lỗi chuẩn (error.v2): tham số sai"}
_ERROR_401 = {"description": "Lỗi chuẩn (error.v2): thiếu hoặc sai operator token"}
_ERROR_404 = {"description": "Lỗi chuẩn (error.v2): tài sản không tồn tại"}

router = APIRouter(tags=["graph"])

QUERY = (
    "WITH latest AS ("
    "  SELECT DISTINCT ON (m.vulnerability_id)"
    "         m.match_id, m.vulnerability_id, m.match_method, m.affected_range, m.confidence,"
    "         m.snapshot_id, m.campaign_id, m.matched, m.created_at"
    "    FROM package_vuln_match m"
    "   WHERE m.package_asset_id = %s"
    "     AND (%s::uuid IS NULL OR m.campaign_id = %s::uuid)"
    "     AND (%s::text IS NULL OR m.vulnerability_id > %s::text)"
    "   ORDER BY m.vulnerability_id, m.created_at DESC, m.match_id DESC"
    ")"
    " SELECT latest.*,"
    "        nvd.cvss AS nvd_cvss, k.kev AS kev_json, e.epss AS epss_json"
    "   FROM latest"
    "   LEFT JOIN vulnerability_current nvd"
    "     ON nvd.vulnerability_id = latest.vulnerability_id AND nvd.source = 'nvd'"
    "    AND NOT nvd.withdrawn"
    "   LEFT JOIN vulnerability_current k"
    "     ON k.vulnerability_id = latest.vulnerability_id AND k.source = 'kev'"
    "    AND NOT k.withdrawn"
    "   LEFT JOIN vulnerability_current e"
    "     ON e.vulnerability_id = latest.vulnerability_id AND e.source = 'epss'"
    "    AND NOT e.withdrawn"
    "  WHERE latest.matched"
    "    AND (%s::boolean = FALSE OR k.kev IS NOT NULL)"
    "  ORDER BY latest.vulnerability_id"
    "  LIMIT %s"
)


def _is_id(value: str) -> bool:
    return not validation.errors("common/ids.v2.schema.json#/$defs/Id", value)


def _trace(request: Request, response: Response) -> None:
    response.headers[TRACEPARENT_HEADER] = traceparent(current_trace_id(request))


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


def encode_cursor(vulnerability_id: str) -> str:
    raw = f"cve|{vulnerability_id}"
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")


def decode_cursor(cursor: str) -> str:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        marker, separator, vulnerability_id = raw.partition("|")
        if marker != "cve" or not separator or not vulnerability_id:
            raise ValueError("not a vulnerability cursor")
    except (ValueError, UnicodeError, binascii.Error) as error:
        raise _bad_request("cursor is not one this endpoint issued", "/cursor") from error
    return vulnerability_id


def _json(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _number(value: object) -> float | None:
    return float(value) if isinstance(value, (int, float)) else None


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _item(row: dict[str, Any]) -> dict[str, Any]:
    cvss = _json(row["nvd_cvss"])
    kev = _json(row["kev_json"])
    epss = _json(row["epss_json"])
    item: dict[str, Any] = {
        "vulnerability_id": str(row["vulnerability_id"]),
        "kev": bool(kev),
        "match_method": str(row["match_method"]),
        "confidence": float(row["confidence"] if row["confidence"] is not None else 0.0),
        "candidate_since": queries.iso_z(row["created_at"]),
    }
    for field, value in (
        ("cvss_base", _number(cvss.get("base_score"))),
        ("cvss_severity", _text(cvss.get("base_severity"))),
        ("kev_due_date", _text(kev.get("due_date"))),
        ("epss", _number(epss.get("score"))),
        ("affected_range", _text(row["affected_range"])),
        ("snapshot_id", None if row["snapshot_id"] is None else str(row["snapshot_id"])),
    ):
        if value is not None:
            item[field] = value
    return item


@router.get(
    CONTRACT_PATH,
    operation_id="listAssetVulnerabilities",
    summary="Ứng viên CVE của một tài sản (cạnh AFFECTED_BY), kèm KEV/EPSS",
    responses={400: _ERROR_400, 401: _ERROR_401, 404: _ERROR_404},
)
def list_asset_vulnerabilities(
    request: Request,
    response: Response,
    asset_id: str,
    principal: Annotated[Principal, Depends(require_principal)],
    db: ConnectionDep,
    campaign_id: Annotated[str | None, Query()] = None,
    kev_only: Annotated[bool, Query()] = False,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> dict[str, Any]:
    _trace(request, response)
    if not _is_id(asset_id):
        raise _not_found(asset_id)
    if campaign_id is not None and not _is_id(campaign_id):
        raise _bad_request("campaign_id is not a valid id", "/campaign_id")
    row = _asset_row(db, asset_id)
    if row is None:
        raise _not_found(asset_id)
    after = decode_cursor(cursor) if cursor else None
    rows = db.execute(
        QUERY,
        (asset_id, campaign_id, campaign_id, after, after, kev_only, limit + 1),
    ).fetchall()
    page = rows[:limit]
    body: dict[str, Any] = {
        "asset": {
            "asset_id": str(row["asset_id"]),
            "canonical_key": row["canonical_key"],
            "kind": row["kind"],
        },
        "items": [_item(dict(item)) for item in page],
        "coverage": _asset_coverage(db, asset_id, campaign_id, bool(page)),
    }
    if len(rows) > limit and page:
        body["next_cursor"] = encode_cursor(str(page[-1]["vulnerability_id"]))
    return _validated(body)


def _asset_coverage(
    db: ConnectionDep,
    asset_id: str,
    campaign_id: str | None,
    has_candidates: bool,
) -> dict[str, Any]:
    obs_rows = db.execute(
        "SELECT DISTINCT ON (predicate) predicate, value"
        "  FROM observation"
        " WHERE subject_asset_id = %s"
        "   AND polarity = 'present'"
        "   AND predicate = ANY(%s)"
        "   AND (%s::uuid IS NULL OR campaign_id = %s::uuid)"
        " ORDER BY predicate, observed_at DESC, ingested_at DESC",
        (asset_id, list(TARGET_PREDICATES), campaign_id, campaign_id),
    ).fetchall()
    inspection = inspect_product_observations(
        [(str(obs["predicate"]), obs["value"]) for obs in obs_rows]
    )
    limitations: list[dict[str, Any]] = []
    if inspection.versionless_products:
        limitations.append(
            {
                "code": VERSION_UNKNOWN_CODE,
                "message": VERSION_UNKNOWN_MESSAGE,
                "products": list(inspection.versionless_products[:100]),
            }
        )
    return {
        "matchable": bool(inspection.cpes) or has_candidates,
        "limitations": limitations,
    }


def _validated(document: dict[str, Any]) -> dict[str, Any]:
    """A page that does not satisfy the published schema is a bug, not a 200."""
    problems = validation.problems(RESPONSE_SCHEMA, document)
    if problems:
        pointer, message = problems[0]
        raise ApiError(
            http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            f"asset vulnerabilities violate {RESPONSE_SCHEMA} at {pointer or '/'}: {message[:300]}",
        )
    return document


def register(registry: RouterRegistry, *, prefix: str = API_PREFIX) -> RouterEntry:
    """Mount the candidate-vulnerability router on an app registry."""
    return registry.register("vulnerabilities", router, prefix=prefix)
