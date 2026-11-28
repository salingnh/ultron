"""M26 report read model (G2 slice C): the JSON snapshot and the delta between two instants.

FR-019 asks for a JSON report at G2; SARIF/HTML and the triage workflow stay G4. The contract
publishes two read-only operations (`contracts/api/openapi.v2.yaml`, tag `reports`) and this module
answers them from rows that already exist - it never rescans, never calls a model and never writes:

* **snapshot** - every finding that existed at `as_of`, with the status it had then
  (`finding_transition` is append-only, so the highest `seq` not later than `as_of` is the answer),
  the severity record current then (`severity_assessment.created_at <= as_of`), and the evidence
  observed no later than `as_of` with its SHA-256. Findings are never deleted, so the snapshot is
  reproducible from the stored history;
* **delta** - two snapshots compared. Every finding lands in exactly one list (fixed, regressed,
  new, changed - in that precedence), so a window never reports the same finding twice, and the
  lists are the snapshot documents themselves (evidence hashes included), not a second query that
  could disagree with the snapshot;
* `assets` in a snapshot is the **exposure inventory**: assets with at least one open finding at
  that instant. `assets_new`/`assets_gone` are its set difference, which is the only meaning the
  schema can honestly give "gone" - PostgreSQL never deletes an asset, so a raw inventory diff
  would always be empty.

Both responses are validated against their contract before they leave the app: a producer bug is a
500, never a 200 with a shape the UI would render as truth.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

import psycopg
from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi import status as http_status

from aegis import validation
from aegis.m26_api.app import API_PREFIX
from aegis.m26_api.db import ConnectionDep
from aegis.m26_api.errors import INPUT_INVALID, ApiError
from aegis.m26_api.operator import Principal, require_principal
from aegis.m26_api.registry import RouterEntry, RouterRegistry
from aegis.m26_api.tracing import TRACEPARENT_HEADER, current_trace_id, traceparent

__all__ = [
    "DELTA_PATH",
    "REPORT_OPERATIONS",
    "SNAPSHOT_PATH",
    "delta_report",
    "register",
    "router",
    "snapshot_report",
]

SNAPSHOT_PATH = "/reports/snapshot"
DELTA_PATH = "/reports/delta"
#: Operations this router implements; the conformance test compares it with the contract.
REPORT_OPERATIONS = ("getSnapshotReport", "getDeltaReport")
#: Statuses that keep an asset in the exposure inventory (everything that still needs an answer).
OPEN_STATUSES = ("CANDIDATE", "CORROBORATED", "VERIFIED", "REGRESSED")
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNRATED")

_ERROR_400 = {"description": "Lỗi chuẩn (error.v2): tham số sai"}
_ERROR_401 = {"description": "Lỗi chuẩn (error.v2): thiếu hoặc sai operator token"}

router = APIRouter(tags=["reports"])

#: Every finding that existed at `as_of`, its status then and the severity record current then.
#: `DISTINCT ON ... ORDER BY seq DESC` is the append-only transition rule, not a timestamp race.
SNAPSHOT_QUERY = (
    "WITH scoped AS ("
    "    SELECT f.finding_id, f.fingerprint, f.asset_id, f.rule_id, f.category, f.title,"
    "           f.vulnerability_ids, f.location, f.match_method, f.confidence, f.first_seen,"
    "           f.last_seen, a.canonical_key AS asset_key, a.kind AS asset_kind,"
    "           a.owner, a.exposure, a.criticality"
    "      FROM finding f JOIN asset a ON a.asset_id = f.asset_id"
    "     WHERE (%(campaign)s::uuid IS NULL OR EXISTS ("
    "             SELECT 1 FROM asset_campaign ac"
    "              WHERE ac.asset_id = f.asset_id AND ac.campaign_id = %(campaign)s::uuid))"
    "), status_at AS ("
    "    SELECT DISTINCT ON (ft.finding_id) ft.finding_id, ft.to_status AS status"
    "      FROM finding_transition ft"
    "     WHERE ft.created_at <= %(as_of)s"
    "     ORDER BY ft.finding_id, ft.seq DESC"
    "), severity_at AS ("
    "    SELECT DISTINCT ON (sa.finding_id) sa.finding_id, sa.assessment_id, sa.severity,"
    "           sa.assessment"
    "      FROM severity_assessment sa"
    "     WHERE sa.created_at <= %(as_of)s"
    "     ORDER BY sa.finding_id, sa.created_at DESC, sa.assessment_id DESC"
    "), runs_at AS ("
    "    SELECT fr.finding_id, max(fr.observed_at) AS last_observed"
    "      FROM finding_run fr"
    "     WHERE fr.observed_at <= %(as_of)s"
    "     GROUP BY fr.finding_id"
    "), providers_at AS ("
    "    SELECT fs.finding_id, array_agg(DISTINCT fs.provider) AS providers"
    "      FROM finding_source fs"
    "     WHERE fs.observed_at <= %(as_of)s"
    "     GROUP BY fs.finding_id"
    ") "
    "SELECT s.*, st.status AS status_at, sv.assessment_id, sv.severity AS severity_at,"
    "       sv.assessment, ra.last_observed, pa.providers"
    "  FROM scoped s"
    "  JOIN status_at st ON st.finding_id = s.finding_id"
    "  LEFT JOIN severity_at sv ON sv.finding_id = s.finding_id"
    "  LEFT JOIN runs_at ra ON ra.finding_id = s.finding_id"
    "  LEFT JOIN providers_at pa ON pa.finding_id = s.finding_id"
    " ORDER BY s.finding_id"
)

EVIDENCE_QUERY = (
    "SELECT DISTINCT ON (fr.finding_id, e.evidence_id)"
    "       fr.finding_id, e.evidence_id, e.sha256, e.source_tool, e.media_type"
    "  FROM finding_run fr JOIN evidence e ON e.evidence_id = fr.evidence_id"
    " WHERE fr.evidence_id IS NOT NULL AND fr.observed_at <= %s"
    "   AND fr.finding_id = ANY(%s::uuid[])"
    " ORDER BY fr.finding_id, e.evidence_id, fr.observed_at DESC"
)


def _stamp(value: object) -> str:
    render = getattr(value, "isoformat", None)
    if callable(render):
        return str(render()).replace("+00:00", "Z")
    return str(value)


def _aware(name: str, value: datetime) -> datetime:
    """A query instant must carry its offset: a naive value would be read in the server's zone."""
    if value.tzinfo is None:
        raise ApiError(
            http_status.HTTP_400_BAD_REQUEST,
            INPUT_INVALID,
            f"{name} must carry a UTC offset (for example 2026-11-28T00:00:00Z)",
            next_action="FIX_INPUT",
            field=f"/{name}",
        )
    return value.astimezone(UTC)


def _evidence(
    db: psycopg.Connection[Any], finding_ids: list[str], as_of: datetime
) -> dict[str, list[dict[str, Any]]]:
    if not finding_ids:
        return {}
    rows = db.execute(EVIDENCE_QUERY, (as_of, finding_ids)).fetchall()
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row["finding_id"]), []).append(
            {
                "evidence_id": str(row["evidence_id"]),
                "sha256": str(row["sha256"]),
                "source_tool": str(row["source_tool"]),
                "media_type": str(row["media_type"]),
            }
        )
    return grouped


def _finding_item(row: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    item: dict[str, Any] = {
        "finding_id": str(row["finding_id"]),
        "fingerprint": str(row["fingerprint"]),
        "asset_id": str(row["asset_id"]),
        "asset_key": str(row["asset_key"]),
        "rule_id": str(row["rule_id"]),
        "category": str(row["category"]),
        "title": str(row["title"]),
        "vulnerability_ids": [str(value) for value in row["vulnerability_ids"] or ()],
        "location": dict(row["location"] or {}),
        "status": str(row["status_at"]),
        "severity": str(row["severity_at"] or "UNRATED"),
        "first_seen": _stamp(row["first_seen"]),
        "last_seen": _stamp(row["last_observed"] or row["first_seen"]),
        "evidence": evidence,
    }
    if row["assessment"] is not None:
        item["severity_assessment"] = dict(row["assessment"])
    if row["match_method"] is not None:
        item["match_method"] = str(row["match_method"])
    if row["confidence"] is not None:
        item["confidence"] = float(row["confidence"])
    providers = [str(value) for value in row["providers"] or ()]
    if providers:
        item["providers"] = providers
    return item


def _asset_item(row: dict[str, Any]) -> dict[str, Any]:
    item: dict[str, Any] = {
        "asset_id": str(row["asset_id"]),
        "canonical_key": str(row["asset_key"]),
        "kind": str(row["asset_kind"]),
        "first_seen": _stamp(row["first_seen"]),
        "last_seen": _stamp(row["last_observed"] or row["last_seen"]),
    }
    if row["owner"] is not None:
        item["owner"] = str(row["owner"])
    if row["exposure"] is not None:
        item["exposure"] = str(row["exposure"])
    if row["criticality"] is not None:
        item["criticality"] = str(row["criticality"])
    return item


def _ordered_findings(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rank = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}
    return sorted(
        items,
        key=lambda item: (
            rank.get(str(item["severity"]), len(rank)),
            str(item["asset_key"]),
            str(item["finding_id"]),
        ),
    )


def snapshot_report(
    db: psycopg.Connection[Any], *, as_of: datetime, campaign_id: str | None
) -> dict[str, Any]:
    """The report document at `as_of`; both operations read through this one function."""
    rows = [
        dict(row) for row in db.execute(SNAPSHOT_QUERY, {"as_of": as_of, "campaign": campaign_id})
    ]
    evidence = _evidence(db, [str(row["finding_id"]) for row in rows], as_of)
    findings = _ordered_findings(
        [_finding_item(row, evidence.get(str(row["finding_id"]), [])) for row in rows]
    )
    open_finding_assets = {
        str(row["asset_id"]) for row in rows if str(row["status_at"]) in OPEN_STATUSES
    }
    inventory = {
        str(row["asset_id"]): _asset_item(row)
        for row in rows
        if str(row["asset_id"]) in open_finding_assets
    }
    assets = sorted(inventory.values(), key=lambda item: str(item["canonical_key"]))
    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for item in findings:
        by_status[str(item["status"])] = by_status.get(str(item["status"]), 0) + 1
        by_severity[str(item["severity"])] = by_severity.get(str(item["severity"]), 0) + 1
    clock = db.execute("SELECT now() AS at").fetchone()
    if clock is None:  # pragma: no cover - PostgreSQL always answers now()
        raise ApiError(
            http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "the database clock is gone",
        )
    document: dict[str, Any] = {
        "generated_at": _stamp(clock["at"]),
        "as_of": _stamp(as_of),
        "counts": {
            "findings": len(findings),
            "assets": len(assets),
            "by_status": by_status,
            "by_severity": by_severity,
        },
        "findings": findings,
        "assets": assets,
    }
    if campaign_id is not None:
        document["campaign_id"] = campaign_id
    return document


def _indexed(items: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    return {str(item[key]): item for item in items}


def delta_report(
    db: psycopg.Connection[Any],
    *,
    start: datetime,
    end: datetime,
    campaign_id: str | None,
) -> dict[str, Any]:
    """Two snapshots compared; each item appears in at most one list and no list repeats an id."""
    before = snapshot_report(db, as_of=start, campaign_id=campaign_id)
    after = snapshot_report(db, as_of=end, campaign_id=campaign_id)
    old_findings = _indexed(before["findings"], "finding_id")
    new_findings = _indexed(after["findings"], "finding_id")
    old_assets = _indexed(before["assets"], "asset_id")
    new_assets = _indexed(after["assets"], "asset_id")

    fixed: list[dict[str, Any]] = []
    regressed: list[dict[str, Any]] = []
    created: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    for finding_id, item in new_findings.items():
        previous = old_findings.get(finding_id)
        if item["status"] == "FIXED" and (previous is None or previous["status"] != "FIXED"):
            fixed.append(item)
        elif item["status"] == "REGRESSED" and (
            previous is None or previous["status"] != "REGRESSED"
        ):
            regressed.append(item)
        elif previous is None:
            created.append(item)
        elif previous["status"] != item["status"] or previous["severity"] != item["severity"]:
            changed.append(item)
    return {
        "from": _stamp(start),
        "to": _stamp(end),
        "assets_new": [item for key, item in new_assets.items() if key not in old_assets],
        "assets_gone": [item for key, item in old_assets.items() if key not in new_assets],
        "findings_new": _ordered_findings(created),
        "findings_changed": _ordered_findings(changed),
        "findings_fixed": _ordered_findings(fixed),
        "findings_regressed": _ordered_findings(regressed),
    }


def _validated(document: dict[str, Any], path: str, label: str) -> dict[str, Any]:
    problems = validation.openapi_response_validator(path).iter_errors(document)
    first = next(problems, None)
    if first is not None:
        raise ApiError(
            http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            f"{label} violates its contract at "
            f"/{'/'.join(str(part) for part in first.absolute_path)}: {first.message[:300]}",
        )
    return document


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


def _check_id(campaign_id: str | None) -> str | None:
    if campaign_id is not None and validation.errors(
        "common/ids.v2.schema.json#/$defs/Id", campaign_id
    ):
        raise _bad_request("campaign_id is not a valid id", "/campaign_id")
    return campaign_id


@router.get(
    SNAPSHOT_PATH,
    operation_id="getSnapshotReport",
    summary="Báo cáo JSON của finding tại một thời điểm",
    responses={400: _ERROR_400, 401: _ERROR_401},
)
def get_snapshot(
    request: Request,
    response: Response,
    principal: Annotated[Principal, Depends(require_principal)],
    db: ConnectionDep,
    as_of: Annotated[datetime | None, Query()] = None,
    campaign_id: Annotated[str | None, Query()] = None,
) -> dict[str, Any]:
    _trace(request, response)
    del principal
    _check_id(campaign_id)
    moment = _aware("as_of", as_of) if as_of is not None else datetime.now(UTC)
    document = snapshot_report(db, as_of=moment, campaign_id=campaign_id)
    return _validated(document, SNAPSHOT_PATH, "a report snapshot")


@router.get(
    DELTA_PATH,
    operation_id="getDeltaReport",
    summary="Báo cáo thay đổi giữa hai thời điểm",
    responses={400: _ERROR_400, 401: _ERROR_401},
)
def get_delta(
    request: Request,
    response: Response,
    principal: Annotated[Principal, Depends(require_principal)],
    db: ConnectionDep,
    start: Annotated[datetime, Query(alias="from")],
    end: Annotated[datetime, Query(alias="to")],
    campaign_id: Annotated[str | None, Query()] = None,
) -> dict[str, Any]:
    _trace(request, response)
    del principal
    _check_id(campaign_id)
    moment_from = _aware("from", start)
    moment_to = _aware("to", end)
    if moment_from >= moment_to:
        raise _bad_request("from must be earlier than to", "/from")
    document = delta_report(db, start=moment_from, end=moment_to, campaign_id=campaign_id)
    return _validated(document, DELTA_PATH, "a report delta")


def register(registry: RouterRegistry, *, prefix: str = API_PREFIX) -> RouterEntry:
    """Mount the reports router on an app registry."""
    return registry.register("reports", router, prefix=prefix)
