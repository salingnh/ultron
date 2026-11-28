"""Shared fixtures of the G2 slice C severity tests: scripted answers and simulated feed deltas.

The intel deltas here are **simulated** documents in the real feed shape: `simulated_kev_added`
edits the committed KEV slice to add one CVE and bumps `catalogVersion`, exactly as a CISA catalog
revision looks. It goes through the real parser, sync and `intel.revision.v2` event path, so the
revision and the event under test are the production ones; no test reaches the network.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis.contracts_gen.agent.model_response_v2_schema import ModelResponse
from aegis.m18_intel.sync import FeedSync
from tests import g16c_support as fixtures

KEV_ADDED_CVE = "CVE-2021-23017"
KEV_ADDED_VERSION = "2026-11-29"
REPOSITORY = Path(__file__).resolve().parent.parent


def completed_response(
    evidence_id: str,
    *,
    severity: str = "MEDIUM",
    kind: str = "evidence",
    ref: str | None = None,
) -> ModelResponse:
    """A `completed` answer that cites one real record of the finding."""
    payload = _template()
    payload["parsed"]["severity"] = severity
    payload["parsed"]["source_refs"] = [{"kind": kind, "ref": ref or evidence_id}]
    payload["message"]["content"][0]["text"] = json.dumps(payload["parsed"])
    return ModelResponse.model_validate(payload)


def refused_response(finish_reason: str = "refused") -> ModelResponse:
    """A truncated/refused answer: a message, no parsed output (model-response.v2)."""
    payload = _template()
    payload["finish_reason"] = finish_reason
    payload.pop("parsed")
    payload["message"]["content"][0]["text"] = "the provider stopped early"
    return ModelResponse.model_validate(payload)


def invalid_output_response() -> ModelResponse:
    payload = json.loads(
        (
            REPOSITORY / "contracts/fixtures/valid/model-response.invalid-output.openai.json"
        ).read_text(encoding="utf-8")
    )
    return ModelResponse.model_validate(payload)


def _template() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(
        (REPOSITORY / "contracts/fixtures/valid/model-response.completed.anthropic.json").read_text(
            encoding="utf-8"
        )
    )
    return document


def findings_by_cve(connection: Any) -> dict[str, dict[str, Any]]:
    rows = connection.execute(
        "SELECT f.*, a.canonical_key, a.exposure, a.criticality"
        "  FROM finding f JOIN asset a ON a.asset_id = f.asset_id"
        " ORDER BY a.canonical_key, f.finding_id"
    ).fetchall()
    return {str(row["vulnerability_ids"][0]): dict(row) for row in rows}


def assessment_rows(connection: Any) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in connection.execute(
            "SELECT finding_id, input_revision, dedup_key, kind, trigger, severity, assessment"
            "  FROM severity_assessment ORDER BY created_at, assessment_id"
        ).fetchall()
    ]


def evidence_of(connection: Any, finding_id: str) -> str:
    row = connection.execute(
        "SELECT evidence_id FROM finding_run WHERE finding_id = %s AND evidence_id IS NOT NULL"
        " ORDER BY observed_at DESC LIMIT 1",
        (finding_id,),
    ).fetchone()
    assert row is not None
    return str(row["evidence_id"])


def simulated_kev_added(*, version: str = KEV_ADDED_VERSION) -> bytes:
    """The committed KEV slice plus one CVE: a catalog revision in the published shape."""
    document = json.loads(fixtures.KEV.read_text(encoding="utf-8"))
    assert not any(entry["cveID"] == KEV_ADDED_CVE for entry in document["vulnerabilities"]), (
        "the fixture already lists the CVE"
    )
    document["vulnerabilities"].append(
        {
            "cveID": KEV_ADDED_CVE,
            "vendorProject": "F5",
            "product": "nginx",
            "vulnerabilityName": "Simulated KEV addition (test fixture)",
            "dateAdded": version,
            "shortDescription": "simulated delta, not a CISA advisory",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2026-12-20",
            "knownRansomwareCampaignUse": "Unknown",
        }
    )
    document["catalogVersion"] = version
    document["dateReleased"] = f"{version}T00:00:00.000Z"
    document["count"] = len(document["vulnerabilities"])
    return json.dumps(document).encode("utf-8")


def sync_kev_added(dsn: str, *, version: str = KEV_ADDED_VERSION) -> None:
    FeedSync(fixtures.connector(dsn), fixtures.MemoryStore()).sync(
        "kev",
        version,
        simulated_kev_added(version=version),
        source_uri="simulated-kev-add.json",
        snapshot_at=datetime(2026, 11, 29, tzinfo=UTC),
    )
