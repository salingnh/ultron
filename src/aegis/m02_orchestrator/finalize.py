"""Finishing a campaign: run the CVE matcher, then decide whether the objective may be claimed.

Two questions are answered here, both about the campaign as a whole and neither about the model:

1. **Did the matcher run?** A campaign that found a versioned service must produce candidates
   without an operator remembering `python -m aegis.m20_vuln run`. The matcher is the last step of
   the discovery chain, so it runs once, here, on the campaign's own targets (`Matcher.run` with
   `campaign_id` narrows to the assets the campaign holds).
2. **Was the surface actually covered?** `result-envelope.v2` makes a job report
   `coverage.complete = false` when it could not conclude what it was asked to check - a paced
   connection the tool gave up on (`EGRESS_PACED`), an egress refusal, a partial collection. A
   campaign that stops while one of its current results says that has not scanned its surface, so
   it may not end `objective_met`: it ends `coverage_incomplete` with the jobs and codes named.

The verdict is computed from the database, not from the model's own summary: the session's stop
reason is the proposal, `FinalCampaign.reason` is the verified outcome, and M02 records the latter
on the campaign row (`status_reason`) through `finish_campaign`.
"""

from __future__ import annotations

from typing import Any

import psycopg

from aegis.m02_orchestrator.types import FinalCampaign

__all__ = [
    "COVERAGE_INCOMPLETE",
    "INCOMPLETE_COVERAGE_SQL",
    "MATCHING_FAILED",
    "OBJECTIVE_MET",
    "finalize",
]

OBJECTIVE_MET = "objective_met"
COVERAGE_INCOMPLETE = "coverage_incomplete"
MATCHING_FAILED = "matching_failed"

#: The campaign's *current* results that report incomplete coverage.
#:
#: Joining `scan_job.envelope_event_id` is what makes this a current verdict: a re-run
#: (generation+1) writes a new envelope, and the superseded row drops out of the view instead of
#: keeping the campaign incomplete forever. `scan_job_campaign_status` (0001) is the driving index.
INCOMPLETE_COVERAGE_SQL = """
SELECT j.job_id, j.capability, i.coverage
  FROM scan_job j
  JOIN ingestion_inbox i ON i.event_id = j.envelope_event_id
 WHERE j.campaign_id = %s
   AND i.coverage IS NOT NULL
   AND i.coverage->>'complete' = 'false'
 ORDER BY j.finished_at DESC NULLS LAST, j.job_id
"""

#: `error` fields are capped in the status reason; a frame dump is not a reason.
MAX_ERROR_CHARS = 300


def incomplete_jobs(connection: psycopg.Connection[Any], campaign_id: str) -> list[dict[str, Any]]:
    """The campaign's current results whose coverage is incomplete, newest first.

    The connection is M20's (`dict_row`, autocommit, `search_path = aegis, public`): the same one
    the matcher runs on, so the two reads of one activity see one snapshot of the campaign.
    """
    rows = connection.execute(INCOMPLETE_COVERAGE_SQL, (campaign_id,)).fetchall()
    return [
        {
            "job_id": str(row["job_id"]),
            "capability": str(row["capability"]),
            "coverage": row["coverage"],
        }
        for row in rows
    ]


def _limitation_codes(rows: list[dict[str, Any]]) -> list[str]:
    codes: set[str] = set()
    for row in rows:
        coverage = row.get("coverage")
        limitations = coverage.get("limitations") if isinstance(coverage, dict) else None
        for item in limitations or []:
            if isinstance(item, dict) and item.get("code"):
                codes.add(str(item["code"]))
    return sorted(codes)


def run_matcher(
    connection: psycopg.Connection[Any], campaign_id: str
) -> tuple[int, int, str | None]:
    """Match this campaign's observed products; `(candidates, retractions, error)`.

    A failure is not swallowed into a success: the caller turns it into a `matching_failed` reason
    so the campaign never reports `objective_met` with no candidates and no signal.
    """
    from aegis.m20_vuln.matching import Matcher

    try:
        report = Matcher(connection).run(campaign_id=campaign_id)
    except Exception as error:  # noqa: BLE001 - the campaign must still finish, honestly
        return 0, 0, f"{type(error).__name__}: {error}"[:MAX_ERROR_CHARS]
    return len(report.matches), int(report.retracted), None


def _notes(incomplete: list[dict[str, Any]], codes: list[str], error: str | None) -> list[str]:
    notes: list[str] = []
    if incomplete:
        named = ", ".join(sorted({row["capability"] for row in incomplete})[:5])
        codes_text = ", ".join(codes) if codes else "no limitation code"
        notes.append(
            f"{len(incomplete)} job(s) report incomplete scan coverage ({named}; {codes_text})"
        )
    if error:
        notes.append(f"candidate matching failed ({error})")
    return notes


def finalize(connection: psycopg.Connection[Any], campaign_id: str, proposed: str) -> FinalCampaign:
    """Run the matcher and turn the verified state of the campaign into its final reason.

    `objective_met` is only kept when every current result reported complete coverage and the
    matcher ran; any other proposed reason (budget/step/cycle stop) keeps its own name and carries
    the notes, because it already says why the campaign stopped.
    """
    incomplete = incomplete_jobs(connection, campaign_id)
    codes = _limitation_codes(incomplete)
    matches, retractions, error = run_matcher(connection, campaign_id)
    notes = _notes(incomplete, codes, error)
    reason = proposed
    if notes and (incomplete or error):
        if proposed == OBJECTIVE_MET:
            code = COVERAGE_INCOMPLETE if incomplete else MATCHING_FAILED
            reason = f"{code}: " + "; ".join(notes)
            reason += "; the objective is not claimed"
        else:
            reason = f"{proposed} (" + "; ".join(notes) + ")"
    return FinalCampaign(
        reason=reason[:2000],
        incomplete_jobs=tuple(row["job_id"] for row in incomplete),
        limitation_codes=tuple(codes),
        matches=matches,
        retractions=retractions,
        matching_error=error,
    )
