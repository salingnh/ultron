"""Operator CLI of M20 (G1.6 slice C): `python -m aegis.m20_vuln <run|status>`.

* `run` - match the current `service.product` / `http.technology` observations against the current
  NVD catalogue and store candidate `package_vuln_match` rows plus their `vulnerability.matched.v2`
  events. A candidate the new revision no longer matches is taken back (`matched = false` at the
  new revision, with the reason in `retractions`). `--campaign` narrows the targets,
  `--changed-since` narrows the catalogue to the CVE ids of the `intel.revision.v2` events after
  that outbox cursor (the delta run), `--dry-run` prints the decisions without writing.
* the same `run` then raises/refreshes the **findings** of those candidates
  (`aegis.m20_vuln.findings`) and assesses their severity (C07) when a live model is configured;
  `--no-findings` keeps the run at the candidate level (the G1.6 behaviour).
* `reassess` - consume the `intel.revision.v2` events published since the consumer's checkpoint
  and re-assess the findings whose CVEs they name (`aegis.m20_vuln.intel_reassess`). It is the
  feed-driven half of C07: a KEV/EPSS/withdrawal/distro change updates the history without a scan
  job, exactly once per finding and input revision; a replay of the same events adds no row and
  calls no model. A second live instance is refused by the dispatcher lease instead of duplicating
  the work.
* `status` - candidate counts per asset (the operator's view of what matching produced: the
  newest decision of every pair, so a retraction removes the pair from the count).

Environment: `AEGIS_PG_DSN`. No network, no container.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from aegis.m20_vuln import intel_reassess, severity, visibility
from aegis.m20_vuln.findings import FindingsEngine
from aegis.m20_vuln.matching import Matcher, changed_vulnerabilities, connect_from_env


def _run(argv: argparse.Namespace) -> int:
    connection = connect_from_env()
    try:
        only: set[str] | None = None
        cursor = None
        if argv.changed_since is not None:
            only, cursor = changed_vulnerabilities(connection, argv.changed_since)
        report = Matcher(connection).run(
            campaign_id=argv.campaign,
            only_vulnerabilities=only,
            dry_run=argv.dry_run,
            cursor=cursor,
        )
        findings = None
        if not argv.no_findings:
            client = severity.model_from_env(os.environ["AEGIS_PG_DSN"])
            model, provider, model_name = (None, None, None) if client is None else client
            findings = FindingsEngine(connection).run(
                campaign_id=argv.campaign,
                only_vulnerabilities=only,
                dry_run=argv.dry_run,
                model=model,
                provider=provider,
                model_name=model_name,
            )
    finally:
        connection.close()
    document: dict[str, Any] = {
        **report.as_dict(),
        "matches": report.matches,
        "retractions": report.retractions,
    }
    if findings is not None:
        document["findings"] = {
            **findings.as_dict(),
            "created": findings.findings,
            "withdrawals": findings.withdrawals,
        }
    print(json.dumps(document, indent=2))
    return 0


def _reassess(argv: argparse.Namespace) -> int:
    connection = connect_from_env()
    try:
        client = severity.model_from_env(os.environ["AEGIS_PG_DSN"])
        model, provider, model_name = (None, None, None) if client is None else client
        report = intel_reassess.run_once(
            connection,
            model=model,
            provider=provider,
            model_name=model_name,
            consumer=argv.consumer,
            batch=argv.batch,
        )
    finally:
        connection.close()
    print(json.dumps(report.as_dict(), indent=2, default=str))
    return 0


def _status() -> int:
    connection = connect_from_env()
    try:
        # `package_vuln_match` is append-only history: a candidate is the newest decision of the
        # pair, and a retraction (matched = false, 0008) means the pair is no longer a candidate.
        rows = connection.execute(
            "WITH "
            + visibility.LATEST_DECISION_CTE
            + " SELECT a.canonical_key, count(*) AS candidates,"
            "       count(*) FILTER (WHERE vc_kev.kev IS NOT NULL) AS kev,"
            "       max(m.created_at) AS newest"
            "  FROM latest m"
            "  JOIN asset a ON a.asset_id = m.package_asset_id"
            "  LEFT JOIN vulnerability_current vc_kev"
            "    ON vc_kev.vulnerability_id = m.vulnerability_id AND vc_kev.source = 'kev'"
            " WHERE m.matched"
            " GROUP BY a.canonical_key ORDER BY candidates DESC",
            (None, None),
        ).fetchall()
    finally:
        connection.close()
    document: dict[str, Any] = {
        "assets": [
            {
                "canonical_key": row["canonical_key"],
                "candidates": row["candidates"],
                "kev": row["kev"],
                "newest": row["newest"],
            }
            for row in rows
        ]
    }
    print(json.dumps(document, indent=2, default=str))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m aegis.m20_vuln")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="match observations against the loaded intel")
    run.add_argument("--campaign", default=None, help="only assets of this campaign")
    run.add_argument(
        "--changed-since",
        type=int,
        default=None,
        help="only re-check the CVEs of intel.revision.v2 events after this outbox seq",
    )
    run.add_argument("--dry-run", action="store_true", help="print candidates, write nothing")
    run.add_argument(
        "--no-findings",
        action="store_true",
        help="stop at candidates: do not raise/refresh finding rows (G1.6 behaviour)",
    )
    reassess = sub.add_parser(
        "reassess", help="re-assess the findings an intel.revision.v2 event names"
    )
    reassess.add_argument(
        "--consumer",
        default=intel_reassess.CONSUMER,
        help="outbox consumer generation (default: m20-severity#g1)",
    )
    reassess.add_argument(
        "--batch", type=int, default=intel_reassess.DEFAULT_BATCH, help="events per pass"
    )
    sub.add_parser("status", help="candidate counts per asset")
    parsed = parser.parse_args(argv)
    if parsed.command == "status":
        return _status()
    if parsed.command == "reassess":
        return _reassess(parsed)
    return _run(parsed)


if __name__ == "__main__":
    sys.exit(main())
