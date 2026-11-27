"""The one definition of "a candidate": the newest decision of an `(asset, vulnerability)` pair.

`aegis.package_vuln_match` is append-only history (migration 0004's unique key has no campaign and
no time), and migration 0008 lets a later intel revision *retract* a candidate (`matched = false`).
A pair is therefore a candidate only when its **newest** row says `matched`; every reader must apply
the same rule or they disagree about the same data:

* M23 removes an `AFFECTED_BY` edge only for a pair whose newest decision is not a match
  (`m23_graph.pg.current_matched_pairs`);
* M26's `GET /assets/{id}/vulnerabilities` lists the newest matched decisions only;
* M20's `status` counts candidates the same way;
* the G1.6c demo compares its candidate list with the graph, so it must read the same set (it did
  not, and reported "the graph edges and the candidates disagree" on any stack with a retraction).

`LATEST_DECISION_CTE` is that one query. A caller composes its own projection and filters around it
(`WITH <cte> SELECT …`), but the ordering and the `matched` rule live here and nowhere else.

The asset filter is an optional `uuid[]` (`NULL` = every asset), always passed twice: the CTE takes
two parameters in this order.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import psycopg
from psycopg.rows import dict_row

__all__ = [
    "LATEST_DECISION_CTE",
    "candidate_rows",
    "connect",
    "current_matched_pairs",
    "latest_decisions",
]

#: The canonical newest-decision CTE. Callers write `"WITH " + LATEST_DECISION_CTE + " SELECT …"`
#: and pass the asset filter twice (a `uuid[]` or `None` for every asset).
LATEST_DECISION_CTE = (
    "latest AS ("
    "  SELECT DISTINCT ON (m.package_asset_id, m.vulnerability_id)"
    "         m.match_id, m.package_asset_id, m.vulnerability_id, m.match_method,"
    "         m.affected_range, m.confidence, m.snapshot_id, m.matched, m.created_at"
    "    FROM package_vuln_match m"
    "   WHERE (%s::uuid[] IS NULL OR m.package_asset_id = ANY(%s::uuid[]))"
    "   ORDER BY m.package_asset_id, m.vulnerability_id, m.created_at DESC, m.match_id DESC"
    ")"
)

#: Read-side connection of this module: autocommit, dict rows, the contract search path.
SEARCH_PATH = "SET search_path = aegis, public"


def connect(dsn: str) -> psycopg.Connection[dict[str, Any]]:
    conn: psycopg.Connection[dict[str, Any]] = psycopg.connect(
        dsn, autocommit=True, row_factory=dict_row
    )
    conn.execute(SEARCH_PATH)
    return conn


def _uuid_list(values: Iterable[Any] | None) -> list[str] | None:
    if values is None:
        return None
    seen: list[str] = []
    for value in values:
        text = str(value)
        if text not in seen:
            seen.append(text)
    return seen


def latest_decisions(
    conn: psycopg.Connection[Any], asset_ids: Iterable[Any] | None = None
) -> list[dict[str, Any]]:
    """The newest decision of every `(asset, vulnerability)` pair, retractions included."""
    assets = _uuid_list(asset_ids)
    rows = conn.execute(
        "WITH " + LATEST_DECISION_CTE + " SELECT * FROM latest"
        " ORDER BY package_asset_id, vulnerability_id",
        (assets, assets),
    ).fetchall()
    return [dict(row) for row in rows]


def current_matched_pairs(
    conn: psycopg.Connection[Any], asset_ids: Iterable[Any] | None = None
) -> set[tuple[str, str]]:
    """The `(asset, vulnerability)` pairs whose newest decision is a match."""
    return {
        (str(row["package_asset_id"]), str(row["vulnerability_id"]))
        for row in latest_decisions(conn, asset_ids)
        if row["matched"]
    }


def candidate_rows(conn: psycopg.Connection[Any], asset_ids: Iterable[Any]) -> list[dict[str, Any]]:
    """Newest matched decisions for these assets, with CVSS/KEV/EPSS from `vulnerability_current`.

    This is the operator/demo shape of a candidate: one row per `(asset, vulnerability)`, a
    retracted pair absent, `kev` a boolean and `epss`/`cvss_base` the published values (None when
    the catalogue does not carry that source for the CVE).
    """
    assets = _uuid_list(asset_ids)
    if not assets:
        return []
    rows = conn.execute(
        "WITH "
        + LATEST_DECISION_CTE
        + " SELECT a.canonical_key, latest.vulnerability_id, latest.match_method,"
        "        latest.affected_range, latest.confidence, latest.snapshot_id, latest.created_at,"
        "        nvd.cvss ->> 'base_score' AS cvss_base,"
        "        nvd.cvss ->> 'base_severity' AS cvss_severity,"
        "        (k.kev IS NOT NULL) AS kev, e.epss ->> 'score' AS epss"
        "   FROM latest"
        "   JOIN asset a ON a.asset_id = latest.package_asset_id"
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
        "  ORDER BY a.canonical_key, latest.vulnerability_id",
        (assets, assets),
    ).fetchall()
    return [dict(row) for row in rows]
