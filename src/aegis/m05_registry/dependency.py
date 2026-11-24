"""Job dependencies at acceptance: exist, same campaign, no cycles - in the submission transaction.

The contract (contracts/README.md §Scheduling, approved-task `depends_on`) says M05 checks
existence,
self-reference and cycles, and the DDL adds the same-campaign foreign keys and the self-reference
CHECK. M05 refuses with `POLICY_DENIED / dependency_invalid` so the refusal is a recorded decision.

`find_cycle` is separated from the query so it can be tested on its own: with ids assigned at insert
time and edges only ever written forward, a submission cannot close a loop today, but the rule is
part
of the contract and a reschedule/reopen (G1.1d) will need exactly this check.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

import psycopg

from aegis.m05_registry.errors import M05Error

__all__ = ["check_dependencies", "find_cycle"]


def find_cycle(edges: Mapping[str, Iterable[str]], start: str) -> list[str] | None:
    """Return one dependency cycle reachable from `start` (as a path), or None.

    Edges point from a job to the jobs it depends on; a cycle means "follow depends_on and come
    back".
    """
    path: list[str] = []
    on_path: set[str] = set()
    done: set[str] = set()

    def walk(node: str) -> list[str] | None:
        if node in on_path:
            return path[path.index(node) :] + [node]
        if node in done:
            return None
        on_path.add(node)
        path.append(node)
        for neighbour in sorted(edges.get(node, ())):
            found = walk(neighbour)
            if found is not None:
                return found
        path.pop()
        on_path.discard(node)
        done.add(node)
        return None

    return walk(start)


def _deduplicated(ids: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in ids:
        if item in seen:
            raise M05Error.input_invalid(f"depends_on repeats job {item}", field="/depends_on")
        seen.add(item)
        ordered.append(item)
    return ordered


def check_dependencies(
    conn: psycopg.Connection[Any],
    *,
    campaign_id: str,
    job_id: str,
    depends_on: Sequence[str],
) -> list[str]:
    """Refuse unknown, foreign or cyclic predecessors; return the accepted ids in request order."""
    ordered = _deduplicated([str(item) for item in depends_on])
    if not ordered:
        return []
    if job_id in ordered:
        raise M05Error.policy_denied(
            "dependency_invalid", "a job cannot depend on itself", field="/depends_on"
        )
    rows = conn.execute(
        "SELECT job_id, campaign_id FROM scan_job WHERE job_id = ANY(%s)",
        (ordered,),
    ).fetchall()
    known = {str(row[0]): str(row[1]) for row in rows}
    for index, dependency in enumerate(ordered):
        if dependency not in known:
            raise M05Error.policy_denied(
                "dependency_invalid",
                f"depends_on job {dependency} does not exist",
                field=f"/depends_on/{index}",
            )
        if known[dependency] != campaign_id:
            raise M05Error.policy_denied(
                "dependency_invalid",
                f"depends_on job {dependency} belongs to another campaign",
                field=f"/depends_on/{index}",
            )
    edges: dict[str, set[str]] = {}
    for row in conn.execute(
        "SELECT job_id, depends_on_job_id FROM job_dependency WHERE campaign_id = %s",
        (campaign_id,),
    ).fetchall():
        edges.setdefault(str(row[0]), set()).add(str(row[1]))
    edges[job_id] = set(ordered)
    cycle = find_cycle(edges, job_id)
    if cycle is not None:
        raise M05Error.policy_denied(
            "dependency_invalid",
            "depends_on would create a cycle: " + " -> ".join(cycle),
            field="/depends_on",
        )
    return ordered
