"""G0.3b scenario 1: 100 concurrent writers upsert the same canonical_key.

Executes the contract template `contracts/graph/projector-upserts.cypher` statement 1
verbatim (no copy), first with no retry to count the raw conflict rate, then with the
retry policy a projector needs, and finally with 100 distinct keys as an upper bound
for what independent upserts can do on the same Neo4j instance.

All connections/sessions are established *before* the barrier, so the measured race is
the transaction execution, not TCP connect skew.

Acceptance (card G0.3b): 100 writers, same key -> exactly one node, NFR-03.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone

from neo4j.exceptions import Neo4jError

from spike_common import (
    apply_constraints,
    iso,
    load_cypher_statements,
    neo4j_driver,
    run_cypher_retry,
    uid,
    wipe_graph,
)

KEY = "concurrent.spike-a.example"
BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _asset_params(index: int, key: str) -> dict:
    return {
        "canonical_key": f"domain:{key}",
        "asset_id": str(uid("asset:domain:" + key)),
        "kind": "domain",
        "first_seen": iso(BASE),
        "last_seen": iso(BASE + timedelta(seconds=index)),
        "campaign_id": f"camp-{index % 5}",
        "revision": index + 1,
    }


def _round(writers: int, prepare, execute) -> tuple[list[dict], float]:
    """Prepare every writer's resources, release them together, then execute."""
    results: list[dict | None] = [None] * writers
    resources: list = [None] * writers
    barrier = threading.Barrier(writers + 1)

    def wrap(i: int) -> None:
        try:
            resources[i] = prepare(i)
            barrier.wait()
            results[i] = execute(i, resources[i])
        except Exception as err:  # noqa: BLE001 - recorded for the report
            results[i] = {"writer": i, "unexpected": f"{type(err).__name__}: {err}"}

    threads = [threading.Thread(target=wrap, args=(i,), daemon=True) for i in range(writers)]
    for t in threads:
        t.start()
    barrier.wait()
    started = time.monotonic()
    for t in threads:
        t.join()
    elapsed = time.monotonic() - started
    for resource in resources:
        if resource is not None and hasattr(resource, "close"):
            resource.close()
    return [r for r in results if r is not None], elapsed


def _no_retry_round(stmt: str, writers: int) -> dict:
    """One attempt per writer: how many lose the MERGE race, and with which error."""

    def prepare(i: int):
        driver = neo4j_driver()
        return driver, driver.session()

    def execute(i: int, resource) -> dict:
        driver, session = resource
        params = {**_asset_params(i, KEY), "revision": 10_000 + i}
        try:
            with session.begin_transaction() as tx:
                tx.run(stmt, params).consume()
            return {"writer": i, "outcome": "success", "revision": params["revision"]}
        except Neo4jError as err:
            return {"writer": i, "outcome": "error", "code": err.code}

    results, elapsed = _round(writers, prepare, execute)
    codes: dict[str, int] = {}
    for r in results:
        key = r.get("code", r.get("outcome", "unexpected"))
        codes[key] = codes.get(key, 0) + 1
    return {"writers": writers, "elapsed_seconds": round(elapsed, 3), "outcomes": codes}


def _retry_round(stmt: str, writers: int, key: str) -> dict:
    completion: list[dict] = []
    stats: dict = {}
    completion_lock = threading.Lock()

    def prepare(i: int):
        return neo4j_driver()

    def execute(i: int, driver) -> dict:
        params = _asset_params(i, key)
        attempts = run_cypher_retry(driver, stmt, params, stats=stats, deadline=120.0)
        with completion_lock:
            completion.append({"writer": i, "revision": params["revision"]})
        return {"writer": i, "outcome": "success", "attempts": attempts, "revision": params["revision"]}

    results, elapsed = _round(writers, prepare, execute)
    successes = [r for r in results if r.get("outcome") == "success"]
    return {
        "writers": writers,
        "elapsed_seconds": round(elapsed, 3),
        "successes": len(successes),
        "completion_order": completion,
        "retries": {
            "total_attempts": stats.get("attempts", 0),
            "attempts_above_one": max(0, stats.get("attempts", 0) - len(successes)),
            "error_codes": stats.get("errors", {}),
        },
        "max_attempts_used": max((r.get("attempts", 0) for r in successes), default=0),
    }


def _inspect_key(driver, key: str) -> dict:
    with driver.session() as session:
        rec = session.run(
            "MATCH (a:Asset {canonical_key: $k}) "
            "RETURN count(a) AS nodes, collect(a.asset_id) AS asset_ids, collect(a.kind) AS kinds, "
            "       collect(a.pg_revision) AS revisions, collect(a.last_seen) AS last_seens, "
            "       collect(a.campaign_ids) AS campaign_ids, collect(labels(a)) AS labels",
            k=f"domain:{key}",
        ).single()
    return {
        "nodes": rec["nodes"],
        "asset_ids": rec["asset_ids"],
        "kinds": rec["kinds"],
        "pg_revisions": [int(n) for n in rec["revisions"]],
        "last_seens": [iso(n.to_native()) for n in rec["last_seens"]],
        "campaign_ids": [sorted(list(x)) for x in rec["campaign_ids"]],
        "labels": rec["labels"],
    }


def run(writers: int = 100) -> dict:
    statements = load_cypher_statements()
    asset_stmt = statements[0]
    driver = neo4j_driver()
    apply_constraints(driver)

    # 1. same key, exactly one attempt per writer: the raw conflict rate.
    wipe_graph(driver)
    no_retry = _no_retry_round(asset_stmt, writers)
    after_no_retry = _inspect_key(driver, KEY)

    # 2. same key, retry until success: the state a projector must reach.
    wipe_graph(driver)
    retry = _retry_round(asset_stmt, writers, KEY)
    after_retry = _inspect_key(driver, KEY)
    last_revision = retry["completion_order"][-1]["revision"] if retry["completion_order"] else None
    expected_campaigns = sorted({f"camp-{i % 5}" for i in range(writers)})

    checks = {
        "one_node_nfr03": after_retry["nodes"] == 1,
        "asset_id": after_retry["asset_ids"] == [str(uid("asset:domain:" + KEY))],
        "kind": after_retry["kinds"] == ["domain"],
        "campaign_ids_union": all(c == expected_campaigns for c in after_retry["campaign_ids"]),
        "last_seen_max": after_retry["last_seens"] == [iso(BASE + timedelta(seconds=writers - 1))],
        "domain_label": all(sorted(lbl) == ["Asset", "Domain"] for lbl in after_retry["labels"]),
        "pg_revision_last_writer": after_retry["pg_revisions"] == [last_revision],
    }

    # 3. distinct keys: what independent upserts cost (upper bound for parallel work).
    def prepare(i: int):
        return neo4j_driver()

    def execute(i: int, d) -> dict:
        key = f"w{i:03d}.spike-a.example"
        attempts = run_cypher_retry(d, asset_stmt, _asset_params(i, key), deadline=60.0)
        return {"writer": i, "outcome": "success", "attempts": attempts}

    distinct, distinct_elapsed = _round(writers, prepare, execute)
    distinct_ok = sum(1 for r in distinct if r.get("outcome") == "success")
    distinct_ops = distinct_ok / distinct_elapsed if distinct_elapsed else 0.0

    result = {
        "scenario": "concurrent-upsert",
        "key": f"domain:{KEY}",
        "writers": writers,
        "no_retry": no_retry,
        "after_no_retry": after_no_retry,
        "retry": {k: v for k, v in retry.items() if k != "completion_order"},
        "after_retry": after_retry,
        "checks": checks,
        "all_checks_pass": all(checks.values()),
        "distinct_keys": {
            "writers": writers,
            "elapsed_seconds": round(distinct_elapsed, 3),
            "ops_per_second": round(distinct_ops, 1),
        },
    }
    driver.close()
    return result
