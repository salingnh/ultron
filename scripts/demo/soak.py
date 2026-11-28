#!/usr/bin/env python3
"""`make soak-start` - the shortened G1 soak (24-48 h by default 24) at a low steady rate.

What it does, one round every `SOAK_INTERVAL_SECONDS` (default 180 s):

* creates one campaign on the lab (`POST /campaigns`, the same body as `demo-g1`);
* keeps at most `SOAK_MAX_ACTIVE` campaigns open and lets stuck ones be recorded, not fixed: a
  campaign still open after `SOAK_CAMPAIGN_TIMEOUT_SECONDS` is cancelled through the API (that is
  the operator's own cancel path, which also exercises it) and counted as a failure;
* every `SOAK_REPORT_SECONDS` (default 300 s) appends one JSON line to `.local/soak/report.jsonl`
  and rewrites `.local/soak/report.txt`, with: campaigns/jobs by status, the tool and ingestion
  error counts (with the first error's code and a few failed jobs), evidence bytes, knowledge
  counts, how far the M23 projection lags the outbox (the projector's **own** consumer cursor),
  the duplicate counts the G1 gate asks for, the resident memory of the stack processes, and the
  health gate below;
* stops when `SOAK_HOURS` is up (default 24) or when asked with SIGTERM, and writes a final report.

**The report is a gate on the stack, not just evidence.** `health.status` is `fail` (and the
process exits 1 at the end) when a stack component is not running, the evidence store rejects a
write, the projector stops advancing while the outbox grows or falls `SOAK_PROJECTOR_LAG_LIMIT`
behind, PostgreSQL and the graph disagree, a duplicate appears, a job FAILED, or ingestion
quarantined a record. Each problem is one line in `health.problems` and at the top of
`report.txt`: the 24 h soak of 2026-11-24 ended with m23 dead and `errors: []` because the old
report only listed what the soak itself raised. The campaign runs are still evidence for the
product gate; this gate says whether a run proves anything at all.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import support  # noqa: E402 - the demo scripts' shared helpers, a sibling module

STATE = support.STATE_DIR / "soak"
REPORT_JSONL = STATE / "report.jsonl"
REPORT_TXT = STATE / "report.txt"
SUMMARY = STATE / "summary.json"
STOP = STATE / "stop"

HOURS_ENV = "SOAK_HOURS"
INTERVAL_ENV = "SOAK_INTERVAL_SECONDS"
REPORT_EVERY_ENV = "SOAK_REPORT_SECONDS"
ACTIVE_ENV = "SOAK_MAX_ACTIVE"
CAMPAIGN_TIMEOUT_ENV = "SOAK_CAMPAIGN_TIMEOUT_SECONDS"
LAG_LIMIT_ENV = "SOAK_PROJECTOR_LAG_LIMIT"

DEFAULT_HOURS = 24.0
DEFAULT_INTERVAL = 180.0
DEFAULT_REPORT_EVERY = 300.0
DEFAULT_ACTIVE = 2
DEFAULT_CAMPAIGN_TIMEOUT = 900.0
#: One projector batch; a steady projector stays far below it. An env override exists for a stack
#: that legitimately batches more (`AEGIS_PROJECTOR_BATCH`).
DEFAULT_LAG_LIMIT = 1000

#: A consumer generation of the projector (`m23-projector#g1`); its `#delta` emitter is separate.
PROJECTOR_GENERATION = re.compile(r"^m23-projector#g(\d+)$")
#: SeaweedFS marks every volume unwritable below `-minFreeSpace` (1% of the filesystem) and refuses
#: to grow a volume, so every S3 PUT answers HTTP 500 InternalError (g2-p0: 34 jobs). The soak
#: reports the host's free space next to a rejected store probe instead of leaving the 500 opaque.
STORE_MIN_FREE_PERCENT = 1.0


def main(argv: list[str] | None = None) -> int:
    support.load_demo_env()
    STATE.mkdir(parents=True, exist_ok=True)
    hours = float(os.environ.get(HOURS_ENV) or DEFAULT_HOURS)
    interval = float(os.environ.get(INTERVAL_ENV) or DEFAULT_INTERVAL)
    report_every = float(os.environ.get(REPORT_EVERY_ENV) or DEFAULT_REPORT_EVERY)
    max_active = int(os.environ.get(ACTIVE_ENV) or DEFAULT_ACTIVE)
    campaign_timeout = float(os.environ.get(CAMPAIGN_TIMEOUT_ENV) or DEFAULT_CAMPAIGN_TIMEOUT)
    deadline = time.monotonic() + hours * 3600
    started = support.now()
    stop = {"asked": False}

    def _stop(signum: int, frame: Any) -> None:
        del signum, frame
        stop["asked"] = True

    previous = signal.signal(signal.SIGTERM, _stop)
    active: dict[str, float] = {}
    rounds = 0
    created = 0
    cancelled = 0
    errors: list[str] = []
    _log(f"soak: {hours:g}h, one campaign every {interval:g}s, report every {report_every:g}s")
    next_report = time.monotonic() + report_every
    next_create = time.monotonic()
    try:
        while not stop["asked"] and time.monotonic() < deadline and not STOP.exists():
            now = time.monotonic()
            for campaign_id, started_at in list(active.items()):
                if now - started_at <= campaign_timeout:
                    continue
                _cancel(campaign_id, errors)
                cancelled += 1
                active.pop(campaign_id, None)
            try:
                _reap_terminal(active, errors)
            except Exception as error:  # noqa: BLE001 - a soak keeps going and records the error
                errors.append(f"reap: {type(error).__name__}: {error}")
            # The rate is the interval, not "as soon as a slot is free": a lab campaign finishes in
            # seconds, and a soak that refills the slot immediately would run hundreds per hour.
            if (
                len(active) < max_active
                and time.monotonic() >= next_create
                and time.monotonic() < deadline
            ):
                next_create = time.monotonic() + interval
                try:
                    campaign_id = support.create_campaign(
                        f"G1.5c soak {time.strftime('%Y-%m-%d %H:%M:%S')}"
                    )
                    active[campaign_id] = time.monotonic()
                    created += 1
                    rounds += 1
                    _log(f"soak: created campaign {campaign_id} ({len(active)} active)")
                except Exception as error:  # noqa: BLE001 - the API may be restarting
                    errors.append(f"create: {type(error).__name__}: {error}")
            if time.monotonic() >= next_report:
                try:
                    row = _report(
                        started=started,
                        deadline_reached=time.monotonic() >= deadline,
                        created=created,
                        cancelled=cancelled,
                        rounds=rounds,
                        errors=errors,
                        final=False,
                    )
                    _log(
                        "soak: report "
                        + f"status={row['health']['status']} "
                        + f"campaigns={row['campaigns']['total']} jobs={row['jobs']['total']} "
                        + f"failures={row['jobs']['by_status'].get('FAILED', 0)} "
                        + f"duplicates={sum(len(v) for v in row['duplicates'].values())} "
                        + f"graph_mismatch={row['graph']['asset_mismatch']}"
                        + f"/{row['graph']['edge_mismatch']}"
                        + f" projector_lag={row['lag']['projector_lag']}"
                    )
                    for problem in row["health"]["problems"]:
                        _log(f"soak: PROBLEM {problem}")
                except Exception as error:  # noqa: BLE001
                    errors.append(f"report: {type(error).__name__}: {error}")
                    _log(f"soak: report failed: {error}")
                next_report = time.monotonic() + report_every
            time.sleep(min(5.0, max(0.2, next_create - time.monotonic())))
    finally:
        signal.signal(signal.SIGTERM, previous)
        row = _report(
            started=started,
            deadline_reached=time.monotonic() >= deadline,
            created=created,
            cancelled=cancelled,
            rounds=rounds,
            errors=errors,
            final=True,
        )
        SUMMARY.write_text(json.dumps(row, indent=1, sort_keys=True, default=str) + "\n", "utf-8")
        _log(f"soak: finished ({row['reason']}); report {REPORT_TXT}")
        _log(f"soak: status {row['health']['status']}")
        for problem in row["health"]["problems"]:
            _log(f"soak: PROBLEM {problem}")
        status = 0 if row["health"]["status"] == "pass" else 1
    return status


def _reap_terminal(active: dict[str, float], errors: list[str]) -> None:
    for campaign_id in list(active):
        body = support.campaign(campaign_id)
        if str(body.get("status")) in support.TERMINAL_CAMPAIGN:
            active.pop(campaign_id, None)


def _cancel(campaign_id: str, errors: list[str]) -> None:
    """Cancel a stuck campaign through the operator path (never a database patch)."""
    try:
        support.api(
            "POST",
            f"/api/v2/campaigns/{campaign_id}/cancel",
            payload={"reason": "soak: campaign exceeded its per-campaign timeout"},
            token=support.operator_token(),
        )
    except Exception as error:  # noqa: BLE001 - recorded, the soak continues
        errors.append(f"cancel {campaign_id}: {type(error).__name__}: {error}")


def _report(
    *,
    started: str,
    deadline_reached: bool,
    created: int,
    cancelled: int,
    rounds: int,
    errors: list[str],
    final: bool,
) -> dict[str, Any]:
    connection = support.pg()
    try:
        row = _collect(
            connection, started, deadline_reached, created, cancelled, rounds, errors, final
        )
    finally:
        connection.close()
    REPORT_JSONL.parent.mkdir(parents=True, exist_ok=True)
    with REPORT_JSONL.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True, default=str) + "\n")
    REPORT_TXT.write_text(_render(row), encoding="utf-8")
    return row


def _collect(
    connection: Any,
    started: str,
    deadline_reached: bool,
    created: int,
    cancelled: int,
    rounds: int,
    errors: list[str],
    final: bool,
) -> dict[str, Any]:
    campaigns = support.rows(
        connection, "SELECT status, count(*) AS n FROM campaign GROUP BY 1 ORDER BY 1"
    )
    jobs = support.rows(
        connection,
        "SELECT capability, status, count(*) AS n FROM scan_job GROUP BY 1, 2 ORDER BY 1, 2",
    )
    job_errors = support.rows(
        connection,
        "SELECT coalesce(error ->> 'code', '(none)') AS code, count(*) AS n FROM scan_job"
        " WHERE status = 'FAILED' GROUP BY 1 ORDER BY 1",
    )
    ingest_errors = support.rows(
        connection,
        "SELECT coalesce(receipt ->> 'status', status) AS state, count(*) AS n"
        " FROM ingestion_inbox GROUP BY 1 ORDER BY 1",
    )
    quarantined = support.count(connection, "SELECT count(*) AS n FROM quarantine_record")
    evidence = support.rows(
        connection,
        "SELECT count(*) AS objects, coalesce(sum(size_bytes), 0) AS bytes FROM evidence",
    )
    knowledge = support.rows(
        connection,
        "SELECT (SELECT count(*) FROM asset) AS assets,"
        " (SELECT count(*) FROM observation) AS observations,"
        " (SELECT count(*) FROM relationship) AS relationships,"
        " (SELECT count(*) FROM graph_revision) AS revisions,"
        " (SELECT count(*) FROM outbox_event) AS outbox_events",
    )
    # The graph must hold exactly the assets and open edges PostgreSQL has: the projection only
    # learns about an asset from its outbox event, so a writer that forgets the event leaves the
    # graph behind (that is how `dns:internal.example` was missing). Totals are comparable because
    # this stack is the only writer of its database and graph.
    pg_assets = support.count(connection, "SELECT count(*) AS n FROM asset")
    pg_edges = support.count(
        connection, "SELECT count(*) AS n FROM relationship WHERE valid_to IS NULL"
    )
    graph_assets = _graph_count("MATCH (a:Asset) RETURN count(a) AS n", "n")
    graph_edges = _graph_count("MATCH ()-[r]->() RETURN count(r) AS n", "n")
    graph_vs_pg = {
        "postgres_assets": pg_assets,
        "graph_assets": graph_assets,
        "postgres_open_edges": pg_edges,
        "graph_edges": graph_edges,
        "asset_mismatch": pg_assets - graph_assets,
        "edge_mismatch": pg_edges - graph_edges,
    }
    lag = _projection(connection)
    duplicates = {
        "jobs_by_fingerprint": support.duplicate_groups(
            connection,
            "SELECT job_fingerprint, count(*) AS n FROM scan_job GROUP BY 1 HAVING count(*) > 1",
        ),
        "assets_by_canonical_key": support.duplicate_groups(
            connection,
            "SELECT canonical_key, count(*) AS n FROM asset GROUP BY 1 HAVING count(*) > 1",
        ),
        "outbox_events": support.duplicate_groups(
            connection,
            "SELECT type, dedup_key, count(*) AS n FROM outbox_event GROUP BY 1, 2"
            " HAVING count(*) > 1",
        ),
        "ingestion_receipts": support.duplicate_groups(
            connection,
            "SELECT dedup_key, count(*) AS n FROM ingestion_inbox GROUP BY 1 HAVING count(*) > 1",
        ),
    }
    components = support.components()
    process_rows = [
        {
            "name": item.name,
            "pid": item.pid,
            "alive": item.alive,
            "problem": item.problem,
            "rss_mb": round(support.rss_kb(item.pid) / 1024.0, 1) if item.pid else 0.0,
        }
        for item in components
    ]
    failure_samples = support.rows(
        connection,
        "SELECT job_id::text AS job_id, capability, coalesce(error ->> 'code', '(none)') AS code,"
        " left(coalesce(error ->> 'technical_cause', error ->> 'message', ''), 300) AS detail"
        " FROM scan_job WHERE status = 'FAILED' ORDER BY finished_at DESC NULLS LAST LIMIT 5",
    )
    paused_reasons = support.rows(
        connection,
        "SELECT coalesce(status_reason, '(none)') AS reason, count(*) AS n FROM campaign"
        " WHERE status = 'PAUSED' GROUP BY 1 ORDER BY 2 DESC",
    )
    store = _store_probe()
    containers = _container_memory()
    failures_by_code = {str(item["code"]): int(item["n"]) for item in job_errors}
    health = _health(
        components=components,
        projection=lag,
        store=store,
        graph=graph_vs_pg,
        duplicates=duplicates,
        failures_by_code=failures_by_code,
        quarantined=int(quarantined),
        previous=_previous_report(),
    )
    return {
        "recorded_at": support.now(),
        "soak_started_at": started,
        "reason": (
            ("hours elapsed" if deadline_reached else "stopped (SIGTERM or .local/soak/stop)")
            if final
            else "periodic report (the soak is still running)"
        ),
        "rounds": rounds,
        "campaigns": {
            "created": created,
            "cancelled_by_timeout": cancelled,
            "by_status": {str(item["status"]): int(item["n"]) for item in campaigns},
            "total": sum(int(item["n"]) for item in campaigns),
            "paused_reasons": {str(item["reason"]): int(item["n"]) for item in paused_reasons},
        },
        "jobs": {
            "by_status": {
                str(item["status"]): _sum(jobs, "status", str(item["status"])) for item in jobs
            },
            "by_capability": {
                str(item["capability"]): _sum(jobs, "capability", str(item["capability"]))
                for item in jobs
            },
            "total": sum(int(item["n"]) for item in jobs),
            "failures_by_code": failures_by_code,
            "failure_samples": [dict(item) for item in failure_samples],
        },
        "ingestion": {
            "by_state": {str(item["state"]): int(item["n"]) for item in ingest_errors},
            "quarantined_records": int(quarantined),
        },
        "evidence": {
            "objects": int(evidence[0]["objects"]) if evidence else 0,
            "bytes": int(evidence[0]["bytes"]) if evidence else 0,
        },
        "knowledge": {
            key: int(value) for key, value in (knowledge[0] if knowledge else {}).items()
        },
        "lag": lag,
        "graph": graph_vs_pg,
        "duplicates": duplicates,
        "store": store,
        "memory": {"processes": process_rows, "containers": containers},
        "health": health,
        "errors": errors[-50:],
    }


def _projection(connection: Any) -> dict[str, Any]:
    """How far the M23 projection is behind the outbox: the **projector's own** cursor.

    The 2026-11-24 report read `max(last_seq)` over `consumer_cursor`, which is whichever consumer
    is furthest along (the SSE reader), never the projector: it printed `projector_cursor ==
    outbox_head` for a graph whose projector had been dead for hours. The projector checkpoints one
    row per generation (`m23-projector#g<N>`); the newest generation is the one a rebuild or the
    running loop uses, and its `#delta` emitter is a consumer of its own, not projection progress.
    """
    head = support.count(connection, "SELECT coalesce(max(seq), 0) AS n FROM outbox_event")
    rows = support.rows(
        connection,
        "SELECT consumer, last_seq FROM consumer_cursor WHERE consumer LIKE %s ORDER BY consumer",
        ("m23-projector#%",),
    )
    consumers = {str(row["consumer"]): int(row["last_seq"]) for row in rows}
    generations = {
        int(match.group(1)): value
        for consumer, value in consumers.items()
        if (match := PROJECTOR_GENERATION.match(consumer))
    }
    generation = max(generations) if generations else None
    cursor = generations[generation] if generation is not None else None
    return {
        "outbox_head": head,
        "projector_generation": f"m23-projector#g{generation}" if generation else None,
        "projector_cursor": cursor,
        "projector_lag": None if cursor is None else head - cursor,
        "consumers": consumers,
    }


def _store_probe() -> dict[str, Any]:
    """One real PUT through the production evidence client: can this store accept a write now?

    The old report never asked, so an S3 500 from a full disk looked exactly like a healthy stack.
    The object key is the soak's own (`soak/probe.json`), not evidence: it is overwritten on every
    report and never referenced by a row.
    """
    result: dict[str, Any] = {
        "ok": False,
        "error": None,
        "endpoint": os.environ.get("AEGIS_S3_ENDPOINT"),
        "bucket": os.environ.get("AEGIS_S3_BUCKET"),
        "path": None,
        "free_percent": None,
        "min_free_percent": STORE_MIN_FREE_PERCENT,
    }
    path = _storage_root()
    if path is not None:
        result["path"] = str(path)
        result["free_percent"] = _free_percent(path)
    try:
        from aegis.m28_evidence.store import S3Config, S3EvidenceClient  # noqa: PLC0415 - optional import

        client = S3EvidenceClient(S3Config.from_env(os.environ))
        payload = json.dumps({"soak": support.now()}).encode("utf-8") + b"\n"
        client.put("soak/probe.json", payload, content_type="application/json")
        result["ok"] = True
    except Exception as error:  # noqa: BLE001 - any store failure is the finding
        result["error"] = f"{type(error).__name__}: {error}"[:500]
    return result


def _storage_root() -> Path | None:
    """Where rootless podman keeps its volumes: the filesystem SeaweedFS writes `/data` into."""
    try:
        completed = subprocess.run(  # noqa: S603 - fixed podman query
            ["podman", "info", "--format", "{{.Store.GraphRoot}}"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except OSError, subprocess.TimeoutExpired:
        return None
    root = completed.stdout.strip()
    return Path(root) if completed.returncode == 0 and root else None


def _free_percent(path: Path) -> float | None:
    try:
        status = os.statvfs(path)
    except OSError:
        return None
    total = status.f_blocks * status.f_frsize
    if not total:
        return None
    return round(100.0 * (status.f_bavail * status.f_frsize) / total, 2)


def _previous_report() -> dict[str, Any] | None:
    """The last line of `report.jsonl`, for the "cursor did not move" check."""
    try:
        lines = REPORT_JSONL.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _health(
    *,
    components: list[support.ComponentState],
    projection: dict[str, Any],
    store: dict[str, Any],
    graph: dict[str, int],
    duplicates: dict[str, list[dict[str, Any]]],
    failures_by_code: dict[str, int],
    quarantined: int,
    previous: dict[str, Any] | None,
) -> dict[str, Any]:
    """Every reason a soak run does not prove anything, as `fail` + one line per problem.

    A soak is evidence only while the stack it measures is the stack that ran: a dead projector, a
    store that refuses a write, a projection that stopped moving, or any failed job makes the
    numbers at the bottom of the report meaningless. Each condition is recorded, never repaired:
    the operator decides.
    """
    problems: list[str] = []
    for item in components:
        if not item.alive:
            problems.append(f"component {item.name} is not running: {item.problem}")
    if store.get("ok") is not True:
        free = store.get("free_percent")
        hint = ""
        if free is not None and free < STORE_MIN_FREE_PERCENT:
            hint = (
                f" (host {store.get('path')} has {free}% free; SeaweedFS marks volumes unwritable"
                f" below {STORE_MIN_FREE_PERCENT}% of the filesystem)"
            )
        problems.append(f"evidence store rejected a write: {store.get('error')}{hint}")
    generation = projection.get("projector_generation")
    cursor = projection.get("projector_cursor")
    limit = int(os.environ.get(LAG_LIMIT_ENV) or DEFAULT_LAG_LIMIT)
    if cursor is None:
        problems.append(
            "projection: no m23-projector#g<N> cursor exists; the projector has never checkpointed"
        )
    else:
        lag = int(projection["projector_lag"])
        if lag > limit:
            problems.append(f"projection: {generation} is {lag} events behind (limit {limit})")
        before = (previous or {}).get("lag") or {}
        if (
            before.get("outbox_head") is not None
            and before.get("projector_cursor") is not None
            and int(projection["outbox_head"]) > int(before["outbox_head"])
            and int(cursor) == int(before["projector_cursor"])
        ):
            problems.append(
                f"projection: {generation} did not advance between two reports while the outbox"
                f" grew from {before['outbox_head']} to {projection['outbox_head']}"
            )
    if graph["asset_mismatch"] or graph["edge_mismatch"]:
        problems.append(
            "graph differs from PostgreSQL: assets {}/{} (graph/PG), open edges {}/{}".format(
                graph["graph_assets"],
                graph["postgres_assets"],
                graph["graph_edges"],
                graph["postgres_open_edges"],
            )
        )
    for name, groups in sorted(duplicates.items()):
        if groups:
            problems.append(f"duplicates {name}: {len(groups)} group(s)")
    if failures_by_code:
        problems.append(
            "jobs FAILED: "
            + ", ".join(f"{code} x{count}" for code, count in sorted(failures_by_code.items()))
        )
    if quarantined:
        problems.append(f"ingestion quarantined {quarantined} record(s)")
    return {"status": "fail" if problems else "pass", "problems": problems}


def _graph_count(cypher: str, column: str) -> int:
    """One count from Neo4j; a graph that cannot be read is reported as -1, not hidden."""
    try:
        rows = support.neo4j_query(cypher)
    except Exception:  # noqa: BLE001 - the soak reports the mismatch, it does not stop
        return -1
    if not rows:
        return 0
    return int(rows[0][column])


def _sum(items: list[dict[str, Any]], key: str, value: str) -> int:
    return sum(int(item["n"]) for item in items if str(item[key]) == value)


def _container_memory() -> dict[str, float]:
    """Resident memory of the dev-stack containers, from `podman stats --no-stream`."""
    try:
        completed = subprocess.run(  # noqa: S603 - fixed podman query
            [
                "podman",
                "stats",
                "--no-stream",
                "--format",
                "{{.Name}}\t{{.MemUsage}}",
                "--filter",
                "label=io.podman.compose.project=aegis-dev",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except OSError, subprocess.TimeoutExpired:
        return {}
    found: dict[str, float] = {}
    for line in completed.stdout.splitlines():
        name, _, usage = line.partition("\t")
        value = usage.split("/")[0].strip()
        for unit, factor in (
            ("GiB", 1024.0),
            ("MiB", 1.0),
            ("KiB", 1 / 1024.0),
            ("B", 1 / 1048576.0),
        ):
            if value.endswith(unit):
                try:
                    found[name.strip()] = round(float(value[: -len(unit)].strip()) * factor, 1)
                except ValueError:
                    break
                break
    return found


def _render(row: dict[str, Any]) -> str:
    memory = row["memory"]["processes"]
    containers = row["memory"]["containers"]
    health = row["health"]
    store = row["store"]
    duplicate_lines = [
        f"  {name}: {len(groups)}" for name, groups in sorted(row["duplicates"].items())
    ]
    return "\n".join(
        [
            f"G1.5c soak - {row['soak_started_at']} -> {row['recorded_at']} ({row['reason']})",
            f"STATUS           {health['status']}",
            *[f"  ! {problem}" for problem in health["problems"]],
            "",
            f"campaigns        {row['campaigns']['total']} ({row['campaigns']['by_status']})",
            f"  created        {row['campaigns']['created']}"
            f"  cancelled by timeout {row['campaigns']['cancelled_by_timeout']}",
            f"  paused because {row['campaigns']['paused_reasons'] or 'none'}",
            f"jobs             {row['jobs']['total']} ({row['jobs']['by_status']})",
            f"  by capability  {row['jobs']['by_capability']}",
            f"  failures       {row['jobs']['failures_by_code'] or 'none'}",
            *[
                f"  failed {sample['job_id']} {sample['capability']} {sample['code']}: "
                f"{sample['detail'][:160]}"
                for sample in row["jobs"]["failure_samples"]
            ],
            f"ingestion        {row['ingestion']['by_state']}",
            f"  quarantined    {row['ingestion']['quarantined_records']} records",
            f"evidence         {row['evidence']['objects']} objects, {row['evidence']['bytes']} B",
            f"  store probe    {'ok' if store['ok'] else 'FAILED: ' + str(store['error'])}"
            f"  host free {store['free_percent']}% (needs >= {store['min_free_percent']}%)",
            f"knowledge        {row['knowledge']}",
            "graph vs PG      assets {}/{} (graph/PG), open edges {}/{}, "
            "asset_mismatch={} edge_mismatch={}".format(
                row["graph"]["graph_assets"],
                row["graph"]["postgres_assets"],
                row["graph"]["graph_edges"],
                row["graph"]["postgres_open_edges"],
                row["graph"]["asset_mismatch"],
                row["graph"]["edge_mismatch"],
            ),
            "projection lag   outbox_head={} {} cursor={} lag={}".format(
                row["lag"].get("outbox_head"),
                row["lag"].get("projector_generation") or "(no projector)",
                row["lag"].get("projector_cursor"),
                row["lag"].get("projector_lag"),
            ),
            f"  consumers      {row['lag'].get('consumers')}",
            "duplicates:",
            *duplicate_lines,
            "memory (RSS, MiB):",
            *[
                f"  {item['name']}: {item['rss_mb']} (pid {item['pid']}, alive={item['alive']}"
                + (f", {item['problem']}" if item["problem"] else "")
                + ")"
                for item in memory
            ],
            "  containers: " + (json.dumps(containers) if containers else "(none)"),
            f"soak-report-errors {len(row['errors'])}",
            *[f"  ! {message}" for message in row["errors"][-10:]],
            "",
        ]
    )


def _log(message: str) -> None:
    print(f"{support.now()} {message}", flush=True)


if __name__ == "__main__":
    sys.exit(main())
