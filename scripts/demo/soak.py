#!/usr/bin/env python3
"""`make soak-start` - the shortened G1 soak (24-48 h by default 24) at a low steady rate.

What it does, one round every `SOAK_INTERVAL_SECONDS` (default 180 s):

* creates one campaign on the lab (`POST /campaigns`, the same body as `demo-g1`);
* keeps at most `SOAK_MAX_ACTIVE` campaigns open and lets stuck ones be recorded, not fixed: a
  campaign still open after `SOAK_CAMPAIGN_TIMEOUT_SECONDS` is cancelled through the API (that is
  the operator's own cancel path, which also exercises it) and counted as a failure;
* every `SOAK_REPORT_SECONDS` (default 300 s) appends one JSON line to `.local/soak/report.jsonl`
  and rewrites `.local/soak/report.txt`, with: campaigns/jobs by status, the tool and ingestion
  error counts (with the first error's code), evidence bytes, knowledge counts, how far the M23
  projection lags the outbox, the duplicate counts the G1 gate asks for, and the resident memory of
  the stack processes;
* stops when `SOAK_HOURS` is up (default 24) or when asked with SIGTERM, and writes a final report.

`make soak-start` runs this detached in `.local/soak/` (pid + log); `make soak-stop` stops it. The
report is the deliverable - the soak is evidence for the gate, not a gate: `make demo-g1` is.
"""

from __future__ import annotations

import json
import os
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

DEFAULT_HOURS = 24.0
DEFAULT_INTERVAL = 180.0
DEFAULT_REPORT_EVERY = 300.0
DEFAULT_ACTIVE = 2
DEFAULT_CAMPAIGN_TIMEOUT = 900.0


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
            if len(active) < max_active and time.monotonic() < deadline:
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
                    )
                    _log(
                        "soak: report "
                        + f"campaigns={row['campaigns']['total']} jobs={row['jobs']['total']} "
                        + f"failures={row['jobs']['by_status'].get('FAILED', 0)} "
                        + f"duplicates={sum(len(v) for v in row['duplicates'].values())}"
                    )
                except Exception as error:  # noqa: BLE001
                    errors.append(f"report: {type(error).__name__}: {error}")
                    _log(f"soak: report failed: {error}")
                next_report = time.monotonic() + report_every
            time.sleep(min(5.0, max(0.2, interval - (time.monotonic() - now))))
    finally:
        signal.signal(signal.SIGTERM, previous)
        row = _report(
            started=started,
            deadline_reached=time.monotonic() >= deadline,
            created=created,
            cancelled=cancelled,
            rounds=rounds,
            errors=errors,
        )
        SUMMARY.write_text(json.dumps(row, indent=1, sort_keys=True, default=str) + "\n", "utf-8")
        _log(f"soak: finished ({row['reason']}); report {REPORT_TXT}")
    return 0


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
) -> dict[str, Any]:
    connection = support.pg()
    try:
        row = _collect(connection, started, deadline_reached, created, cancelled, rounds, errors)
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
    lag = support.rows(
        connection,
        """
        SELECT (SELECT coalesce(max(seq), 0) FROM outbox_event) AS outbox_head,
               (SELECT coalesce(max(last_seq), 0) FROM consumer_cursor) AS projector_cursor,
               (SELECT coalesce(max(revision), 0) FROM graph_revision) AS revision_head
        """,
    )
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
    process_rows = [
        {
            "name": item.name,
            "pid": item.pid,
            "alive": item.alive,
            "rss_mb": round(support.rss_kb(item.pid) / 1024.0, 1),
        }
        for item in support.processes()
        if item.name in {"api", "mcp", "m02-worker", "m02-dispatcher", "m23", "m06"}
    ]
    containers = _container_memory()
    return {
        "recorded_at": support.now(),
        "soak_started_at": started,
        "reason": (
            "hours elapsed" if deadline_reached else "stopped (SIGTERM or .local/soak/stop)"
        ),
        "rounds": rounds,
        "campaigns": {
            "created": created,
            "cancelled_by_timeout": cancelled,
            "by_status": {str(item["status"]): int(item["n"]) for item in campaigns},
            "total": sum(int(item["n"]) for item in campaigns),
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
            "failures_by_code": {str(item["code"]): int(item["n"]) for item in job_errors},
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
        "lag": {key: int(value) for key, value in (lag[0] if lag else {}).items()},
        "duplicates": duplicates,
        "memory": {"processes": process_rows, "containers": containers},
        "errors": errors[-50:],
    }


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
    except (OSError, subprocess.TimeoutExpired):
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
    duplicate_lines = [
        f"  {name}: {len(groups)}" for name, groups in sorted(row["duplicates"].items())
    ]
    return "\n".join(
        [
            f"G1.5c soak - {row['soak_started_at']} -> {row['recorded_at']} ({row['reason']})",
            "",
            f"campaigns        {row['campaigns']['total']} ({row['campaigns']['by_status']})",
            f"  created        {row['campaigns']['created']}"
            f"  cancelled by timeout {row['campaigns']['cancelled_by_timeout']}",
            f"jobs             {row['jobs']['total']} ({row['jobs']['by_status']})",
            f"  by capability  {row['jobs']['by_capability']}",
            f"  failures       {row['jobs']['failures_by_code'] or 'none'}",
            f"ingestion        {row['ingestion']['by_state']}",
            f"  quarantined    {row['ingestion']['quarantined_records']} records",
            f"evidence         {row['evidence']['objects']} objects, {row['evidence']['bytes']} B",
            f"knowledge        {row['knowledge']}",
            "projection lag   outbox_head={} projector_cursor={} revision_head={}".format(
                row["lag"].get("outbox_head"),
                row["lag"].get("projector_cursor"),
                row["lag"].get("revision_head"),
            ),
            "duplicates:",
            *duplicate_lines,
            "memory (RSS, MiB):",
            *[
                f"  {item['name']}: {item['rss_mb']} (pid {item['pid']}, alive={item['alive']})"
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
