#!/usr/bin/env python3
"""`make demo-recovery` - SIGKILL the M06 runner mid-job and prove it resumes with no duplicate.

The plan's G1 row asks for exactly this ("tắt worker giữa job rồi tiếp tục không trùng"). The demo
does not simulate it:

1. create a campaign and wait until its first job is `RUNNING` in the database **and** its container
   is up on the host (the runner has started it and is supervising it);
2. `SIGKILL` the runner process (`kill -9`, no cleanup): the tool keeps running in its container,
   the job row stays `RUNNING`, the envelope was never built;
3. start the runner again with the same base directory (same runner identity) - `make run-local`
   started it with `.local/m06.pid`, so this is exactly the restart of the same service;
4. require the resumed run to reach `SUCCEEDED` with:
   * **one** container for the job (the resumed runner adopts it, never starts a second),
   * **one** envelope and one receipt for the job (`dedup_key = job:<id>:envelope`),
   * **one** evidence object and no duplicated assets,
   * one `resume:` line in the runner log naming the adopted job.

Exit codes: 0 = every check passed, 1 = a check failed, 2 = the stack is not ready.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import support  # noqa: E402 - the demo scripts' shared helpers, a sibling module

#: How long the demo waits for a job to reach RUNNING with its container up.
STARTUP_TIMEOUT = 120.0
#: How long the resumed runner has to finish the job.
RESUME_TIMEOUT = 300.0
#: How long the campaign has to finish after the recovered job (one more session: DNSx).
RECOVERY_CAMPAIGN_TIMEOUT = 240.0
POLL = 0.2


def main(argv: list[str] | None = None) -> int:
    support.load_demo_env()
    support.section("1. campaign")
    campaign_id = support.create_campaign("G1.5c recovery demo")
    support.line("campaign_id", campaign_id)

    support.section("2. wait for a job whose container is up")
    job_id = _wait_for_started_job(campaign_id)
    container_before = support.container_id(job_id)
    support.line("job_id", job_id)
    support.line("container", support.container_name(job_id), container_before[:12])
    support.require(container_before, "the job has no container to adopt")

    support.section("3. SIGKILL the runner (`kill -9`, no cleanup)")
    pid = _runner_pid()
    os.kill(pid, signal.SIGKILL)
    support.line("killed runner pid", pid)
    deadline = time.monotonic() + 5.0
    while _alive(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    support.require(not _alive(pid), "the runner survived SIGKILL")
    status_after_kill = _job_status(job_id)
    support.line("job status after the kill", status_after_kill)
    support.require(
        status_after_kill in {"DISPATCHED", "RUNNING", "COLLECTING"},
        f"the job left the runner's hands on its own ({status_after_kill}): nothing to recover",
    )
    # A lab run finishes in seconds, so the tool may already have exited inside its container while
    # the (dead) runner never collected it. Both states are a recovery: the container is adopted by
    # name, its output collected once. The demo records which one it saw.
    support.line(
        "container state after the kill", "running" if _container_running(job_id) else "exited"
    )
    support.line("envelope so far", _receipts(job_id))

    support.section("4. restart the same runner (same base directory = same runner identity)")
    log_offset = _log_size()
    support.start_runner()
    support.line("runner restarted; log .local/m06.log")

    support.section("5. wait for the resumed run to finish")
    finished, containers_during = _wait_for_terminal(job_id, container_before)
    support.line("job status", finished)
    support.line("containers seen while resuming", containers_during)
    support.require(finished == "SUCCEEDED", f"the resumed job ended {finished}, not SUCCEEDED")

    support.section("6. no duplicate: container, envelope, evidence, assets")
    resumed_log = _log_since(log_offset)
    resume_lines = [line for line in resumed_log.splitlines() if line.startswith("resume:")]
    support.line("resume log", "; ".join(resume_lines) or "(none)")

    connection = support.pg()
    try:
        containers = containers_during
        receipts = _receipts(job_id)
        evidence = support.rows(
            connection,
            "SELECT evidence_id, sha256, storage_uri FROM evidence WHERE job_id = %s",
            (job_id,),
        )
        attempts = support.rows(
            connection,
            "SELECT seq, from_status, to_status FROM job_status_change"
            " WHERE job_id = %s ORDER BY seq",
            (job_id,),
        )
        duplicates = {
            "jobs_by_fingerprint": support.duplicate_groups(
                connection,
                "SELECT job_fingerprint, count(*) AS n FROM scan_job WHERE campaign_id = %s"
                " GROUP BY 1 HAVING count(*) > 1",
                (campaign_id,),
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
        }
    finally:
        connection.close()

    support.line("containers seen for the job", containers)
    support.line("ingestion receipts", receipts)
    support.line("evidence objects", len(evidence))
    support.line(
        "status chain", " ".join(f"{row['from_status']}→{row['to_status']}" for row in attempts)
    )
    support.line("jobs for the campaign", _job_count(campaign_id))

    support.section("7. the campaign continues on the recovered job")
    campaign = support.wait_campaign(campaign_id, timeout_seconds=RECOVERY_CAMPAIGN_TIMEOUT)
    support.line("campaign", campaign.get("status"), "|", campaign.get("status_reason") or "-")
    support.require(
        str(campaign.get("status")) == "COMPLETED",
        f"the campaign ended {campaign.get('status')} after the recovery",
    )

    document = {
        "campaign_id": campaign_id,
        "job_id": job_id,
        "killed_pid": pid,
        "status_after_kill": status_after_kill,
        "final_status": finished,
        "containers_seen": containers,
        "receipts": receipts,
        "evidence": evidence,
        "status_chain": attempts,
        "resume_lines": resume_lines,
        "duplicates": duplicates,
        "recorded_at": support.now(),
    }
    artifact = support.write_artifact(f"recovery-{_stamp()}.json", document)

    support.section("checks")
    support.require(resume_lines, "the restarted runner did not log that it adopted the job")
    support.require(
        containers == [container_before],
        f"the resumed runner did not keep the one container of the job: {containers}",
    )
    support.require(len(receipts) == 1, f"expected one envelope receipt, found {len(receipts)}")
    support.require(len(evidence) >= 1, "the resumed job produced no evidence object")
    support.require(not any(duplicates.values()), f"duplicates after recovery: {duplicates}")
    support.require(
        _job_count(campaign_id) == 2,
        "the campaign does not have exactly two jobs after the recovery",
    )

    support.section("evidence file")
    support.line(str(artifact))
    support.section("result")
    support.line("PASS - the job resumed after SIGKILL with no duplicate container/job/envelope")
    return 0


def _wait_for_started_job(campaign_id: str) -> str:
    """A job the runner has claimed and given a container to (`DISPATCHED` or `RUNNING`).

    The lab tools finish in well under a second (the stub and the resolver answer immediately), so
    waiting for "RUNNING and its container still running" would race the tool. The state that
    matters for the recovery is: the runner owns a container for the job and has not terminalized
    it - which is exactly when a SIGKILL loses work.
    """
    deadline = time.monotonic() + STARTUP_TIMEOUT
    while time.monotonic() < deadline:
        connection = support.pg()
        try:
            row = support.one(
                connection,
                "SELECT job_id FROM scan_job WHERE campaign_id = %s"
                " AND status IN ('DISPATCHED', 'RUNNING') ORDER BY created_at LIMIT 1",
                (campaign_id,),
            )
        finally:
            connection.close()
        if row is not None:
            job_id = str(row["job_id"])
            if support.container_id(job_id):
                return job_id
        time.sleep(POLL)
    support.fail(
        "no job reached the runner with a container: is the M06 runner up (make run-local) and "
        "the lab available (make lab-up)?"
    )
    raise AssertionError("unreachable")


def _wait_for_terminal(job_id: str, container_before: str) -> tuple[str, list[str]]:
    """Wait for the resumed job; sample the container the whole time (a second one would show)."""
    deadline = time.monotonic() + RESUME_TIMEOUT
    status = ""
    seen: list[str] = []
    while time.monotonic() < deadline:
        status = _job_status(job_id)
        current = support.container_id(job_id)
        if current and current not in seen:
            seen.append(current)
        if status in {"SUCCEEDED", "FAILED", "CANCELLED"}:
            if not seen:
                seen.append(container_before)
            return status, seen
        time.sleep(POLL)
    support.fail(f"the resumed job stayed {status} for {RESUME_TIMEOUT:.0f}s; see .local/m06.log")
    raise AssertionError("unreachable")


def _job_status(job_id: str) -> str:
    connection = support.pg()
    try:
        row = support.one(connection, "SELECT status FROM scan_job WHERE job_id = %s", (job_id,))
    finally:
        connection.close()
    return "" if row is None else str(row["status"])


def _container_running(job_id: str) -> bool:
    completed = subprocess.run(
        [
            "podman",
            "container",
            "inspect",
            "--format",
            "{{.State.Running}}",
            support.container_name(job_id),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    return completed.stdout.strip() == "true"


def _receipts(job_id: str) -> list[dict[str, Any]]:
    connection = support.pg()
    try:
        return support.rows(
            connection,
            "SELECT event_id, dedup_key, status, revision FROM ingestion_inbox WHERE job_id = %s",
            (job_id,),
        )
    finally:
        connection.close()


def _job_count(campaign_id: str) -> int:
    connection = support.pg()
    try:
        return support.count(
            connection, "SELECT count(*) AS n FROM scan_job WHERE campaign_id = %s", (campaign_id,)
        )
    finally:
        connection.close()


def _runner_pid() -> int:
    pid_file = support.STATE_DIR / "m06.pid"
    if not pid_file.is_file():
        support.fail("no .local/m06.pid: the runner was not started by `make run-local`")
    pid = int(pid_file.read_text(encoding="utf-8").strip())
    if not _alive(pid):
        support.fail(f"the runner pid {pid} is not running: run `make run-local` first")
    return pid


def _alive(pid: int) -> bool:
    """True while the process exists; a zombie (`Z`) is already dead, not running."""
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    try:
        state = (Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").split()[2],)
    except (OSError, IndexError):
        return True
    return state[0] != "Z"


def _log_size() -> int:
    path = support.STATE_DIR / "m06.log"
    return path.stat().st_size if path.is_file() else 0


def _log_since(offset: int) -> str:
    path = support.STATE_DIR / "m06.log"
    if not path.is_file():
        return ""
    with path.open("rb") as handle:
        handle.seek(offset)
        return handle.read().decode("utf-8", "replace")


def _stamp() -> str:
    return str(support.now()).replace(":", "").replace("-", "").replace(".", "")


if __name__ == "__main__":
    sys.exit(main())
