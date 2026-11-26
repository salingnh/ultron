#!/usr/bin/env python3
"""Manual internet smoke of the `internet` network profile (G1.6): one Subfinder job on a domain.

    make internet-smoke DOMAIN=icomm.vn      # after `make run-local` (works, internet profile, broker)

It is manual on purpose: passive Subfinder is the first thing an operator runs against a real
domain, and the owner runs it on property he owns. The script therefore

* refuses a domain that is not on the explicit authorization list (owner, item 61, 2026-11-25:
  `icomm.vn`, `salingnh.com`; widen it with `AEGIS_INTERNET_SMOKE_DOMAINS=a.com,b.com`),
* creates a campaign whose RoE names the `internet` profile with conservative caps (1 parallel job,
  0.5 request/s per host, 1 connection per host, 2 jobs) and records the authorization reference in
  its labels (the API writes it into the `campaign.create` audit row too),
* submits **one** `dns.enumerate_subdomains` (Subfinder) job through M05 - no DNSx, no port scan,
  no fingerprint: those are slice A/B work and come after review,
* dispatches it with M02's own scheduler (the running M06 loop claims and runs it),
* prints the evidence: job status, envelope counts and sample names, and the broker's egress audit
  (allow/deny histogram, profile, authorization) from `.local/m06/jobs/<job>/audit/egress.jsonl`.

Every destination Subfinder reaches must be one the pinned manifest declares (`crt.sh`,
`otx.alienvault.com`); the broker refuses everything else, so a deny-set hit in the audit is a
failure of this smoke, not noise.

`AEGIS_SUBFINDER_PROVIDER_CONFIG` (a path, see .env.example) is optional: it is mounted read-only
into the job so the passive sources can use API keys. Values never appear in argv, the task, a log
line or this output.
"""

from __future__ import annotations

import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts" / "demo"))

import support  # noqa: E402 - the demo scripts' shared helpers, a sibling module

from aegis.m06_runner.authorization import authorization_of  # noqa: E402

#: Owner-authorized first targets (owner message, item 61, 2026-11-25). Widen explicitly, never
#: by accident: this list is the reason the smoke cannot scan a third party's domain.
AUTHORIZED = ("icomm.vn", "salingnh.com")
AUTHORIZATION = "owner, item 61, 2026-11-25"
TERMINAL = {"SUCCEEDED", "FAILED", "CANCELLED"}
ALWAYS_DENY = {
    "DENY_METADATA",
    "DENY_LOOPBACK",
    "DENY_LINK_LOCAL",
    "DENY_UNSPECIFIED",
    "DENY_RESERVED",
    "DENY_MULTICAST",
    "DENY_EMBEDDED_V4",
    "DENY_PLATFORM_NETWORK",
    "DENY_TARGET_DENYLIST",
    "DENY_PRIVATE",
}
#: What the pinned Subfinder manifest declares as `egressSources`; the broker can only open these.
DECLARED_HOSTS = {"crt.sh", "otx.alienvault.com"}

#: Conservative RoE for a first run on a real domain: one job at a time, half a request per second
#: per host, one open connection per host, at most two jobs in the campaign.
#: The RoE's structured authorization: the owner's statement that the targets are theirs. It is
#: required for an internet campaign and copied into every audit line.
AUTHORIZATION_REFERENCE = "owner, item 61, 2026-11-25"

SMOKE_POLICY: dict[str, Any] = {
    "network_profile": "internet",
    "authorization": {
        "owner": "owner",
        "reference": AUTHORIZATION_REFERENCE,
        "date": "2026-11-25",
        "authorized_suffixes": list(AUTHORIZED),
    },
    "max_parallel_jobs": 1,
    "max_duration_hours": 1,
    "rate_limits": {
        "requests_per_second_per_host": 0.5,
        "max_concurrent_connections_per_host": 1,
        "jobs_per_minute": 2,
    },
    "budget": {"max_jobs": 2, "idle_cycles_before_pause": 3},
}
SMOKE_INPUT: dict[str, Any] = {
    "concurrency": 1,
    "rate_limit": 0.5,
    "max_results": 2000,
    "sources": ["crtsh", "otx"],
}


def authorized_domains() -> tuple[str, ...]:
    raw = os.environ.get("AEGIS_INTERNET_SMOKE_DOMAINS", "").strip()
    return tuple(item.strip().lower() for item in raw.split(",") if item.strip()) or AUTHORIZED


def campaign_body(domain: str) -> dict[str, Any]:
    return {
        "name": f"internet smoke {domain} {uuid.uuid4().hex[:6]}",
        "objective": (
            f"Passive subdomain enumeration of {domain} over the internet profile: one Subfinder "
            "job through the egress broker; no active scanning"
        ),
        "targets": {"domains": [domain]},
        "policy": dict(SMOKE_POLICY),
        "labels": {
            "authorization": AUTHORIZATION,
            "network_profile": "internet",
            "purpose": "internet-profile smoke (passive only)",
        },
    }


def _connect(dsn: str) -> Any:
    import psycopg

    return psycopg.connect(dsn)


def submit_job(dsn: str, campaign_id: str, domain: str) -> str:
    from aegis.contracts_gen.capability.job_submit_v2_schema import JobSubmit
    from aegis.m05_registry.registry import PostgresManifestRegistry
    from aegis.m05_registry.service import PostgresJobService
    from aegis.m05_registry.signing import KeyRing

    registry = PostgresManifestRegistry(lambda: _connect(dsn))
    service = PostgresJobService(
        lambda: _connect(dsn), registry=registry, key_ring=KeyRing.from_env()
    )
    outcome = service.submit(
        JobSubmit.model_validate(
            {
                "campaign_id": campaign_id,
                "capability": "dns.enumerate_subdomains",
                "input": {"targets": [domain], **SMOKE_INPUT},
                "rationale": "G1.6 internet profile smoke: passive enumeration only",
            }
        ),
        requested_by={"kind": "operator", "id": "op-local"},
        idempotency_key=f"internet-smoke-{uuid.uuid4().hex}",
    )
    return str(outcome.job_id)


def dispatch(dsn: str, campaign_id: str) -> None:
    """M02's own dispatch step (QUEUED -> VALIDATING); the running M06 loop does the rest."""
    from aegis.m02_orchestrator.scheduler import PostgresScheduler

    plan = PostgresScheduler(lambda: _connect(dsn)).dispatch(campaign_id)
    support.line("dispatch", f"queued={plan.queued} in_flight={plan.in_flight} stop={plan.stop}")


def wait_for_job(connection: Any, job_id: str, timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        row = connection.execute(
            "SELECT status, error, envelope_event_id FROM scan_job WHERE job_id = %s", (job_id,)
        ).fetchone()
        if row is None:
            support.fail(f"job {job_id} disappeared from scan_job")
        if row["status"] != last:
            support.line("job", row["status"], "|", row["error"] or "-")
            last = str(row["status"])
        if row["status"] in TERMINAL:
            return dict(row)
        time.sleep(2.0)
    support.fail(f"job {job_id} did not finish within {timeout:.0f}s (it stays {last})")
    raise AssertionError("unreachable")


def audit_records(job_id: str) -> list[dict[str, Any]]:
    import json

    base = Path(os.environ.get("AEGIS_M06_BASE_DIR") or REPO / ".local" / "m06")
    path = base / "jobs" / job_id / "audit" / "egress.jsonl"
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def envelope(connection: Any, job_id: str) -> dict[str, Any] | None:
    row = connection.execute(
        "SELECT payload FROM ingestion_inbox WHERE dedup_key = %s", (f"job:{job_id}:envelope",)
    ).fetchone()
    return None if row is None else dict(row["payload"])


def authorization_line() -> str:
    """The audit form of `SMOKE_POLICY["authorization"]` — what M06 signs and the broker audits.

    The broker records the *rendered structured authorization* (`owner | reference | date |
    suffixes`), never the free-text campaign label: comparing the audit against
    `AUTHORIZATION = "owner, item 61, 2026-11-25"` failed on a correct run (item 61 follow-up).
    Validating the same object here also fails the smoke loudly if its RoE drifts from what M06
    accepts.
    """
    validated, problem = authorization_of(SMOKE_POLICY["authorization"])
    if validated is None:
        support.fail(f"the smoke RoE authorization is not valid: {problem}")
        raise SystemExit(1)  # support.fail exits; this keeps a type checker from guessing
    return validated.reference_line()


def check_audit(records: list[dict[str, Any]]) -> dict[str, int]:
    histogram: dict[str, int] = {}
    for record in records:
        reason = str(record.get("reason"))
        histogram[reason] = histogram.get(reason, 0) + 1
    support.require(records, "the broker wrote no egress audit line: the job never used the broker")
    support.require(
        {str(record.get("network_profile")) for record in records} == {"internet"},
        "an audit line does not carry network_profile=internet",
    )
    expected = authorization_line()
    support.require(
        {str(record.get("authorization")) for record in records} == {expected},
        f"the audit line does not carry the signed authorization ({expected!r})",
    )
    denied = {reason for reason in histogram if reason in ALWAYS_DENY}
    support.require(
        not denied, f"the broker denied an always-deny destination: {sorted(denied)}"
    )
    allowed_hosts = {
        str(record.get("host")) for record in records if record.get("decision") == "allow"
    }
    outside = allowed_hosts - DECLARED_HOSTS
    support.require(
        not outside,
        f"the broker opened a host the pinned manifest does not declare: {sorted(outside)}",
    )
    return histogram


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: make internet-smoke DOMAIN=<domain or subdomain>", file=sys.stderr)
        return 2
    domain = args[0].strip().lower().rstrip(".")
    allowed = authorized_domains()
    if not any(domain == item or domain.endswith("." + item) for item in allowed):
        print(
            f"refusing {domain!r}: only authorized targets ({', '.join(allowed)}) may be scanned; "
            "widen with AEGIS_INTERNET_SMOKE_DOMAINS only for property you own",
            file=sys.stderr,
        )
        return 2

    support.load_demo_env()
    support.section("0. stack")
    alive = {item.name for item in support.processes() if item.alive}
    support.require("api" in alive and "m06" in alive, "api/m06 are not running: make run-local")
    support.require(
        os.environ.get("AEGIS_M06_INTERNET_PROFILE"),
        "AEGIS_M06_INTERNET_PROFILE is not set: restart `make run-local` on this revision",
    )
    support.require(
        os.environ.get("AEGIS_M06_BROKER_IMAGE"),
        "AEGIS_M06_BROKER_IMAGE is not set: the internet profile needs the broker image "
        "(make broker-image / make run-local)",
    )
    support.line("api", os.environ["AEGIS_API_URL"])
    support.line("target", domain)
    support.line("authorization", authorization_line())
    support.line("broker image", os.environ["AEGIS_M06_BROKER_IMAGE"])
    support.line(
        "provider config",
        "set (path only, mounted read-only)"
        if os.environ.get("AEGIS_SUBFINDER_PROVIDER_CONFIG")
        else "unset (keyless sources)",
    )

    support.section("1. campaign (POST /campaigns, internet profile, conservative caps)")
    created = support.api(
        "POST",
        "/api/v2/campaigns",
        payload=campaign_body(domain),
        token=support.operator_token(),
        headers={"Idempotency-Key": f"internet-smoke-{uuid.uuid4()}"},
    )
    campaign_id = str(created["campaign_id"])
    support.line("campaign_id", campaign_id)
    support.line("policy", str(created.get("policy_version")))
    support.line("policy body", SMOKE_POLICY)

    dsn = os.environ["AEGIS_PG_DSN"]
    support.section("2. one Subfinder job through M05, dispatched by M02")
    job_id = submit_job(dsn, campaign_id, domain)
    support.line("job_id", job_id)
    dispatch(dsn, campaign_id)

    timeout = float(os.environ.get("SMOKE_TIMEOUT_SECONDS") or 900)
    connection = support.pg()
    try:
        support.section("3. run (M06: job network -> broker -> passive sources)")
        job = wait_for_job(connection, job_id, timeout)
        support.require(
            job["status"] == "SUCCEEDED",
            f"job ended {job['status']}: {job.get('error') or '-'} (logs: .local/m06.log)",
        )
        support.line("envelope_event_id", job.get("envelope_event_id"))
        body = envelope(connection, job_id)
        support.require(body is not None, "the job has no ingested envelope")
        results = body.get("results") or {}
        names = sorted(
            str(item.get("key") or item.get("name") or item)
            for item in results.get("assets") or []
        )
        support.line("status", body.get("status"))
        support.line(
            "results",
            f"assets={len(results.get('assets') or [])} "
            f"observations={len(results.get('observations') or [])} "
            f"relationships={len(results.get('relationships') or [])}",
        )
        for name in names[:10]:
            support.line("asset", name)

        support.section("4. egress audit (broker, .local/m06/jobs/<job>/audit/egress.jsonl)")
        records = audit_records(job_id)
        histogram = check_audit(records)
        support.line("decisions", histogram)
        hosts = sorted({str(record.get("host")) for record in records})
        support.line("hosts", ", ".join(hosts))
    finally:
        connection.close()

    support.section("result")
    support.line("PASS - one passive Subfinder job on the internet profile, broker-enforced")
    support.line("campaign", f"{campaign_id} (left for inspection; POST /campaigns/{{id}}/cancel)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
