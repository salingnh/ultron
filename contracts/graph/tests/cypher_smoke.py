#!/usr/bin/env python3
"""Neo4j Cypher smoke test for the committed graph templates (CI: scripts/ci/neo4j-smoke.sh).

Executes the real files - contracts/graph/constraints.cypher and
contracts/graph/projector-upserts.cypher - not a copy of them, and asserts the properties
PROGRESS.md claims for them:

  1. constraints.cypher is idempotent: both runs succeed.
  2. The four projector upserts are idempotent: applied twice they keep 2 Asset, 1 Finding,
     1 Evidence and 3 edges.
  3. Closing a relationship interval and opening a new one keeps two SUBDOMAIN_OF windows
     with exactly one current (valid_to IS NULL) edge.
  4. A second Asset with an existing asset_id but another canonical_key is rejected by the
     schema constraint.

Every id, key and hash is generated per run and every assertion is scoped to that run, so
the smoke can run again against the same database (dev stack) and only adds its own
namespaced fixtures instead of deleting anything.

Talks to the HTTP Query API (Neo4j 5.x) with the standard library only.

Environment: NEO4J_URI (http://127.0.0.1:17474), NEO4J_USER (neo4j),
NEO4J_PASSWORD (required), NEO4J_DATABASE (neo4j), NEO4J_READY_TIMEOUT (180).
"""
from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

GRAPH_DIR = Path(__file__).resolve().parents[1]
CONSTRAINTS = GRAPH_DIR / "constraints.cypher"
PROJECTOR = GRAPH_DIR / "projector-upserts.cypher"

BASE = os.environ.get("NEO4J_URI", "http://127.0.0.1:17474").rstrip("/")
USER = os.environ.get("NEO4J_USER", "neo4j")
PASSWORD = os.environ.get("NEO4J_PASSWORD", "")
DATABASE = os.environ.get("NEO4J_DATABASE", "neo4j")
READY_TIMEOUT = int(os.environ.get("NEO4J_READY_TIMEOUT", "180"))

AUTH = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
CHECKS: list[tuple[str, bool, str]] = []

RUN = uuid.uuid4().hex[:12]
SUFFIX = f"smoke-{RUN}.internal.example"
OBSERVED = "2026-11-20T00:00:00Z"
CLOSED_AT = "2026-11-21T00:00:00Z"

CAMPAIGN = str(uuid.uuid4())
JOB = str(uuid.uuid4())
FINDING = str(uuid.uuid4())
EVIDENCE = str(uuid.uuid4())
ROOT_CANONICAL = f"dns:app.{SUFFIX}"
ROOT_ASSET = str(uuid.uuid4())
SUB_CANONICAL = f"dns:www.app.{SUFFIX}"
SUB_ASSET = str(uuid.uuid4())
REL_ONE = str(uuid.uuid4())
REL_TWO = str(uuid.uuid4())
FINGERPRINT = f"fingerprint-{RUN}"
SHA256 = (RUN * 6)[:64]
STORAGE_URI = f"s3://aegis-raw/smoke/{RUN}/evidence.txt"


def request(path: str, body: dict | None = None) -> tuple[int, dict]:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        BASE + path,
        data=data,
        method="GET" if body is None else "POST",
        headers={"Authorization": AUTH, "Content-Type": "application/json",
                 "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return exc.code, {"errors": [{"message": raw.decode(errors="replace")}]}


def wait_ready() -> None:
    deadline = time.monotonic() + READY_TIMEOUT
    while time.monotonic() < deadline:
        try:
            status, _ = request("/")
        except OSError:
            status = 0
        if status == 200:
            return
        time.sleep(2)
    raise SystemExit(f"cypher smoke: FAIL - Neo4j at {BASE} not ready after {READY_TIMEOUT}s")


def run(statement: str, parameters: dict | None = None) -> list[list]:
    """Runs one statement and returns its rows; raises RuntimeError on a query error."""
    status, payload = request(
        f"/db/{DATABASE}/query/v2",
        {"statement": statement, "parameters": parameters or {}},
    )
    errors = payload.get("errors") or []
    if status >= 400 or errors:
        raise RuntimeError(f"{errors or payload} (HTTP {status}) for: {statement}")
    data = payload.get("data") or {}
    return data.get("values") or []


def scalars(statement: str, parameters: dict | None = None) -> list:
    rows = run(statement, parameters)
    return rows[0] if rows else []


def check(description: str, fn) -> None:
    try:
        detail = fn()
        CHECKS.append((description, True, str(detail)))
        print(f"PASS {description}: {detail}")
    except Exception as exc:  # noqa: BLE001 - report every check, then exit non-zero
        CHECKS.append((description, False, str(exc)))
        print(f"FAIL {description}: {exc}")


def statements(path: Path) -> list[str]:
    lines = [line for line in path.read_text(encoding="utf-8").splitlines()
             if not line.lstrip().startswith("//")]
    return [part.strip() for part in "\n".join(lines).split(";") if part.strip()]


def apply_file(path: Path) -> int:
    parts = statements(path)
    for part in parts:
        run(part)
    return len(parts)


def apply_projector(relationship_id: str | None, valid_to: str | None) -> None:
    """Runs the four projector upserts from the committed template, in file order."""
    asset, edge, finding, evidence = statements(PROJECTOR)
    run(asset, {
        "canonical_key": ROOT_CANONICAL, "asset_id": ROOT_ASSET, "kind": "domain",
        "first_seen": OBSERVED, "last_seen": OBSERVED,
        "campaign_id": CAMPAIGN, "revision": 1,
    })
    run(asset, {
        "canonical_key": SUB_CANONICAL, "asset_id": SUB_ASSET, "kind": "domain",
        "first_seen": OBSERVED, "last_seen": OBSERVED,
        "campaign_id": CAMPAIGN, "revision": 1,
    })
    if relationship_id is not None:
        run(edge, {
            "from_asset_id": SUB_ASSET, "to_asset_id": ROOT_ASSET,
            "relationship_id": relationship_id, "observed_at": OBSERVED,
            "valid_from": OBSERVED, "source_job_id": JOB, "confidence": 0.9,
            "campaign_id": CAMPAIGN, "valid_to": valid_to,
        })
    run(finding, {
        "asset_id": SUB_ASSET, "finding_id": FINDING, "fingerprint": FINGERPRINT,
        "rule_id": "rule-1", "title": "Smoke finding", "status": "OPEN",
        "severity": "LOW", "transition_seq": 1, "secret_value": None,
        "observed_at": OBSERVED, "source_job_id": JOB, "confidence": 0.9,
    })
    run(evidence, {
        "finding_id": FINDING, "evidence_id": EVIDENCE, "sha256": SHA256,
        "storage_uri": STORAGE_URI, "source_tool": "smoke",
        "observed_at": OBSERVED, "source_job_id": JOB,
    })


def constraint_runs() -> str:
    total = len(statements(CONSTRAINTS))
    first = apply_file(CONSTRAINTS)
    second = apply_file(CONSTRAINTS)
    if not (first == second == total):
        raise AssertionError(f"applied {first}/{second} statements, expected {total} each run")
    return f"{total} statements applied twice without error"


def projector_twice() -> str:
    apply_projector(REL_ONE, None)
    apply_projector(REL_ONE, None)
    counts = {
        "assets": scalars("MATCH (a:Asset) WHERE $campaign IN a.campaign_ids RETURN count(a)",
                          {"campaign": CAMPAIGN})[0],
        "findings": scalars("MATCH (f:Finding {fingerprint: $fingerprint}) RETURN count(f)",
                            {"fingerprint": FINGERPRINT})[0],
        "evidence": scalars("MATCH (e:Evidence {sha256: $sha256}) RETURN count(e)",
                            {"sha256": SHA256})[0],
        "edges": scalars("MATCH ()-[r]->() WHERE r.source_job_id = $job RETURN count(r)",
                         {"job": JOB})[0],
    }
    expected = {"assets": 2, "findings": 1, "evidence": 1, "edges": 3}
    if counts != expected:
        raise AssertionError(f"{counts} != {expected}")
    return str(counts)


def interval_reopen() -> str:
    # a later observation closes the first window through the same template ...
    apply_projector(REL_ONE, CLOSED_AT)
    # ... and a new observation opens a second window with its own relationship_id
    apply_projector(REL_TWO, None)
    windows, current = scalars(
        "MATCH ()-[r:SUBDOMAIN_OF]->() WHERE r.source_job_id = $job "
        "RETURN count(r), sum(CASE WHEN r.valid_to IS NULL THEN 1 ELSE 0 END)",
        {"job": JOB},
    )
    if (windows, current) != (2, 1):
        raise AssertionError(f"{windows} windows / {current} current, expected 2/1")
    return f"{windows} windows, {current} current"


def duplicate_asset_id_rejected() -> str:
    try:
        run("CREATE (a:Asset {asset_id: $asset_id, canonical_key: $canonical_key, kind: 'domain'})",
            {"asset_id": SUB_ASSET, "canonical_key": f"dns:duplicate.{SUFFIX}"})
    except RuntimeError as exc:
        if "ConstraintValidationFailed" not in str(exc):
            raise
        return "second Asset with an existing asset_id was rejected"
    raise AssertionError("second Asset with an existing asset_id was accepted")


def main() -> int:
    if not PASSWORD:
        raise SystemExit("cypher smoke: FAIL - NEO4J_PASSWORD is not set")
    print(f"cypher smoke: run {RUN} against {BASE} (database {DATABASE})")
    wait_ready()
    check("constraints.cypher is idempotent", constraint_runs)
    check("projector upserts are idempotent", projector_twice)
    check("reopening a relationship keeps one current window", interval_reopen)
    check("asset_id uniqueness is enforced", duplicate_asset_id_rejected)

    failed = [name for name, ok, _ in CHECKS if not ok]
    print(f"cypher smoke: {len(CHECKS) - len(failed)}/{len(CHECKS)} checks PASS")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
