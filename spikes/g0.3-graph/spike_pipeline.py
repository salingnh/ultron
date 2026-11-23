"""G0.3b scenario 2: outbox -> Neo4j projection, rebuild, allocator measurement.

Writers produce real contract rows (asset, asset_campaign, relationship, finding,
evidence, graph_revision, outbox_event) in one PostgreSQL transaction per event, so the
0008 allocator is exercised exactly as S1.3 locked it. A single projector consumes
`aegis.outbox_batch` at or below the published watermark and applies
contracts/graph/projector-upserts.cypher verbatim; the template's input properties come
from PostgreSQL, as graph/model.md specifies (the projector reads the corresponding PG
row, the event payload identifies it).

Measured:
  * producer throughput and publish/project lag under 100 concurrent writers
  * allocator comparisons: transactional counter (0008) vs nextval under the same lock
  * watermark refresh: try-lock (0008) vs blocking exclusive lock (spike-only variant)
  * crash-window redelivery (Neo4j committed, PG checkpoint lost): idempotency
  * full rebuild under a new consumer generation `m23-projector#g2` from cursor 0, and
    equality with the original by metadata/revision/evidence reconciliation
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field

import psycopg
from psycopg.types.json import Jsonb

from spike_common import (
    SQL_DIR,
    apply_constraints,
    apply_sql_file,
    apply_batch_retry,
    connect,
    graph_snapshot,
    iso,
    load_cypher_statements,
    median,
    neo4j_driver,
    run_cypher_retry,
    sha256_hex,
    snapshot_diff,
    uid,
    utc_now,
    wipe_graph,
    RunDatabase,
)

CAMPAIGNS = 5
ROOT_DOMAINS = [f"root{i}.spike-a.example" for i in range(CAMPAIGNS)]
HOT_DOMAINS = [f"hot{i:02d}.spike-a.example" for i in range(60)]
DEFAULT_BATCH = 100


def ckey(domain: str) -> str:
    return f"dns:{domain}"


def aid(domain: str) -> "uuid.UUID":
    return uid("asset:" + ckey(domain))


# ---------------------------------------------------------------------------
# PostgreSQL seed: campaigns, jobs, seed-target assets
# ---------------------------------------------------------------------------
def seed_contract_rows(conn: psycopg.Connection) -> None:
    for i in range(CAMPAIGNS):
        cid, sid, pv = uid(f"campaign:{i}"), uid(f"scope:{i}"), f"roe-{i + 1}"
        actor = Jsonb({"kind": "operator", "id": "g03b-spike"})
        with conn.transaction():
            conn.execute(
                "INSERT INTO campaign (campaign_id, name, objective, current_policy_version, scope_id, created_by) "
                "VALUES (%s,%s,'G0.3b graph spike',%s,%s,%s) ON CONFLICT DO NOTHING",
                (cid, f"g03b campaign {i}", pv, sid, actor),
            )
            conn.execute(
                # 0009 requires new snapshots to be roe-policy.v2 configuration.
                "INSERT INTO policy_snapshot (policy_version, campaign_id, policy, policy_hash, created_by) "
                "VALUES (%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                (pv, cid, Jsonb({"max_parallel_jobs": 10, "max_duration_hours": 24}), sha256_hex(pv), actor),
            )
            conn.execute(
                "INSERT INTO scope_snapshot (scope_id, campaign_id, targets) VALUES (%s,%s,%s) ON CONFLICT DO NOTHING",
                (sid, cid, Jsonb({"targets": [ROOT_DOMAINS[i]]})),
            )
            conn.execute(
                "INSERT INTO campaign_target (target_id, scope_id, kind, raw_value, canonical_key) "
                "VALUES (%s,%s,'domain',%s,%s) ON CONFLICT DO NOTHING",
                (uid(f"target:{i}"), sid, ROOT_DOMAINS[i], ckey(ROOT_DOMAINS[i])),
            )
            conn.execute(
                "INSERT INTO policy_decision (decision_id, campaign_id, capability, provider, targets, input, "
                "decision, rationale, requested_by, policy_version, scope_id, idempotency_key, trace_id) "
                "VALUES (%s,%s,'dns/enumerate-subdomains','subfinder',%s,'{}'::jsonb,'approved','spike',%s,%s,%s,%s,%s) "
                "ON CONFLICT DO NOTHING",
                (uid(f"decision:{i}"), cid, [ROOT_DOMAINS[i]], actor, pv, sid, f"g03b-decision-{i}", os.urandom(16).hex()),
            )
            conn.execute(
                "INSERT INTO scan_job (job_id, campaign_id, decision_id, capability, provider, provider_version, "
                "adapter_version, image_digest, manifest_sha256, scan_cycle, job_fingerprint, policy_version, scope_id, "
                "input, targets, target_refs, requested_by, rationale, trace_id) "
                "VALUES (%s,%s,%s,'dns/enumerate-subdomains','subfinder','2.17.0','subfinder@2.17.0',%s,%s,%s,%s,%s,%s,"
                "'{}'::jsonb,%s,%s,%s,'spike',%s) ON CONFLICT DO NOTHING",
                (
                    uid(f"job:{i}"), cid, uid(f"decision:{i}"),
                    "sha256:" + sha256_hex(f"image:{i}"), sha256_hex(f"manifest:{i}"), uid(f"cycle:{i}"),
                    sha256_hex(f"fingerprint:{i}"), pv, sid, [ROOT_DOMAINS[i]],
                    Jsonb([{"seed_id": str(uid(f"target:{i}"))}]), actor, os.urandom(16).hex(),
                ),
            )
            for root in ROOT_DOMAINS:
                conn.execute(
                    "INSERT INTO asset (asset_id, canonical_key, kind, first_seen, last_seen, first_job_id) "
                    "VALUES (%s,%s,'domain',%s,%s,%s) ON CONFLICT (canonical_key) DO NOTHING",
                    (aid(root), ckey(root), utc_now(), utc_now(), uid(f"job:{i}")),
                )
                conn.execute(
                    "INSERT INTO asset_campaign (asset_id, campaign_id, first_seen, first_job_id) "
                    "VALUES (%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                    (aid(root), cid, utc_now(), uid(f"job:{i}")),
                )


def project_seed_assets(conn: psycopg.Connection, driver, statements: list[str]) -> int:
    """Project seed-target assets: they exist before any scan, so no outbox event drives them."""
    rows = conn.execute(
        "SELECT a.asset_id, a.canonical_key, a.kind, a.first_seen, a.last_seen, "
        "       array_agg(ac.campaign_id ORDER BY ac.first_seen, ac.campaign_id) AS campaigns "
        "FROM asset a JOIN asset_campaign ac USING (asset_id) "
        "WHERE a.canonical_key = ANY(%s) GROUP BY a.asset_id, a.canonical_key, a.kind, a.first_seen, a.last_seen",
        ([ckey(r) for r in ROOT_DOMAINS],),
    ).fetchall()
    ops = 0
    for row in rows:
        canonical_key = row[1]
        for campaign_id in row[5]:
            params = {
                "canonical_key": canonical_key,
                "asset_id": str(row[0]),
                "kind": row[2],
                "first_seen": iso(row[3]),
                "last_seen": iso(row[4]),
                "campaign_id": str(campaign_id),
                "revision": 0,
            }
            run_cypher_retry(driver, statements[0], params)
            ops += 1
    return ops


# ---------------------------------------------------------------------------
# Producers: one PostgreSQL transaction per event (the C04 writer transaction)
# ---------------------------------------------------------------------------
class _Rollback(Exception):
    def __init__(self, seq: int):
        super().__init__(f"deliberate rollback of publication number {seq}")
        self.seq = seq


@dataclass
class LoadConfig:
    writers: int = 100
    events_per_writer: int = 20


@dataclass
class WriterStats:
    committed: int = 0
    max_seq: int = 0
    rolled_back_seq: int | None = None
    started: float = 0.0
    finished: float = 0.0


def _produce(conn: psycopg.Connection, writer_id: int, cfg: LoadConfig, barrier: threading.Barrier) -> WriterStats:
    stats = WriterStats()
    campaign_i = writer_id % CAMPAIGNS
    cid, jid = uid(f"campaign:{campaign_i}"), uid(f"job:{campaign_i}")
    barrier.wait()
    stats.started = time.monotonic()
    for j in range(cfg.events_per_writer):
        now = utc_now()
        hot = j % 10 < 6
        domain = HOT_DOMAINS[(writer_id * 7 + j) % len(HOT_DOMAINS)] if hot else f"w{writer_id:03d}-{j:04d}.spike-a.example"
        asset_id = aid(domain)
        parent_id = aid(ROOT_DOMAINS[(writer_id + j) % CAMPAIGNS])
        reopen = (writer_id + j) % 17 == 0
        finding = not hot  # one finding per unique asset; repeated findings would repeat dedup_key
        do_rollback = writer_id == 0 and j == 0
        try:
            with conn.transaction():
                # asset_id and canonical_key are both unique, and concurrent writers send both:
                # ON CONFLICT (canonical_key) lets the asset_pkey conflict escape (the arbiter is
                # only canonical_key), so insert-ignore then update is the race-free form.
                conn.execute(
                    "INSERT INTO asset (asset_id, canonical_key, kind, first_seen, last_seen, first_job_id) "
                    "VALUES (%s,%s,'domain',clock_timestamp(),clock_timestamp(),%s) ON CONFLICT DO NOTHING",
                    (asset_id, ckey(domain), jid),
                )
                conn.execute(
                    "UPDATE asset SET last_seen = greatest(last_seen, clock_timestamp()) WHERE canonical_key = %s",
                    (ckey(domain),),
                )
                conn.execute(
                    "INSERT INTO asset_campaign (asset_id, campaign_id, first_seen, first_job_id) "
                    "VALUES (%s,%s,clock_timestamp(),%s) ON CONFLICT DO NOTHING",
                    (asset_id, cid, jid),
                )
                if reopen:
                    # valid_from is taken from the DB clock at insert; close with a value that
                    # cannot precede it (0001 raises if valid_to < valid_from).
                    conn.execute(
                        "UPDATE relationship SET valid_to = greatest(clock_timestamp(), valid_from) "
                        "WHERE type = 'SUBDOMAIN_OF' AND from_asset_id = %s AND to_asset_id = %s "
                        "AND valid_to IS NULL",
                        (asset_id, parent_id),
                    )
                conn.execute(
                    "INSERT INTO relationship (relationship_id, type, from_asset_id, to_asset_id, observed_at, "
                    "valid_from, valid_to, source_job_id, confidence, campaign_id) "
                    "VALUES (%s,'SUBDOMAIN_OF',%s,%s,clock_timestamp(),clock_timestamp(),NULL,%s,0.9,%s) "
                    "ON CONFLICT DO NOTHING",
                    (uid(f"rel:{asset_id}:{parent_id}:{j}"), asset_id, parent_id, jid, cid),
                )
                finding_id = None
                evidence_id = None
                if finding:
                    finding_id = uid(f"finding:{asset_id}")
                    evidence_id = uid(f"evidence:{asset_id}")
                    conn.execute(
                        "INSERT INTO finding (finding_id, fingerprint, asset_id, rule_id, category, title, "
                        "vulnerability_ids, location, status, severity, transition_seq, confidence, first_seen, "
                        "last_seen, first_job_id, first_campaign_id) "
                        "VALUES (%s,%s,%s,'spike-exposure','exposure','spike exposure',ARRAY[]::text[],'{}'::jsonb,"
                        "'CANDIDATE','HIGH',1,0.9,%s,%s,%s,%s) ON CONFLICT (finding_id) DO NOTHING",
                        (finding_id, sha256_hex(f"finding:{finding_id}"), asset_id, now, now, jid, cid),
                    )
                    conn.execute(
                        "INSERT INTO evidence (evidence_id, sha256, storage_uri, campaign_id, job_id, size_bytes, "
                        "media_type, kind, classification, source_tool) "
                        "VALUES (%s,%s,%s,%s,%s,256,'application/json','raw_output','INTERNAL','spike') "
                        "ON CONFLICT (evidence_id) DO NOTHING",
                        (
                            evidence_id, sha256_hex(f"evidence:{finding_id}:{j}"),
                            f"s3://evidence/{cid}/{jid}/{sha256_hex(f'evidence:{finding_id}:{j}')}",
                            cid, jid,
                        ),
                    )
                revision = conn.execute(
                    "INSERT INTO graph_revision (campaign_id, causal_job_id) VALUES (%s,%s) RETURNING revision",
                    (cid, jid),
                ).fetchone()[0]
                seq = conn.execute(
                    "INSERT INTO outbox_event (event_id, type, producer, dedup_key, campaign_id, payload, trace, occurred_at) "
                    "VALUES (%s,'asset.discovered.v2','M27',%s,%s,%s,%s,%s) RETURNING seq",
                    (
                        uid(f"event:{writer_id}:{j}"), f"{asset_id}:{revision}", cid,
                        Jsonb({
                            "asset_id": str(asset_id),
                            "canonical_key": ckey(domain),
                            "kind": "domain",
                            "revision": int(revision),
                            "causal_job_id": str(jid),
                            "campaign_id": str(cid),
                            "discovered_from": [ckey(ROOT_DOMAINS[(writer_id + j) % CAMPAIGNS])],
                            "first_seen": iso(now),
                        }),
                        Jsonb({"trace_id": os.urandom(16).hex()}), now,
                    ),
                ).fetchone()[0]
                if finding:
                    conn.execute(
                        "INSERT INTO outbox_event (event_id, type, producer, dedup_key, campaign_id, payload, trace, occurred_at) "
                        "VALUES (%s,'finding.changed.v2','M20',%s,%s,%s,%s,%s)",
                        (
                            uid(f"fev:{writer_id}:{j}"), f"{finding_id}:1", cid,
                            Jsonb({
                                "finding_id": str(finding_id), "transition_seq": 1, "asset_id": str(asset_id),
                                "campaign_id": str(cid), "old_status": None, "new_status": "CANDIDATE",
                                "old_severity": None, "new_severity": "HIGH", "reason": "spike",
                                "evidence_ref": str(evidence_id),
                                "changed_by": {"kind": "module", "id": "M20"}, "cause": "scan",
                                "changed_at": iso(now),
                            }),
                            Jsonb({"trace_id": os.urandom(16).hex()}), now,
                        ),
                    )
                if do_rollback:
                    raise _Rollback(int(seq))
        except _Rollback as rolled:
            stats.rolled_back_seq = rolled.seq
            continue
        stats.committed += 1
        stats.max_seq = max(stats.max_seq, int(seq))
    stats.finished = time.monotonic()
    return stats


# ---------------------------------------------------------------------------
# Projector: dispatcher lease + watermark + outbox_batch + Neo4j upserts
# ---------------------------------------------------------------------------
def apply_variant(conn: psycopg.Connection, allocator: str, watermark: str) -> None:
    if allocator == "counter":
        apply_sql_file(conn, SQL_DIR / "last_counter.sql")
    elif allocator == "nextval":
        apply_sql_file(conn, SQL_DIR / "allocator_nextval.sql")
    else:
        raise ValueError(f"unknown allocator variant {allocator!r}")
    if watermark == "blocking":
        apply_sql_file(conn, SQL_DIR / "watermark_blocking.sql")
    elif watermark != "try":
        raise ValueError(f"unknown watermark variant {watermark!r}")


@dataclass
class ProjectorStats:
    consumer: str
    batches: int = 0
    events_applied: int = 0
    events_skipped_inbox: int = 0
    checkpoints: int = 0
    refresh_attempts: int = 0
    refresh_advanced: int = 0
    refresh_blocked_with_pending: int = 0
    refresh_idle: int = 0
    max_publication_lag: int = 0
    nf_retries: dict = field(default_factory=dict)
    first_event_at: float | None = None
    last_event_at: float | None = None
    done_at: float | None = None
    final_cursor: int = 0
    error: str | None = None

    def as_dict(self) -> dict:
        out = dict(self.__dict__)
        return out


class Projector(threading.Thread):
    def __init__(
        self,
        db: str,
        driver,
        *,
        consumer: str,
        dispatcher: str,
        holder: str,
        target: list[int],
        stop_event: threading.Event,
        statements: list[str],
        batch: int = DEFAULT_BATCH,
        ttl: int = 900,
    ):
        super().__init__(daemon=True)
        self.db = db
        self.driver = driver
        self.consumer = consumer
        self.dispatcher = dispatcher
        self.holder = holder
        self.target = target
        self.stop_event = stop_event
        self.statements = statements
        self.batch = batch
        self.ttl = ttl
        self.stats = ProjectorStats(consumer=consumer)
        self.cursor = 0
        self._stmt_asset, self._stmt_rel, self._stmt_finding, self._stmt_evidence = statements

    # -- Neo4j ops per event -------------------------------------------------
    def _asset_ops(self, pg: psycopg.Connection, asset_id: str, revision: int) -> list[dict]:
        row = pg.execute(
            "SELECT a.asset_id, a.canonical_key, a.kind, a.first_seen, a.last_seen, "
            "       coalesce((SELECT array_agg(ac.campaign_id ORDER BY ac.first_seen, ac.campaign_id) "
            "                  FROM asset_campaign ac WHERE ac.asset_id = a.asset_id), '{}') AS campaigns "
            "FROM asset a WHERE a.asset_id = %s",
            (asset_id,),
        ).fetchone()
        if row is None:
            return []
        ops: list[dict] = []
        for campaign_id in row[5]:
            ops.append({
                "query": self._stmt_asset,
                "params": {
                    "canonical_key": row[1], "asset_id": str(row[0]), "kind": row[2],
                    "first_seen": iso(row[3]), "last_seen": iso(row[4]),
                    "campaign_id": str(campaign_id), "revision": revision,
                },
            })
        rels = pg.execute(
            "SELECT relationship_id, from_asset_id, to_asset_id, observed_at, valid_from, valid_to, "
            "       source_job_id, confidence, campaign_id "
            "FROM relationship WHERE type = 'SUBDOMAIN_OF' AND from_asset_id = %s "
            "ORDER BY valid_from, relationship_id",
            (asset_id,),
        ).fetchall()
        for rel in rels:
            ops.append({
                "query": self._stmt_rel,
                "params": {
                    "from_asset_id": str(rel[1]), "to_asset_id": str(rel[2]), "relationship_id": str(rel[0]),
                    "observed_at": iso(rel[3]), "valid_from": iso(rel[4]),
                    "valid_to": iso(rel[5]) if rel[5] else None,
                    "source_job_id": str(rel[6]), "confidence": float(rel[7]), "campaign_id": str(rel[8]),
                },
            })
        return ops

    def _finding_ops(self, pg: psycopg.Connection, payload: dict) -> list[dict]:
        finding = pg.execute(
            "SELECT finding_id, asset_id, fingerprint, rule_id, title, status, severity, transition_seq, "
            "       confidence, secret_value, first_seen, first_job_id "
            "FROM finding WHERE finding_id = %s",
            (payload["finding_id"],),
        ).fetchone()
        if finding is None:
            return []
        observed_at = iso(finding[10])
        ops = [{
            "query": self._stmt_finding,
            "params": {
                "asset_id": str(finding[1]), "finding_id": str(finding[0]), "fingerprint": finding[2],
                "rule_id": finding[3], "title": finding[4], "status": finding[5], "severity": finding[6],
                "transition_seq": int(finding[7]), "secret_value": finding[9],
                "observed_at": observed_at, "source_job_id": str(finding[11]),
                "confidence": float(finding[8]) if finding[8] is not None else 1.0,
            },
        }]
        evidence = pg.execute(
            "SELECT evidence_id, sha256, storage_uri, source_tool, job_id FROM evidence WHERE evidence_id = %s",
            (payload.get("evidence_ref"),),
        ).fetchone()
        if evidence is not None:
            ops.append({
                "query": self._stmt_evidence,
                "params": {
                    "finding_id": str(finding[0]), "evidence_id": str(evidence[0]), "sha256": evidence[1],
                    "storage_uri": evidence[2], "source_tool": evidence[3],
                    "observed_at": observed_at, "source_job_id": str(evidence[4]),
                },
            })
        return ops

    # -- loop ----------------------------------------------------------------
    def run(self) -> None:
        try:
            self._loop()
        except BaseException as err:  # noqa: BLE001 - surfaced as a failed scenario
            self.stats.error = f"{type(err).__name__}: {err}"
            raise

    def _loop(self) -> None:
        # Autocommit: a read must not pin one snapshot for the whole loop, and the
        # checkpoint block below is an explicit transaction. 0008 requires the
        # watermark refresh to be its own short transaction (the exclusive
        # publication lock is xact-scoped and would otherwise block writers).
        pg = connect(self.db, autocommit=True)
        wm = connect(self.db, autocommit=True)
        fence = wm.execute(
            "SELECT aegis.outbox_dispatch_lease(%s,%s,%s)", (self.dispatcher, self.holder, self.ttl)
        ).fetchone()[0]
        if fence is None:
            raise RuntimeError("another live dispatcher holds the lease")
        resume = wm.execute(
            "SELECT last_seq FROM consumer_cursor WHERE consumer = %s", (self.consumer,)
        ).fetchone()
        self.cursor = int(resume[0]) if resume else 0
        self.stats.final_cursor = self.cursor
        while True:
            last = wm.execute("SELECT aegis.spike_publication_last()").fetchone()[0] or 0
            wm_before = wm.execute("SELECT published_upto FROM aegis.outbox_watermark").fetchone()[0]
            wm_after = wm.execute(
                "SELECT aegis.outbox_watermark_refresh(%s,%s)", (self.dispatcher, fence)
            ).fetchone()[0]
            st = self.stats
            st.refresh_attempts += 1
            if wm_after > wm_before:
                st.refresh_advanced += 1
            elif last - wm_before > 0:
                st.refresh_blocked_with_pending += 1
            else:
                st.refresh_idle += 1
            st.max_publication_lag = max(st.max_publication_lag, last - self.cursor)

            rows = pg.execute(
                "SELECT seq, event_id, type, dedup_key, payload FROM aegis.outbox_batch(%s,%s)",
                (self.consumer, self.batch),
            ).fetchall()
            if rows:
                keys = [f"{r[2]}:{r[3]}" for r in rows]
                seen = {
                    r[0]
                    for r in pg.execute(
                        "SELECT dedup_key FROM consumer_inbox WHERE consumer = %s AND dedup_key = ANY(%s)",
                        (self.consumer, keys),
                    ).fetchall()
                }
                ops: list[dict] = []
                applied = []
                for seq, event_id, typ, dedup_key, payload in rows:
                    inbox_key = f"{typ}:{dedup_key}"
                    if inbox_key in seen:
                        st.events_skipped_inbox += 1
                        continue
                    if typ == "asset.discovered.v2":
                        ops.extend(self._asset_ops(pg, payload["asset_id"], int(payload["revision"])))
                    elif typ == "finding.changed.v2":
                        ops.extend(self._finding_ops(pg, payload))
                    applied.append((seq, event_id, inbox_key))
                if ops:
                    apply_batch_retry(self.driver, ops, stats=self._nf_retry_stats())
                now = time.monotonic()
                st.first_event_at = st.first_event_at or now
                st.last_event_at = now
                with pg.transaction():
                    for seq, event_id, inbox_key in applied:
                        pg.execute(
                            "INSERT INTO consumer_inbox (consumer, dedup_key, event_id) VALUES (%s,%s,%s) "
                            "ON CONFLICT DO NOTHING",
                            (self.consumer, inbox_key, event_id),
                        )
                    max_seq = int(rows[-1][0])
                    self.cursor = int(pg.execute(
                        "SELECT aegis.consumer_advance(%s,%s,%s,%s)",
                        (self.consumer, max_seq, self.dispatcher, fence),
                    ).fetchone()[0])
                st.events_applied += len(applied)
                st.batches += 1
                st.checkpoints += 1
                self.stats.final_cursor = self.cursor
                continue
            if self.stop_event.is_set() and self.cursor >= self.target[0]:
                break
            time.sleep(0.004)
        self.stats.done_at = time.monotonic()
        self.stats.final_cursor = self.cursor

    def _nf_retry_stats(self) -> dict:
        return self.stats.nf_retries


# ---------------------------------------------------------------------------
# Scenario: load, project, crash-window redelivery, rebuild, reconcile
# ---------------------------------------------------------------------------
def _run_producers(db: str, cfg: LoadConfig, target: list[int]) -> tuple[list[WriterStats], dict]:
    conns = [connect(db) for _ in range(cfg.writers)]
    barrier = threading.Barrier(cfg.writers + 1)
    results: list[WriterStats | None] = [None] * cfg.writers
    errors: list[str] = []

    def wrap(i: int) -> None:
        try:
            results[i] = _produce(conns[i], i, cfg, barrier)
        except BaseException as err:  # noqa: BLE001 - fail the scenario, do not hide a lost writer
            errors.append(f"writer {i}: {type(err).__name__}: {err}")

    threads = [threading.Thread(target=wrap, args=(i,), daemon=True) for i in range(cfg.writers)]
    for t in threads:
        t.start()
    barrier.wait()
    started = time.monotonic()
    for t in threads:
        t.join()
    finished = time.monotonic()
    for c in conns:
        c.close()
    if errors:
        raise RuntimeError("producer failed: " + "; ".join(errors[:3]))
    done = [r for r in results if r is not None]
    target[0] = max((r.max_seq for r in done), default=0)
    info = {
        "writers": cfg.writers,
        "events_requested": cfg.writers * cfg.events_per_writer,
        "events_committed": sum(r.committed for r in done),
        "rolled_back_seq": next((r.rolled_back_seq for r in done if r.rolled_back_seq is not None), None),
        "wall_seconds": round(finished - started, 3),
        "producer_events_per_second": round(sum(r.committed for r in done) / (finished - started), 1),
        "started_at_monotonic": started,
        "finished_at_monotonic": finished,
    }
    return done, info


def _event_counts(conn: psycopg.Connection) -> dict:
    row = conn.execute(
        "SELECT count(*) FILTER (WHERE type = 'asset.discovered.v2'), "
        "       count(*) FILTER (WHERE type = 'finding.changed.v2'), count(*) FROM outbox_event"
    ).fetchone()
    return {"asset_events": row[0], "finding_events": row[1], "outbox_events": row[2]}


def _redelivery(
    db: str, driver, *, statements, dispatcher: str, holder: str, rewind: int = 100
) -> dict:
    """Re-apply already projected events into the populated graph.

    consumer_inbox is append-only (0001 forbids DELETE), so the crash window cannot be
    simulated by deleting inbox rows. A fresh consumer id with no inbox rows and a cursor
    just below the end is the same situation as 0008's rebuild rule: Neo4j already has the
    data, the checkpoint is behind. The template must be idempotent under that replay.
    """
    consumer = "m23-projector#g1-replay"
    with connect(db, autocommit=True) as pg:
        last = pg.execute(
            "SELECT last_seq FROM consumer_cursor WHERE consumer = 'm23-projector#g1'"
        ).fetchone()
        last = int(last[0]) if last else 0
        rewind_to = max(0, last - rewind)
        pg.execute(
            "INSERT INTO consumer_cursor (consumer, last_seq) VALUES (%s,%s) "
            "ON CONFLICT (consumer) DO UPDATE SET last_seq = EXCLUDED.last_seq",
            (consumer, rewind_to),
        )
    stop = threading.Event()
    stop.set()
    projector = Projector(
        db, driver, consumer=consumer, dispatcher=dispatcher, holder=holder,
        target=[last], stop_event=stop, statements=statements, batch=DEFAULT_BATCH,
    )
    projector.run()
    return {
        "consumer": consumer,
        "started_from": rewind_to,
        "previous_cursor": last,
        "redelivered_events": projector.stats.events_applied,
        "new_cursor": projector.stats.final_cursor,
        "error": projector.stats.error,
    }


def _rebuild(db: str, driver, *, statements, dispatcher: str, holder: str, target: list[int]) -> dict:
    wipe_graph(driver)
    with connect(db) as pg:
        project_seed_assets(pg, driver, statements)
    stop = threading.Event()
    stop.set()
    started = time.monotonic()
    projector = Projector(
        db, driver, consumer="m23-projector#g2", dispatcher=dispatcher, holder=holder,
        target=[target[0]], stop_event=stop, statements=statements, batch=DEFAULT_BATCH,
    )
    projector.run()
    elapsed = time.monotonic() - started
    events = projector.stats.events_applied + projector.stats.events_skipped_inbox
    return {
        "consumer": "m23-projector#g2",
        "started_from_cursor": 0,
        "events_replayed": projector.stats.events_applied,
        "seconds": round(elapsed, 3),
        "events_per_second": round(events / elapsed, 1) if elapsed else 0.0,
        "watermark_refresh_attempts": projector.stats.refresh_attempts,
        "final_cursor": projector.stats.final_cursor,
        "error": projector.stats.error,
    }


def reconcile_with_pg(pg: psycopg.Connection, snapshot: dict, target_seq: int) -> dict:
    """Metadata/revision/evidence reconciliation of the graph against PostgreSQL."""
    nodes, edges = snapshot["nodes"], snapshot["edges"]
    graph_assets = {k: v["properties"] for k, v in nodes.items() if "Asset" in v["labels"]}
    graph_findings = {k: v["properties"] for k, v in nodes.items() if "Finding" in v["labels"]}
    graph_evidence = {k: v["properties"] for k, v in nodes.items() if "Evidence" in v["labels"]}
    rel_edges = [e for e in edges.values() if e["type"] == "SUBDOMAIN_OF"]
    mismatches: list[str] = []

    expected_revision = {
        str(row[0]): int(row[1])
        for row in pg.execute(
            "SELECT payload->>'asset_id', max((payload->>'revision')::bigint) FROM outbox_event "
            "WHERE type = 'asset.discovered.v2' GROUP BY 1"
        ).fetchall()
    }
    campaigns = {
        str(row[0]): sorted(str(x) for x in row[1])
        for row in pg.execute(
            "SELECT asset_id, array_agg(campaign_id) FROM asset_campaign GROUP BY asset_id"
        ).fetchall()
    }

    assets = pg.execute("SELECT asset_id, canonical_key FROM asset").fetchall()
    for asset_id, canonical_key in assets:
        key = f"Asset:{canonical_key}"
        node = graph_assets.get(key)
        if node is None:
            mismatches.append(f"asset missing in graph: {canonical_key}")
            continue
        if node["asset_id"] != str(asset_id):
            mismatches.append(f"asset_id mismatch: {canonical_key}: {node['asset_id']} != {asset_id}")
        want_rev = expected_revision.get(str(asset_id), 0)
        if node.get("pg_revision") != want_rev:
            mismatches.append(f"revision mismatch: {canonical_key}: {node.get('pg_revision')} != {want_rev}")
        if sorted(node.get("campaign_ids") or []) != campaigns.get(str(asset_id), []):
            mismatches.append(f"campaign_ids mismatch: {canonical_key}")
    if len(graph_assets) != len(assets):
        mismatches.append(f"asset count: graph {len(graph_assets)} != pg {len(assets)}")

    findings = pg.execute(
        "SELECT finding_id, fingerprint, rule_id, status, severity, transition_seq FROM finding"
    ).fetchall()
    for finding_id, fingerprint, rule_id, status, severity, transition_seq in findings:
        node = graph_findings.get(f"Finding:{finding_id}")
        if node is None:
            mismatches.append(f"finding missing in graph: {finding_id}")
            continue
        if (node.get("fingerprint"), node.get("rule_id"), node.get("status"), node.get("severity"),
                node.get("transition_seq")) != (fingerprint, rule_id, status, severity, transition_seq):
            mismatches.append(f"finding metadata mismatch: {finding_id}")
    if len(graph_findings) != len(findings):
        mismatches.append(f"finding count: graph {len(graph_findings)} != pg {len(findings)}")

    evidence = pg.execute("SELECT evidence_id, sha256, storage_uri, source_tool FROM evidence").fetchall()
    for evidence_id, sha, uri, tool in evidence:
        node = graph_evidence.get(f"Evidence:{evidence_id}")
        if node is None:
            mismatches.append(f"evidence missing in graph: {evidence_id}")
            continue
        if (node.get("sha256"), node.get("storage_uri"), node.get("source_tool")) != (sha, uri, tool):
            mismatches.append(f"evidence metadata mismatch: {evidence_id}")
    if len(graph_evidence) != len(evidence):
        mismatches.append(f"evidence count: graph {len(graph_evidence)} != pg {len(evidence)}")

    rel_count = pg.execute("SELECT count(*) FROM relationship WHERE type = 'SUBDOMAIN_OF'").fetchone()[0]
    if len(rel_edges) != rel_count:
        mismatches.append(f"relationship count: graph {len(rel_edges)} != pg {rel_count}")

    receipt = pg.execute("SELECT count(*) FROM outbox_event").fetchone()[0]
    return {
        "ok": not mismatches,
        "graph_nodes": len(nodes),
        "graph_edges": len(edges),
        "pg": {
            "assets": len(assets), "findings": len(findings), "evidence": len(evidence),
            "subdomain_edges": rel_count, "outbox_events": receipt, "target_seq": target_seq,
        },
        "mismatches": mismatches[:20],
        "mismatch_count": len(mismatches),
    }


def run_load(*, allocator: str, writers: int, events_per_writer: int, runs: int) -> dict:
    """Same writer transactions as the pipeline, without a consumer: allocator in situ."""
    per_run = []
    for run_index in range(runs):
        with RunDatabase(f"load_{allocator}_{writers}_{run_index}") as db:
            with connect(db, autocommit=True) as meta:
                apply_variant(meta, allocator, "try")
            with connect(db) as pg:
                seed_contract_rows(pg)
            target = [0]
            _, info = _run_producers(db, LoadConfig(writers=writers, events_per_writer=events_per_writer), target)
            with connect(db) as pg:
                counts = _event_counts(pg)
            per_run.append({
                "run": run_index,
                "outbox_events": counts["outbox_events"],
                "wall_seconds": info["wall_seconds"],
                "events_per_second": round(counts["outbox_events"] / info["wall_seconds"], 1),
                "target_seq": target[0],
            })
    rates = [r["events_per_second"] for r in per_run]
    return {
        "allocator": allocator, "writers": writers,
        "events_per_writer": events_per_writer, "runs": per_run,
        "median_events_per_second": round(median(rates), 1),
        "max_publication_seq": per_run[-1]["target_seq"] if per_run else 0,
    }


def run_pipeline(
    *,
    label: str,
    allocator: str,
    watermark: str,
    writers: int,
    events_per_writer: int,
    rebuild: bool = True,
    redelivery: bool = True,
) -> dict:
    cfg = LoadConfig(writers=writers, events_per_writer=events_per_writer)
    statements = load_cypher_statements()
    holder = f"g03b-{os.getpid()}"
    result: dict = {
        "scenario": "pipeline", "label": label, "allocator": allocator, "watermark": watermark,
        "generation": "m23-projector#g1",
    }
    with RunDatabase(label) as db:
        with connect(db, autocommit=True) as meta:
            apply_variant(meta, allocator, watermark)
        with connect(db) as pg:
            seed_contract_rows(pg)
        driver = neo4j_driver()
        apply_constraints(driver)
        wipe_graph(driver)
        with connect(db) as pg:
            result["seed_assets_projected"] = project_seed_assets(pg, driver, statements)

        target = [0]
        stop = threading.Event()
        projector = Projector(
            db, driver, consumer="m23-projector#g1", dispatcher="m23-projector", holder=holder,
            target=target, stop_event=stop, statements=statements,
        )
        projector.start()
        _, producer_info = _run_producers(db, cfg, target)
        with connect(db) as pg:
            counts = _event_counts(pg)
        stop.set()
        projector.join(timeout=300)
        if projector.is_alive():
            raise RuntimeError("projector did not drain within 300s")
        if projector.stats.error:
            raise RuntimeError(projector.stats.error)

        e2e_seconds = projector.stats.done_at - producer_info["started_at_monotonic"]
        gap_seq = producer_info["rolled_back_seq"]
        with connect(db) as pg:
            gap_rows = pg.execute("SELECT count(*) FROM outbox_event WHERE seq = %s", (gap_seq,)).fetchone()[0]
        # Counter allocator: a rollback returns its number, so a later writer reuses it and an
        # event row exists at that seq (it must be projected). nextval: the number stays a
        # permanent gap (no row). Both must be passed by the consumer without stalling.
        result["publication_gap"] = {
            "rolled_back_seq": gap_seq,
            "number_reused_by_later_tx": gap_rows > 0,
            "final_cursor": projector.stats.final_cursor,
            "passed": projector.stats.final_cursor > (gap_seq or 0),
        }
        result["producers"] = {k: v for k, v in producer_info.items() if not k.endswith("_monotonic")}
        result["producers"]["events_committed_total"] = counts["outbox_events"]
        result["projector"] = projector.stats.as_dict()
        result["projector"]["drain_seconds"] = round(projector.stats.done_at - producer_info["finished_at_monotonic"], 3)
        result["projector"]["first_event_seconds_after_producers_finished"] = (
            round(projector.stats.first_event_at - producer_info["finished_at_monotonic"], 3)
            if projector.stats.first_event_at else None
        )
        result["projector"]["end_to_end_seconds"] = round(e2e_seconds, 3)
        result["projector"]["end_to_end_events_per_second"] = round(counts["outbox_events"] / e2e_seconds, 1)
        result["events"] = counts

        snapshot_original = graph_snapshot(driver)
        result["original_graph"] = {k: len(v) for k, v in snapshot_original.items()}
        with connect(db) as pg:
            result["original_reconcile"] = reconcile_with_pg(pg, snapshot_original, target[0])

        if redelivery:
            result["redelivery"] = _redelivery(
                db, driver, statements=statements, dispatcher="m23-projector", holder=holder
            )
            snapshot_retry = graph_snapshot(driver)
            result["redelivery"]["graph_equal_after_redelivery"] = snapshot_diff(
                snapshot_original, snapshot_retry
            )
            result["redelivery"]["graph_unchanged"] = result["redelivery"]["graph_equal_after_redelivery"]["equal"]

        if rebuild:
            result["rebuild"] = _rebuild(
                db, driver, statements=statements, dispatcher="m23-projector", holder=holder, target=target
            )
            snapshot_rebuild = graph_snapshot(driver)
            result["rebuild"]["equality"] = snapshot_diff(snapshot_original, snapshot_rebuild)
            result["rebuild"]["equals_original"] = result["rebuild"]["equality"]["equal"]
            with connect(db) as pg:
                result["rebuild"]["reconcile"] = reconcile_with_pg(pg, snapshot_rebuild, target[0])
            result["rebuild"]["reconcile_ok"] = result["rebuild"]["reconcile"]["ok"]
            # The old generation's checkpoint must be untouched by the rebuild.
            with connect(db) as pg:
                old = pg.execute(
                    "SELECT last_seq FROM consumer_cursor WHERE consumer = 'm23-projector#g1'"
                ).fetchone()
                new = pg.execute(
                    "SELECT last_seq FROM consumer_cursor WHERE consumer = 'm23-projector#g2'"
                ).fetchone()
                result["rebuild"]["cursors"] = {
                    "g1": int(old[0]) if old else None, "g2": int(new[0]) if new else None,
                }
        driver.close()
    return result


# ---------------------------------------------------------------------------
# Allocator-only measurement: identical writer transactions, allocator swapped
# ---------------------------------------------------------------------------
def run_alloc(*, allocator: str, writers: int, total_events: int, runs: int) -> dict:
    per_run = []
    label_base = f"alloc_{allocator}_{writers}"
    for run_index in range(runs):
        with RunDatabase(f"{label_base}_{run_index}") as db:
            with connect(db, autocommit=True) as meta:
                apply_variant(meta, allocator, "try")
            with connect(db) as pg:
                seed_contract_rows(pg)
            per_writer = max(1, total_events // writers)
            cids = [uid(f"campaign:{i}") for i in range(CAMPAIGNS)]
            jids = [uid(f"job:{i}") for i in range(CAMPAIGNS)]
            conns = [connect(db) for _ in range(writers)]
            barrier = threading.Barrier(writers + 1)
            errors: list[str] = []

            def one(i: int) -> None:
                conn = conns[i]
                cid, jid = cids[i % CAMPAIGNS], jids[i % CAMPAIGNS]
                barrier.wait()
                try:
                    for j in range(per_writer):
                        now = utc_now()
                        with conn.transaction():
                            conn.execute(
                                "INSERT INTO graph_revision (campaign_id, causal_job_id) VALUES (%s,%s)",
                                (cid, jid),
                            )
                            conn.execute(
                                "INSERT INTO outbox_event (event_id, type, producer, dedup_key, campaign_id, "
                                "payload, trace, occurred_at) VALUES (%s,'asset.discovered.v2','M27',%s,%s,%s,%s,%s)",
                                (
                                    uid(f"alloc-event:{i}:{j}"), f"alloc:{i}:{j}", cid,
                                    Jsonb({"asset_id": str(uid(f"alloc-asset:{i}:{j}")), "canonical_key":
                                           ckey(f"alloc-{i}-{j}.spike-a.example"), "kind": "domain",
                                           "revision": 1, "causal_job_id": str(jid), "campaign_id": str(cid),
                                           "discovered_from": [], "first_seen": iso(now)}),
                                    Jsonb({"trace_id": os.urandom(16).hex()}), now,
                                ),
                            )
                except Exception as err:  # noqa: BLE001
                    errors.append(f"{type(err).__name__}: {err}")

            threads = [threading.Thread(target=one, args=(i,), daemon=True) for i in range(writers)]
            for t in threads:
                t.start()
            barrier.wait()
            started = time.monotonic()
            for t in threads:
                t.join()
            elapsed = time.monotonic() - started
            for c in conns:
                c.close()
            events = writers * per_writer
            per_run.append({
                "run": run_index,
                "transactions": events,
                "elapsed_seconds": round(elapsed, 3),
                "transactions_per_second": round(events / elapsed, 1),
                "errors": errors[:5],
            })
    rates = [r["transactions_per_second"] for r in per_run]
    return {
        "allocator": allocator,
        "writers": writers,
        "transactions_per_run": per_run[0]["transactions"] if per_run else 0,
        "runs": per_run,
        "median_transactions_per_second": round(median(rates), 1),
        "errors": sorted({e for r in per_run for e in r["errors"]}),
    }
