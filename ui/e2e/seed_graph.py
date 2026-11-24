#!/usr/bin/env python3
"""Seed real asset graph and project to Neo4j for the active campaign."""
import sys
import uuid
from pathlib import Path

# Add repo root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import psycopg
from neo4j import GraphDatabase
from aegis.m27_ingestion.service import IngestionService
from aegis.m23_graph.projector import Projector, ProjectorConfig
from tests.support_ingestion import (
    asset,
    build_envelope,
    observation,
    relationship,
)

dsn = "postgresql://aegis:aegis-dev-pg@127.0.0.1:15432/aegis"
neo4j_uri = "bolt://127.0.0.1:17687"
neo4j_auth = ("neo4j", "aegis-dev-neo4j")

def main():
    with psycopg.connect(dsn) as conn:
        row = conn.execute(
            "SELECT j.job_id, j.campaign_id, j.scope_id, j.policy_version, j.provider, j.provider_version, j.target_refs"
            "  FROM scan_job j ORDER BY j.created_at DESC LIMIT 1"
        ).fetchone()
        if not row:
            print("NO_JOB_FOUND")
            sys.exit(1)

        job_id = str(row[0])
        campaign_id = str(row[1])
        scope_id = str(row[2])
        policy_version = row[3]
        provider_name = row[4]
        provider_version = row[5]
        seed_targets = row[6]

        # Seed evidence entry for this campaign and job
        evidence_id = str(uuid.uuid4())
        sha256 = "1e1c8bcdd33168e15528d61a006bf5e5e5a31e5b8e4d4d4f1f10ad0876240a9f"
        storage_uri = f"s3://evidence/{campaign_id}/{job_id}/{sha256}"
        conn.execute(
            "INSERT INTO evidence (evidence_id, sha256, storage_uri, campaign_id, job_id, size_bytes, media_type, kind, classification, source_tool)"
            " VALUES (%s, %s, %s, %s, %s, 1024, 'application/json', 'raw_output', 'INTERNAL', %s)"
            " ON CONFLICT (storage_uri) DO NOTHING",
            (evidence_id, sha256, storage_uri, campaign_id, job_id, f"{provider_name}:{provider_version}"),
        )

    # Assets, observations, and relationships
    assets = [
        asset("dns:internal.example", "domain"),
        asset("dns:vpn.internal.example", "domain", discovered_from=["dns:internal.example"]),
        asset("ip:203.0.113.10", "ip"),
    ]
    observations = [
        observation(
            "dns:vpn.internal.example",
            "dns.record",
            {"type": "A", "value": "203.0.113.10", "ttl": 300},
            evidence_refs=[{"local_ref": "raw"}],
        )
    ]
    relationships = [
        relationship("SUBDOMAIN_OF", "dns:vpn.internal.example", "dns:internal.example"),
        relationship("RESOLVES_TO", "dns:vpn.internal.example", "ip:203.0.113.10"),
    ]
    coverage = ["dns:internal.example", "dns:vpn.internal.example", "ip:203.0.113.10"]

    envelope = build_envelope(
        job_id,
        campaign_id=campaign_id,
        scope_id=scope_id,
        policy_version=policy_version,
        provider_name=provider_name,
        provider_version=provider_version,
        seed_targets=seed_targets if seed_targets else None,
        assets=assets,
        observations=observations,
        relationships=relationships,
        coverage=coverage,
        evidence=[
            {
                "local_ref": "raw",
                "uri": storage_uri,
                "sha256": sha256,
                "size_bytes": 1024,
                "media_type": "application/json",
                "classification": "INTERNAL",
                "kind": "raw_output",
            }
        ],
    )

    outcome = IngestionService.from_dsn(dsn).submit_payload(envelope)
    print(f"INGESTION_OUTCOME {outcome}")

    with GraphDatabase.driver(neo4j_uri, auth=neo4j_auth) as driver:
        projector = Projector(
            dsn,
            driver,
            ProjectorConfig(consumer="api#g1", dispatcher="api-dispatcher#g1", batch=500, partitions=2, poll_seconds=0.001),
        )
        with projector:
            projector.run(drain_rounds=3, timeout=30.0)

        records = driver.execute_query(
            "MATCH (a:Asset) RETURN a.asset_id AS id, a.canonical_key AS key"
        ).records
        print(f"SEEDED_CAMPAIGN_ID {campaign_id}")
        print(f"JOB_ID {job_id}")
        for r in records:
            asset_id = r["id"]
            asset_key = r["key"]
            print(f"ASSET {asset_id} {asset_key}")

if __name__ == "__main__":
    main()
