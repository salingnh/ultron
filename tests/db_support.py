"""Database support for the G1.1c tests: a throwaway database per test, seeded like a campaign.

The helpers reuse the migration runner's own `throwaway_database` (tests/test_migrations.py) so the
schema under test is the README contract chain, applied by the same code the gate runs. Seeds
are inserted as M01 would insert them: a v2 policy snapshot, a scope with campaign targets, and an
asset the campaign already knows (P3a).
"""

from __future__ import annotations

import itertools
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import psycopg
import pytest
from psycopg.types.json import Jsonb

from aegis.m05_registry.canonical import sha256_hex

DSN_ENV = "AEGIS_TEST_PG_DSN"
REPO = Path(__file__).resolve().parents[1]
requires_postgres = pytest.mark.skipif(
    not os.environ.get(DSN_ENV),
    reason=f"set {DSN_ENV} to a PostgreSQL 16 server to run the database tests",
)
OPERATOR = {"kind": "operator", "id": "op-g11c"}
# `policy_version` must match `^roe-[1-9][0-9]*$` and is unique per database. A random value in
# 10..99 collided once a test seeded a second campaign (~1 % per pair, and one suite seeds ten);
# a per-process counter keeps every seeded campaign in a fresh database distinct.
_POLICY_VERSIONS = itertools.count(10)


@contextmanager
def throwaway_database() -> Iterator[str]:
    """Create an empty database on the test server and drop it afterwards."""
    from tests.test_migrations import throwaway_database as helper

    with helper() as dsn:
        yield dsn


@contextmanager
def migrated_database() -> Iterator[str]:
    """A throwaway database with the whole contract chain applied."""
    from aegis.migrations import apply_contract_migrations

    with throwaway_database() as dsn, psycopg.connect(dsn, autocommit=True) as connection:
        apply_contract_migrations(connection)
        yield dsn


def connect(dsn: str) -> psycopg.Connection[Any]:
    return psycopg.connect(dsn)


@dataclass(frozen=True, slots=True)
class SeededCampaign:
    campaign_id: str
    policy_version: str
    scope_id: str
    seed_domain: str
    seed_ip: str
    known_asset: str
    policy: dict[str, Any] = field(default_factory=dict)


def _uuid7() -> str:
    from aegis.m05_registry.ids import uuid7

    return uuid7()


def policy_document(**overrides: Any) -> dict[str, Any]:
    """A valid roe-policy.v2 document (fixture baseline) with targeted overrides."""
    policy: dict[str, Any] = json.loads(
        (REPO / "contracts/fixtures/valid/roe-policy.from-v1.json").read_text()
    )
    policy.pop("capability_denylist", None)  # the fixture denies network.discover_services
    policy["budget"] = {"max_jobs": 50, "max_llm_tokens": 100000, "max_llm_cost_usd": 5}
    policy["rate_limits"] = {"requests_per_second_per_host": 10, "jobs_per_minute": 100}
    # Test campaigns are lab campaigns: the internet profile requires a structured authorization
    # and the platform deny set, which the unit/DB fixtures do not exercise.
    policy["network_profile"] = "lab"
    policy.update(overrides)
    return policy


def seed_campaign(
    dsn: str,
    *,
    status: str = "RUNNING",
    policy: dict[str, Any] | None = None,
) -> SeededCampaign:
    """Insert a v2 campaign with one domain seed, one IP seed and one known asset (P3a)."""
    campaign_id, scope_id = _uuid7(), _uuid7()
    policy_version = f"roe-{next(_POLICY_VERSIONS)}"
    document = policy if policy is not None else policy_document()
    seed_domain, seed_ip = "internal.example", "10.114.53.53"
    known_asset = f"dns:www.{campaign_id[-12:]}.internal.example"
    with connect(dsn) as conn, conn.transaction():
        conn.execute(
            "INSERT INTO scope_snapshot (scope_id, campaign_id, targets) VALUES (%s, %s, %s)",
            (scope_id, campaign_id, Jsonb({"domains": [seed_domain]})),
        )
        conn.execute(
            "INSERT INTO policy_snapshot (policy_version, campaign_id, policy, policy_hash, "
            "created_by) VALUES (%s, %s, %s, %s, %s)",
            (
                policy_version,
                campaign_id,
                Jsonb(document),
                sha256_hex(document),
                Jsonb(OPERATOR),
            ),
        )
        conn.execute(
            "INSERT INTO campaign (campaign_id, name, objective, status, current_policy_version, "
            "scope_id, created_by) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (
                campaign_id,
                "G1.1c test campaign",
                "prove M05 acceptance",
                status,
                policy_version,
                scope_id,
                Jsonb(OPERATOR),
            ),
        )
        for kind, raw_value, canonical in (
            ("domain", seed_domain, "dns:" + seed_domain),
            ("ip", seed_ip, "ip:" + seed_ip),
        ):
            conn.execute(
                "INSERT INTO campaign_target (target_id, scope_id, kind, raw_value, canonical_key) "
                "VALUES (%s, %s, %s, %s, %s)",
                (_uuid7(), scope_id, kind, raw_value, canonical),
            )
        asset_id = _uuid7()
        conn.execute(
            "INSERT INTO asset (asset_id, canonical_key, kind, first_seen, last_seen,"
            " normalization_version) VALUES (%s, %s, 'domain', now(), now(), 'aegis-norm/1')",
            (asset_id, known_asset),
        )
        conn.execute(
            "INSERT INTO asset_campaign (asset_id, campaign_id, first_seen) VALUES (%s, %s, now())",
            (asset_id, campaign_id),
        )
    return SeededCampaign(
        campaign_id=campaign_id,
        policy_version=policy_version,
        scope_id=scope_id,
        seed_domain=seed_domain,
        seed_ip=seed_ip,
        known_asset=known_asset,
        policy=document,
    )


def read_campaign_policy(dsn: str, campaign_id: str) -> dict[str, Any]:
    with connect(dsn) as conn:
        row = conn.execute(
            "SELECT p.policy FROM campaign c JOIN policy_snapshot p "
            "ON p.policy_version = c.current_policy_version WHERE c.campaign_id = %s",
            (campaign_id,),
        ).fetchone()
    assert row is not None
    return dict(row[0])
