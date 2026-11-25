"""M05 acceptance end to end: decision, signed task, job, dependencies, events, idempotency."""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest

from aegis import validation
from aegis.contracts_gen.capability.job_submit_v2_schema import JobSubmit
from aegis.m05_registry.dependency import find_cycle
from aegis.m05_registry.errors import M05Error
from aegis.m05_registry.registry import PostgresManifestRegistry
from aegis.m05_registry.service import PostgresJobService
from aegis.m05_registry.signing import KeyRing
from tests.db_support import (
    OPERATOR,
    SeededCampaign,
    connect,
    migrated_database,
    policy_document,
    requires_postgres,
    seed_campaign,
)
from tests.support import REPO_ROOT

pytestmark = requires_postgres

TASK_SCHEMA = "capability/approved-task.v2.schema.json"
BINDER_MAP = {"internal.example": ("10.114.53.53",)}


class FakeBinder:
    """Deterministic resolver: tests never touch DNS."""

    def addresses(self, value: str) -> tuple[str, ...]:
        return BINDER_MAP.get(value, (f"198.51.100.{abs(hash(value)) % 200 + 1}",))


def _reference() -> Any:
    path = REPO_ROOT / "contracts/tests/canonicalization.py"
    spec = importlib.util.spec_from_file_location("aegis_c14n_reference_service", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


REFERENCE = _reference()


@contextmanager
def service(dsn: str, *, binder: Any = None) -> Iterator[PostgresJobService]:
    registry = PostgresManifestRegistry(lambda: connect(dsn))
    registry.register(
        (REPO_ROOT / "contracts/fixtures/valid/manifest.subfinder.yaml").read_bytes(),
        registered_by={"kind": "module", "id": "M05"},
    )
    registry.register(
        (REPO_ROOT / "contracts/fixtures/valid/manifest.dnsx.yaml").read_bytes(),
        registered_by={"kind": "module", "id": "M05"},
    )
    yield PostgresJobService(
        lambda: connect(dsn),
        registry=registry,
        key_ring=KeyRing.dev(),
        binder=binder or FakeBinder(),
    )


def body(campaign: SeededCampaign, **overrides: Any) -> JobSubmit:
    payload: dict[str, Any] = {
        "campaign_id": campaign.campaign_id,
        "capability": "dns.enumerate_subdomains",
        "input": {"targets": [campaign.seed_domain]},
        "rationale": "G1.1c acceptance test",
    }
    payload.update(overrides)
    return JobSubmit.model_validate(payload)


def scalar(dsn: str, query: str, params: tuple[Any, ...] = ()) -> Any:
    with connect(dsn) as conn:
        row = conn.execute(query, params).fetchone()
    return None if row is None else row[0]


def rows(dsn: str, query: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    with connect(dsn) as conn:
        return [tuple(row) for row in conn.execute(query, params).fetchall()]


def test_acceptance_writes_decision_job_dependencies_and_a_verifiable_task() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        with service(dsn) as jobs:
            first = jobs.submit(
                body(campaign, priority=60), requested_by=OPERATOR, idempotency_key="key-accept-1"
            )
        assert first.replayed is False
        job = first.job
        validation.validate("capability/job.v2.schema.json", job)
        assert job["status"] == "QUEUED" and job["priority"] == 60
        assert job["requested_by"] == OPERATOR
        seed_id = rows(
            dsn,
            "SELECT target_id::text FROM campaign_target WHERE raw_value = %s",
            (campaign.seed_domain,),
        )[0][0]
        assert job["targets"] == [{"seed_id": seed_id}]

        decision = rows(
            dsn,
            "SELECT capability, provider, decision, input, target_refs, targets, request_hash "
            "FROM policy_decision WHERE decision_id = %s",
            (first.decision_id,),
        )[0]
        assert decision[0] == "dns.enumerate_subdomains" and decision[1] == "subfinder"
        assert decision[2] == "approved"
        # README:89 - the decision approves the *merged* input, and the job stores the same one.
        merged = decision[3]
        assert merged == {"targets": [campaign.seed_domain], "recursive": False}
        assert decision[4] == job["targets"]
        assert decision[5] == [], (
            "every target is a keyword-capable seed, so the projection is empty"
        )
        assert decision[6] is not None and len(decision[6]) == 64

        stored_task = scalar(
            dsn, "SELECT approved_task FROM scan_job WHERE job_id = %s", (job["job_id"],)
        )
        validation.validate(TASK_SCHEMA, stored_task)
        assert KeyRing.dev().verify(stored_task) == "g1-dev-1"
        assert stored_task["input"] == merged
        assert stored_task["signature_key_id"] == "g1-dev-1"
        binding = stored_task["egress_binding"]
        assert binding["mode"] == "broker" and binding["target_binding"] == "none"
        assert binding["entries"] == ["crt.sh:443", "otx.alienvault.com:443"]
        assert binding["target_addresses"] == []
        assert stored_task["trace"]["campaign_id"] == campaign.campaign_id
        # X-1: the fingerprint is the contract's, over refs/input/pins and never the projection.
        assert job["job_fingerprint"] == REFERENCE.job_fingerprint(
            {
                **{
                    key: stored_task[key]
                    for key in (
                        "campaign_id",
                        "capability",
                        "policy_version",
                        "provider",
                        "provider_version",
                        "adapter_version",
                        "image_digest",
                        "manifest_sha256",
                        "input",
                        "scan_cycle",
                    )
                },
                "target_refs": stored_task["targets"],
            }
        )
        # No event for an accepted job.
        assert scalar(dsn, "SELECT count(*) FROM outbox_event") == 0


def test_unknown_capability_is_a_recorded_policy_denial_with_next_action() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        with service(dsn) as jobs, pytest.raises(M05Error) as caught:
            jobs.submit(
                body(campaign, capability="dns.not_a_capability"),
                requested_by=OPERATOR,
                idempotency_key="key-unknown-cap",
            )
        refusal = caught.value.refusal
        assert refusal.code == "POLICY_DENIED" and refusal.status_code == 403
        assert refusal.rule == "capability_unknown"
        assert refusal.next_action == "CHECK_PROVIDER"
        decision = rows(dsn, "SELECT decision, rule, error, target_refs FROM policy_decision")[0]
        assert decision[0] == "denied" and decision[1] == "capability_unknown"
        assert decision[2]["next_action"] == "CHECK_PROVIDER"
        assert decision[3], "a denial keeps the resolved TargetRefs for provenance"
        events = rows(dsn, "SELECT type, producer, dedup_key, payload FROM outbox_event")
        assert [event[0] for event in events] == ["policy.denied.v2"]
        assert (
            events[0][1] == "M05"
            and events[0][2] == rows(dsn, "SELECT decision_id::text FROM policy_decision")[0][0]
        )
        validation.validate("events/policy.denied.v2.schema.json", events[0][3])
        assert events[0][3]["rule"] == "capability_unknown"
        assert scalar(dsn, "SELECT count(*) FROM scan_job") == 0


def test_invalid_input_is_a_400_and_writes_no_decision() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        with service(dsn) as jobs, pytest.raises(M05Error) as caught:
            jobs.submit(
                body(campaign, input={"targets": campaign.seed_domain}),  # not a list
                requested_by=OPERATOR,
                idempotency_key="key-invalid-input",
            )
        refusal = caught.value.refusal
        assert refusal.code == "INPUT_INVALID" and refusal.status_code == 400
        assert refusal.next_action == "FIX_INPUT"
        assert refusal.field is not None and refusal.field.startswith("/input")
        assert scalar(dsn, "SELECT count(*) FROM policy_decision") == 0
        assert scalar(dsn, "SELECT count(*) FROM outbox_event") == 0


def test_over_cap_refusals_are_decisions_with_next_action() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        with service(dsn) as jobs, pytest.raises(M05Error) as caught:
            jobs.submit(
                body(campaign, input={"targets": ["internal.example"], "concurrency": 10}),
                requested_by=OPERATOR,
                idempotency_key="key-over-concurrency",
            )
        assert caught.value.refusal.rule == "concurrency_cap"
        assert caught.value.refusal.field == "/input/concurrency"

    with migrated_database() as dsn:
        campaign = seed_campaign(dsn, policy=policy_document(budget={"max_jobs": 1}))
        from aegis.m05_registry.ids import uuid7

        with service(dsn) as jobs:
            jobs.submit(body(campaign), requested_by=OPERATOR, idempotency_key="key-budget-first")
            with pytest.raises(M05Error) as caught:
                jobs.submit(
                    body(campaign, scan_cycle=uuid7()),
                    requested_by=OPERATOR,
                    idempotency_key="key-over-budget",
                )
        assert caught.value.refusal.rule == "budget_max_jobs"
        assert caught.value.refusal.status_code == 403
        assert caught.value.refusal.next_action == "FIX_INPUT"
        assert scalar(dsn, "SELECT count(*) FROM outbox_event WHERE type = 'policy.denied.v2'") == 1


def test_rate_caps_use_the_campaign_snapshot_and_rate_limited_is_a_decision() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(
            dsn,
            policy=policy_document(
                rate_limits={"requests_per_second_per_host": 10, "jobs_per_minute": 1}
            ),
        )
        from aegis.m05_registry.ids import uuid7

        with service(dsn) as jobs:
            with pytest.raises(M05Error) as tool_rate:
                jobs.submit(
                    body(campaign, input={"targets": ["internal.example"], "rate_limit": 11}),
                    requested_by=OPERATOR,
                    idempotency_key="key-rate-tool",
                )
            assert tool_rate.value.refusal.rule == "rate_limit_cap"
            assert tool_rate.value.refusal.field == "/input/rate_limit"

            jobs.submit(body(campaign), requested_by=OPERATOR, idempotency_key="key-rate-first")
            with pytest.raises(M05Error) as campaign_rate:
                jobs.submit(
                    body(campaign, scan_cycle=uuid7()),
                    requested_by=OPERATOR,
                    idempotency_key="key-rate-second",
                )
        refusal = campaign_rate.value.refusal
        assert refusal.code == "RATE_LIMITED" and refusal.status_code == 429
        assert refusal.rule == "rate_jobs_per_minute"
        assert refusal.next_action == "RETRY_LATER"
        assert refusal.retry_after_seconds is not None and 1 <= refusal.retry_after_seconds <= 60
        assert scalar(dsn, "SELECT count(*) FROM outbox_event WHERE type = 'policy.denied.v2'") == 2


def test_target_must_be_a_seed_or_an_asset_the_campaign_knows() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        with service(dsn) as jobs:
            # P3a: a canonical key for an asset the campaign never saw is refused, not invented.
            with pytest.raises(M05Error) as caught:
                jobs.submit(
                    body(campaign, input={"targets": ["dns:unknown.internal.example"]}),
                    requested_by=OPERATOR,
                    idempotency_key="key-unknown-asset",
                )
            assert caught.value.refusal.code == "INPUT_INVALID"
            assert caught.value.refusal.field == "/input/targets/0"
            assert scalar(dsn, "SELECT count(*) FROM policy_decision") == 0

            accepted = jobs.submit(
                body(campaign, input={"targets": [campaign.known_asset]}),
                requested_by=OPERATOR,
                idempotency_key="key-known-asset",
            )
        assert accepted.job["targets"] == [{"canonical_key": campaign.known_asset}]
        decision = rows(dsn, "SELECT targets, target_refs FROM policy_decision")[0]
        assert decision[0] == [campaign.known_asset]
        assert decision[1] == [{"canonical_key": campaign.known_asset}]


def test_dependencies_must_exist_in_the_same_campaign() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        other = seed_campaign(dsn)
        with service(dsn) as jobs:
            first = jobs.submit(
                body(campaign), requested_by=OPERATOR, idempotency_key="key-dep-root"
            )
            with pytest.raises(M05Error) as unknown:
                jobs.submit(
                    body(campaign, depends_on=["01934f6a-0000-7000-8000-0000000000ff"]),
                    requested_by=OPERATOR,
                    idempotency_key="key-dep-unknown",
                )
            assert unknown.value.refusal.rule == "dependency_invalid"

            with service(dsn) as other_jobs:
                foreign = other_jobs.submit(
                    body(other), requested_by=OPERATOR, idempotency_key="key-other-root"
                )
            with pytest.raises(M05Error) as cross:
                jobs.submit(
                    body(campaign, depends_on=[foreign.job["job_id"]]),
                    requested_by=OPERATOR,
                    idempotency_key="key-dep-cross",
                )
            assert cross.value.refusal.rule == "dependency_invalid"
            assert "another campaign" in cross.value.refusal.message

            dependent = jobs.submit(
                body(
                    campaign,
                    input={"targets": ["internal.example"], "recursive": True},
                    depends_on=[first.job["job_id"]],
                ),
                requested_by=OPERATOR,
                idempotency_key="key-dep-ok",
            )
        assert dependent.job["depends_on"] == [first.job["job_id"]]
        assert rows(
            dsn,
            "SELECT depends_on_job_id::text FROM job_dependency WHERE job_id = %s",
            (dependent.job["job_id"],),
        ) == [(first.job["job_id"],)]


def test_cycle_detector_refuses_a_closing_edge() -> None:
    edges = {"a": {"b"}, "b": {"c"}, "c": set()}
    assert find_cycle(edges, "a") is None
    edges["c"] = {"a"}
    assert find_cycle(edges, "a") == ["a", "b", "c", "a"]


def test_retry_and_conflicting_scheduling() -> None:
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        with service(dsn) as jobs:
            first = jobs.submit(
                body(campaign), requested_by=OPERATOR, idempotency_key="key-retry-1"
            )
            retry = jobs.submit(
                body(campaign), requested_by=OPERATOR, idempotency_key="key-retry-1"
            )
            assert retry.replayed is True and retry.job["job_id"] == first.job["job_id"]

            with pytest.raises(M05Error) as conflict:
                jobs.submit(
                    body(campaign, priority=80),
                    requested_by=OPERATOR,
                    idempotency_key="key-retry-1",
                )
            assert conflict.value.refusal.code == "IDEMPOTENCY_CONFLICT"

            # Same scan (pinned scan_cycle), different key: the job is returned, not duplicated.
            replay = jobs.submit(
                body(campaign, scan_cycle=first.job["scan_cycle"]),
                requested_by=OPERATOR,
                idempotency_key="key-retry-2",
            )
            assert replay.replayed is True and replay.job["job_id"] == first.job["job_id"]
            # Same scan with different scheduling is a conflict, never a silent merge (X-1).
            with pytest.raises(M05Error) as scheduling:
                jobs.submit(
                    body(campaign, scan_cycle=first.job["scan_cycle"], priority=70),
                    requested_by=OPERATOR,
                    idempotency_key="key-retry-3",
                )
            assert scheduling.value.refusal.code == "IDEMPOTENCY_CONFLICT"
            assert "different scheduling" in scheduling.value.refusal.message
            # Without a pinned scan_cycle the contract says "new scan" - a new job, not a replay.
            new_scan = jobs.submit(
                body(campaign), requested_by=OPERATOR, idempotency_key="key-retry-4"
            )
            assert new_scan.replayed is False and new_scan.job["job_id"] != first.job["job_id"]
        assert scalar(dsn, "SELECT count(*) FROM scan_job") == 2
        assert scalar(dsn, "SELECT count(*) FROM policy_decision") == 2


def test_a_concurrent_duplicate_is_recovered_by_the_unique_constraint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The loser of a same-fingerprint race must answer with the winner, not a 500."""
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        with service(dsn) as jobs:
            first = jobs.submit(body(campaign), requested_by=OPERATOR, idempotency_key="key-race-1")
            real_lookup = PostgresJobService._existing_fingerprint
            calls = {"n": 0}

            def blind_first_lookup(
                self: PostgresJobService, conn: Any, fingerprint: str
            ) -> str | None:
                calls["n"] += 1
                if calls["n"] == 1:
                    return None  # pretend the racing submission has not committed yet
                return real_lookup(self, conn, fingerprint)

            monkeypatch.setattr(PostgresJobService, "_existing_fingerprint", blind_first_lookup)
            second = jobs.submit(
                body(campaign, scan_cycle=first.job["scan_cycle"]),
                requested_by=OPERATOR,
                idempotency_key="key-race-2",
            )
        assert calls["n"] >= 2, "the insert had to hit the unique constraint and recover"
        assert second.replayed is True
        assert second.job["job_id"] == first.job["job_id"]
        assert scalar(dsn, "SELECT count(*) FROM scan_job") == 1


def test_scan_cycle_is_the_new_scan_switch() -> None:
    from aegis.m05_registry.ids import uuid7

    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        with service(dsn) as jobs:
            first = jobs.submit(
                body(campaign), requested_by=OPERATOR, idempotency_key="key-cycle-1"
            )
            second = jobs.submit(
                body(campaign, scan_cycle=uuid7()),
                requested_by=OPERATOR,
                idempotency_key="key-cycle-2",
            )
        assert first.job["job_id"] != second.job["job_id"]
        assert first.job["job_fingerprint"] != second.job["job_fingerprint"]
        assert scalar(dsn, "SELECT count(*) FROM scan_job") == 2


def test_terminal_campaign_and_deny_lists_refuse_before_a_job_exists() -> None:
    with migrated_database() as dsn:
        completed = seed_campaign(dsn, status="COMPLETED")
        with service(dsn) as jobs, pytest.raises(M05Error) as terminal:
            jobs.submit(body(completed), requested_by=OPERATOR, idempotency_key="key-terminal")
        assert terminal.value.refusal.rule == "campaign_terminal"

        denied = seed_campaign(
            dsn, policy=policy_document(capability_denylist=["dns.enumerate_subdomains"])
        )
        with service(dsn) as jobs, pytest.raises(M05Error) as denied_error:
            jobs.submit(body(denied), requested_by=OPERATOR, idempotency_key="key-denied-cap")
        assert denied_error.value.refusal.rule == "capability_denied"

        scoped = seed_campaign(dsn, policy=policy_document(target_denylist=["internal.example"]))
        with service(dsn) as jobs, pytest.raises(M05Error) as scope_error:
            jobs.submit(body(scoped), requested_by=OPERATOR, idempotency_key="key-denied-target")
        assert scope_error.value.refusal.code == "OUT_OF_SCOPE"
        assert scope_error.value.refusal.rule == "target_denied"
        assert scalar(dsn, "SELECT count(*) FROM scan_job") == 0


def test_target_bound_binding_pins_resolved_addresses_and_drops_the_deny_set() -> None:
    """E-1 for `targetBinding: required`: M05 resolves, pins and signs the addresses it verified."""
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        from aegis.m05_registry.ids import uuid7

        with connect(dsn) as conn, conn.transaction():
            conn.execute(
                "INSERT INTO campaign_target (target_id, scope_id, kind, raw_value, canonical_key) "
                "VALUES (%s, %s, 'ip', '127.0.0.1', 'ip:127.0.0.1')",
                (uuid7(), campaign.scope_id),
            )
        registry = PostgresManifestRegistry(lambda: connect(dsn))
        registry.register(
            (REPO_ROOT / "contracts/fixtures/valid/manifest.naabu.yaml").read_bytes(),
            registered_by={"kind": "module", "id": "M05"},
        )
        registry.register(
            (REPO_ROOT / "contracts/fixtures/valid/manifest.subfinder.yaml").read_bytes(),
            registered_by={"kind": "module", "id": "M05"},
        )
        jobs = PostgresJobService(
            lambda: connect(dsn), registry=registry, key_ring=KeyRing.dev(), binder=FakeBinder()
        )
        accepted = jobs.submit(
            JobSubmit.model_validate(
                {
                    "campaign_id": campaign.campaign_id,
                    "capability": "network.discover_services",
                    "input": {"targets": ["ip:" + campaign.seed_ip], "ports": [443]},
                    "rationale": "target-bound egress binding (E-1)",
                }
            ),
            requested_by=OPERATOR,
            idempotency_key="key-target-bound",
        )
        task = scalar(
            dsn, "SELECT approved_task FROM scan_job WHERE job_id = %s", (accepted.job["job_id"],)
        )
        assert task["egress_binding"] == {
            "mode": "broker",
            "target_binding": "required",
            "entries": ["10.114.53.53:443"],
            "target_addresses": ["10.114.53.53"],
        }
        assert KeyRing.dev().verify(task) == "g1-dev-1"

        # The deny set wins over a resolved target address (OI-5): a loopback seed opens nothing.
        with pytest.raises(M05Error) as denied:
            jobs.submit(
                JobSubmit.model_validate(
                    {
                        "campaign_id": campaign.campaign_id,
                        "capability": "network.discover_services",
                        "input": {"targets": ["ip:127.0.0.1"], "ports": [443]},
                        "rationale": "loopback target must never be opened",
                    }
                ),
                requested_by=OPERATOR,
                idempotency_key="key-target-denied",
            )
        assert denied.value.refusal.code == "OUT_OF_SCOPE", denied.value.refusal.message
        assert denied.value.refusal.rule == "target_denied"


def test_a_discovered_address_asset_target_binds_its_canonical_key() -> None:
    """The address-targeted capability takes `ip:` keys; the binding must read the key's address.

    Root cause this covers: `build_egress_binding` handed the *raw input text* to the IP parser,
    so a target that was an asset the campaign had discovered (`ip:<address>`, the only form the
    capability schema accepts for an address asset) was refused as "not an IP address" while the
    same address worked as a seed. The key prefix is notation, not part of the address.
    """
    with migrated_database() as dsn:
        campaign = seed_campaign(dsn)
        from aegis.m05_registry.ids import uuid7

        address = "203.0.113.10"
        with connect(dsn) as conn, conn.transaction():
            asset_id = uuid7()
            conn.execute(
                "INSERT INTO asset (asset_id, canonical_key, kind, first_seen, last_seen,"
                " normalization_version) VALUES (%s, %s, 'ip', now(), now(), 'aegis-norm/1')",
                (asset_id, f"ip:{address}"),
            )
            conn.execute(
                "INSERT INTO asset_campaign (asset_id, campaign_id, first_seen)"
                " VALUES (%s, %s, now())",
                (asset_id, campaign.campaign_id),
            )
        registry = PostgresManifestRegistry(lambda: connect(dsn))
        registry.register(
            (REPO_ROOT / "contracts/fixtures/valid/manifest.naabu.yaml").read_bytes(),
            registered_by={"kind": "module", "id": "M05"},
        )
        jobs = PostgresJobService(
            lambda: connect(dsn), registry=registry, key_ring=KeyRing.dev(), binder=FakeBinder()
        )
        accepted = jobs.submit(
            JobSubmit.model_validate(
                {
                    "campaign_id": campaign.campaign_id,
                    "capability": "network.discover_services",
                    "input": {"targets": [f"ip:{address}"], "ports": [443, 80]},
                    "rationale": "a discovered address is a target, and its key is notation",
                }
            ),
            requested_by=OPERATOR,
            idempotency_key="key-asset-target-bound",
        )
        task = scalar(
            dsn, "SELECT approved_task FROM scan_job WHERE job_id = %s", (accepted.job["job_id"],)
        )
        assert task["targets"] == [{"canonical_key": f"ip:{address}"}]
        assert task["egress_binding"] == {
            "mode": "broker",
            "target_binding": "required",
            "entries": [f"{address}:443", f"{address}:80"],
            "target_addresses": [address],
        }
        assert KeyRing.dev().verify(task) == "g1-dev-1"
