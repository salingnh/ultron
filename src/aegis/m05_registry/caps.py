"""InputDefaults merge + validation, and the campaign-cap checks a submission must pass.

Two different refusals, kept apart on purpose:

* the merged input must satisfy the pinned capability schema (`INPUT_INVALID`, 400). `inputDefaults`
  is merged first, exactly like the conformance reference does (`{**defaults, **input}`), and the
  *merged* value is what M05 stores in the decision and the job - 0014 compares those two rows, and
  the
  runner executes that value (contracts/README.md:89).
* the request must fit the campaign snapshot and the pinned manifest (`POLICY_DENIED` or
  `RATE_LIMITED`,
  403/429): capability denylist, target denylist, `budget.max_jobs`, `rate_limits.jobs_per_minute`,
  and the two ceilings the contract states for input - `concurrency` vs the pinned
  `budget.maxConcurrency`, `rate_limit` vs `rate_limits.requests_per_second_per_host`. The scheduler
  owns windows/parallelism/budget at dispatch time (G1.1d); M05 refuses what the campaign
  configuration
  already forbids at acceptance time.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import psycopg

from aegis import validation
from aegis.m05_registry.errors import M05Error
from aegis.m05_registry.manifest import ManifestRecord

__all__ = [
    "CampaignPolicy",
    "check_campaign_caps",
    "merge_input",
    "network_profile",
]

#: The profile a campaign with no `network_profile` in its RoE runs on: the operator default is
#: the internet profile; demo/CI set `lab` explicitly (G1.6).
DEFAULT_NETWORK_PROFILE = "internet"
PROFILES = frozenset({"lab", "internet"})


def network_profile(policy: Mapping[str, Any]) -> str:
    """The campaign's network profile, signed into every task it produces."""
    value = policy.get("network_profile")
    profile = DEFAULT_NETWORK_PROFILE if value is None else str(value)
    if profile not in PROFILES:
        # The schema and the DDL already close the enum; this is the fail-closed read in M05.
        raise M05Error.policy_denied(
            "network_profile_unknown",
            f"campaign RoE names an unknown network_profile {profile!r}",
            field="/policy/network_profile",
        )
    return profile


def merge_input(record: ManifestRecord, submitted: Mapping[str, Any]) -> dict[str, Any]:
    """Merge `inputDefaults` under the submitted input and validate the result against the pin."""
    defaults = record.spec.get("inputDefaults") or {}
    if not isinstance(defaults, Mapping):
        raise validation.ContractUnavailable(
            f"{record.provider}: manifest inputDefaults is not an object"
        )
    merged: dict[str, Any] = {}
    for key, value in defaults.items():
        merged[str(key)] = value
    for key, value in submitted.items():
        merged[str(key)] = value
    # One validator for structure and for the aegis-* semantic formats: the shared hook.
    found = validation.problems(_schema_path(record.input_schema_ref), merged)
    if found:
        pointer, message = found[0]
        raise M05Error.input_invalid(
            f"input does not satisfy the pinned schema {record.input_schema_ref}: {message}",
            field=f"/input{pointer}" if pointer else "/input",
        )
    for field_name in defaults:
        if field_name not in merged:  # pragma: no cover - merged always contains its own defaults
            raise M05Error.policy_denied(
                "input_defaults",
                f"inputDefaults field {field_name!r} is missing from the merged input",
                field=f"/input/{field_name}",
            )
    return merged


def _schema_path(reference: str) -> str:
    from aegis.m05_registry.manifest import schema_reference_path

    path = schema_reference_path(reference)
    if path is None:
        raise validation.ContractUnavailable(f"unresolvable input schema reference {reference!r}")
    return path


@dataclass(frozen=True, slots=True)
class CampaignPolicy:
    """The immutable policy snapshot a decision is made against, plus campaign identity."""

    campaign_id: str
    policy_version: str
    scope_id: str
    policy: Mapping[str, Any]


def _denied_target(value: str, deny_list: list[str]) -> bool:
    candidate = value.strip().lower().rstrip(".")
    if candidate.startswith("dns:"):
        candidate = candidate[4:]
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        address = None
    for entry in deny_list:
        item = str(entry).strip().lower().rstrip(".")
        if not item:
            continue
        if "/" in item:
            try:
                network = ipaddress.ip_network(item, strict=False)
            except ValueError:
                continue
            if address is not None and address.version == network.version and address in network:
                return True
            continue
        if candidate == item or candidate.endswith("." + item):
            return True
    return False


def check_campaign_caps(
    conn: psycopg.Connection[Any],
    *,
    policy: CampaignPolicy,
    record: ManifestRecord,
    merged_input: Mapping[str, Any],
    raw_targets: list[str],
) -> None:
    """Refuse a request the campaign snapshot or the pinned manifest already forbids."""
    document = policy.policy
    capability = record.capability

    denylist = document.get("capability_denylist") or []
    if capability in denylist:
        raise M05Error.policy_denied(
            "capability_denied",
            f"capability {capability} is denied by policy {policy.policy_version}",
        )

    target_denylist = [str(entry) for entry in document.get("target_denylist") or []]
    for index, value in enumerate(raw_targets):
        if _denied_target(value, target_denylist):
            raise M05Error.out_of_scope(
                "target_denied",
                f"target {value!r} is on the campaign target_denylist",
                field=f"/input/targets/{index}",
            )

    budget = document.get("budget") or {}
    max_jobs = budget.get("max_jobs")
    if isinstance(max_jobs, int):
        accepted = conn.execute(
            "SELECT count(*) FROM scan_job WHERE campaign_id = %s AND status <> 'CANCELLED'",
            (policy.campaign_id,),
        ).fetchone()
        if accepted is not None and int(accepted[0]) >= max_jobs:
            raise M05Error.policy_denied(
                "budget_max_jobs",
                f"campaign {policy.campaign_id} already accepted {int(accepted[0])} job(s); "
                f"policy {policy.policy_version} allows {max_jobs}",
            )

    rate_limits = document.get("rate_limits") or {}
    jobs_per_minute = rate_limits.get("jobs_per_minute")
    if isinstance(jobs_per_minute, int):
        recent = conn.execute(
            "SELECT count(*), ceil(extract(epoch FROM "
            "(now() - (min(created_at) + interval '1 minute')))) "
            "FROM scan_job WHERE campaign_id = %s AND created_at > now() - interval '1 minute'",
            (policy.campaign_id,),
        ).fetchone()
        if recent is not None and int(recent[0]) >= jobs_per_minute:
            wait = int(recent[1]) if recent[1] is not None else 60
            raise M05Error.rate_limited(
                "rate_jobs_per_minute",
                f"campaign {policy.campaign_id} accepted {int(recent[0])} job(s) in the last "
                f"minute; "
                f"policy {policy.policy_version} allows {jobs_per_minute} per minute",
                retry_after_seconds=max(1, min(60, wait)),
            )

    budget_caps = record.spec.get("budget") or {}
    concurrency = merged_input.get("concurrency")
    max_concurrency = budget_caps.get("maxConcurrency")
    if (
        concurrency is not None
        and isinstance(max_concurrency, int)
        and concurrency > max_concurrency
    ):
        raise M05Error.policy_denied(
            "concurrency_cap",
            f"concurrency {concurrency} exceeds the pinned manifest cap {max_concurrency}",
            field="/input/concurrency",
        )

    rate_limit = merged_input.get("rate_limit")
    if rate_limit is not None:
        campaign_rate = rate_limits.get("requests_per_second_per_host")
        if campaign_rate is None:
            raise M05Error.policy_denied(
                "rate_limit_unbounded",
                f"policy {policy.policy_version} declares no requests_per_second_per_host cap, "
                f"so a "
                "rate_limit cannot be enforced",
                field="/input/rate_limit",
            )
        if rate_limit > campaign_rate:
            raise M05Error.policy_denied(
                "rate_limit_cap",
                f"rate_limit {rate_limit} exceeds the campaign cap {campaign_rate}",
                field="/input/rate_limit",
            )
