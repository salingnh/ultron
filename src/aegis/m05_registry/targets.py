"""TargetRef resolution (C02/P3a): raw input values become seeds of the campaign or known assets.

The contract (job-submit/capability-request input descriptions) is explicit about what M05 may
do:

* a raw value that matches a `campaign_target` of the campaign/scope becomes `{seed_id}` - including
  keyword/CIDR/email seeds, which have no canonical key; the seed is never replaced by an asset;
* otherwise the value must name an asset the campaign already knows (`asset_campaign`), and becomes
  `{canonical_key}`; this is P3a - a canonical key for an unknown asset is INPUT_INVALID, not a new
  asset and not a silent alias;
* a value matching nothing, or matching more than one seed, is INPUT_INVALID with the offending
index.

`targets` (the `text[]` projection) is only the canonical_key subset of those refs (0012's
projection
rule); it is never the identity source.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import psycopg

from aegis.m05_registry.errors import M05Error

__all__ = ["ResolvedTargets", "asset_kind", "resolve_targets"]

CANONICAL_PREFIX = re.compile(
    r"^(dns|ip|service|app|url|email|oci|repo|git|artifact|purl|cloud|k8s):"
)
PREFIX_KINDS = {
    "dns": "domain",
    "ip": "ip",
    "service": "service",
    "app": "application",
    "url": "url",
    "email": "email",
    "oci": "oci_image",
    "repo": "repo",
    "git": "repo",
    "artifact": "artifact",
    "purl": "package",
    "cloud": "cloud_resource",
    "k8s": "k8s_workload",
}


def asset_kind(canonical_key: str) -> str:
    """Asset kind implied by a canonical key prefix (`dns:` -> `domain`, ...)."""
    match = CANONICAL_PREFIX.match(canonical_key)
    return PREFIX_KINDS.get(match.group(1), "unknown") if match else "unknown"


@dataclass(frozen=True, slots=True)
class ResolvedTargets:
    """Resolved TargetRefs, the kind of each, and the raw value each came from."""

    refs: tuple[dict[str, str], ...]
    kinds: tuple[str, ...]
    raw: tuple[str, ...]

    @property
    def projection(self) -> list[str]:
        """The canonical_key subset, in ref order (0012 projection rule)."""
        return [ref["canonical_key"] for ref in self.refs if "canonical_key" in ref]


def _matches_seed(text: str, candidate: str, raw_value: str, canonical_key: str | None) -> bool:
    """A value names a seed when it is its raw form, its canonical key, or that key minus `dns:`."""
    raw = (raw_value or "").lower().rstrip(".")
    key = (canonical_key or "").lower()
    if key and text == key:
        return True
    return candidate == raw or (bool(key) and f"dns:{candidate}" == key)


def _canonical_candidates(text: str, candidate: str) -> tuple[str, ...]:
    """Keys a raw value may name, in priority order (a `dns:` prefix is the common case)."""
    if CANONICAL_PREFIX.match(text):
        return (text,)
    return (f"dns:{candidate}", text)


def resolve_targets(
    conn: psycopg.Connection[Any],
    *,
    campaign_id: str,
    scope_id: str,
    values: Sequence[Any],
) -> ResolvedTargets:
    """Resolve raw input targets to TargetRefs; refuse unknowns and ambiguity (400, no decision)."""
    if not values:
        raise M05Error.input_invalid(
            "input.targets must name at least one campaign seed or known asset",
            field="/input/targets",
        )
    seeds = conn.execute(
        "SELECT ct.target_id, ct.kind, ct.raw_value, ct.canonical_key "
        "FROM campaign_target ct JOIN campaign c ON c.campaign_id = %s "
        "WHERE ct.scope_id = c.scope_id AND ct.scope_id = %s ORDER BY ct.created_at, ct.target_id",
        (campaign_id, scope_id),
    ).fetchall()

    refs: list[dict[str, str]] = []
    kinds: list[str] = []
    raw_values: list[str] = []
    seen: set[str] = set()
    pending: list[tuple[int, str, str]] = []  # (index, normalized text, bare candidate)

    for index, value in enumerate(values):
        text = str(value).strip().lower().rstrip(".")
        candidate = text[4:] if text.startswith("dns:") else text
        matches = [seed for seed in seeds if _matches_seed(text, candidate, str(seed[2]), seed[3])]
        if len(matches) > 1:
            raise M05Error.input_invalid(
                f"target {value!r} matches {len(matches)} campaign seeds",
                field=f"/input/targets/{index}",
            )
        if not matches:
            pending.append((index, text, candidate))
            continue
        seed = matches[0]
        ref = {"seed_id": str(seed[0])}
        if ref["seed_id"] in seen:
            continue
        seen.add(ref["seed_id"])
        refs.append(ref)
        kinds.append(str(seed[1]))
        raw_values.append(str(seed[2]))

    if pending:
        candidates = sorted(
            {
                key
                for _, text, candidate in pending
                for key in _canonical_candidates(text, candidate)
            }
        )
        known = {
            str(row[0]): str(row[1])
            for row in conn.execute(
                "SELECT a.canonical_key, a.kind FROM asset a "
                "JOIN asset_campaign ac ON ac.asset_id = a.asset_id "
                "WHERE ac.campaign_id = %s AND a.canonical_key = ANY(%s)",
                (campaign_id, candidates),
            ).fetchall()
        }
        for index, text, candidate in pending:
            canonical = next(
                (key for key in _canonical_candidates(text, candidate) if key in known), None
            )
            if canonical is None:
                raise M05Error.input_invalid(
                    f"target {text!r} is neither a campaign seed nor an asset this campaign knows",
                    field=f"/input/targets/{index}",
                )
            if canonical in seen:
                continue
            seen.add(canonical)
            refs.append({"canonical_key": canonical})
            kinds.append(known[canonical])
            raw_values.append(text)

    if not refs:
        raise M05Error.input_invalid("no target could be resolved", field="/input/targets")
    return ResolvedTargets(refs=tuple(refs), kinds=tuple(kinds), raw=tuple(raw_values))
