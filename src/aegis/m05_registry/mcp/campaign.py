"""The campaign facts `tools/list` needs: which capabilities this campaign may not run.

`contracts/mcp/README.md` requires the published tool list to be filtered by the campaign's
`capability_denylist`; the policy lives in `policy_snapshot` (0001) and the campaign points at its
current version. Reading it per `tools/list` (instead of caching it in the session) means an adopted
policy takes effect on the next list, which is what "the request must fit the campaign snapshot"
means at the point of publication.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, Protocol

import psycopg

__all__ = ["InMemoryCampaignPolicies", "PostgresCampaignPolicies", "PolicySource"]


class PolicySource(Protocol):
    def capability_denylist(self, campaign_id: str) -> frozenset[str]:
        """Capability ids the campaign's current policy snapshot forbids."""
        ...


class InMemoryCampaignPolicies:
    def __init__(self, denylists: Mapping[str, frozenset[str]] | None = None) -> None:
        self._denylists = dict(denylists or {})

    def capability_denylist(self, campaign_id: str) -> frozenset[str]:
        return self._denylists.get(campaign_id, frozenset())


class PostgresCampaignPolicies:
    def __init__(self, connect: Callable[[], psycopg.Connection[Any]]) -> None:
        self._connect = connect

    def capability_denylist(self, campaign_id: str) -> frozenset[str]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT p.policy FROM campaign c JOIN policy_snapshot p "
                "ON p.policy_version = c.current_policy_version WHERE c.campaign_id = %s",
                (campaign_id,),
            ).fetchone()
        if row is None or not isinstance(row[0], Mapping):
            return frozenset()
        denied = row[0].get("capability_denylist") or []
        return frozenset(str(item) for item in denied)
