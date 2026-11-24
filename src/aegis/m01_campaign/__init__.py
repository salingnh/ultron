"""M01: campaign, its seed targets and its RoE snapshots (C02/G5, C06 actions).

The API layer (`aegis.m26_api.campaigns`) owns HTTP, identity and idempotency; this
package owns the rows. Nothing here imports FastAPI, so the module can be driven by
a worker, a CLI or a test without an app.
"""

from __future__ import annotations

from .audit import record_audit
from .campaigns import CreatedCampaign, create_campaign, get_campaign, list_campaigns, timestamp
from .errors import CampaignNotFound, CampaignStateConflict, CampaignStoreError
from .ids import new_id, uuid7
from .policy import adopt_policy
from .status import ACTIONS, change_status
from .targets import (
    NORM_VERSION,
    SEED_ARRAY_KINDS,
    SeedIdentityError,
    SeedTarget,
    insert_seeds,
    seed_canonical_key,
    seed_targets,
)

__all__ = [
    "ACTIONS",
    "CampaignNotFound",
    "CampaignStateConflict",
    "CampaignStoreError",
    "CreatedCampaign",
    "NORM_VERSION",
    "SEED_ARRAY_KINDS",
    "SeedIdentityError",
    "SeedTarget",
    "adopt_policy",
    "change_status",
    "create_campaign",
    "get_campaign",
    "insert_seeds",
    "list_campaigns",
    "new_id",
    "record_audit",
    "seed_canonical_key",
    "seed_targets",
    "timestamp",
    "uuid7",
]
