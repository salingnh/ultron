"""Typed M01 failures; the M26 router maps them onto `error.v2` (no FastAPI import here)."""

from __future__ import annotations

__all__ = ["CampaignNotFound", "CampaignStateConflict", "CampaignStoreError"]


class CampaignStoreError(RuntimeError):
    """Base class for M01 domain failures that are not "not found"."""


class CampaignNotFound(LookupError):
    """The campaign id does not exist (404)."""


class CampaignStateConflict(CampaignStoreError):
    """The action is not allowed in the campaign's current state (409)."""

    def __init__(self, campaign_id: str, action: str, status: str, detail: str) -> None:
        self.campaign_id = campaign_id
        self.action = action
        self.status = status
        self.detail = detail
        super().__init__(f"campaign {campaign_id} cannot {action} while {status}: {detail}")
