"""Small runtime helpers shared by activities and the LangGraph nodes."""

from __future__ import annotations

from typing import Any

from temporalio import activity


def in_activity() -> bool:
    return activity.in_activity()


def current_attempt() -> int:
    return activity.info().attempt if in_activity() else 1


def beat(payload: dict[str, Any] | None = None) -> None:
    """Heartbeat only when running inside a Temporal activity (graph unit tests run outside)."""
    if in_activity():
        activity.heartbeat(payload)
