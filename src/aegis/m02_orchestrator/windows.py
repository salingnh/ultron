"""Allowed/blackout windows of a campaign policy (roe-policy.v2 `TimeWindow`).

The contract fixes the semantics: half-open `[start, end)` in the window's local timezone, `days`
are the days the window starts on, `end < start` continues into the next day, `start = end` is an
empty window, `24:00` is only a valid end and closes the start day. A DST hour that is repeated
matches both occurrences; an hour that does not exist (spring forward) creates no instant, so no
job is inside the skipped interval.

The comparison is done on the local wall clock, deliberately: a repeated hour has two instants
that map to the same local time (both must match), and a skipped hour has no instant that maps
into it (so nothing can match). Converting the window bounds to instants instead would need
ambiguity resolution (`fold`) and would make one of the two repeated occurrences unreachable.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, date, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

__all__ = ["blackout_active", "windows_open"]

_DAY_KEYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_END_OF_DAY = 24 * 60


def _minutes(value: str) -> int:
    hours, minutes = value.split(":")
    return int(hours) * 60 + int(minutes)


def _bounds(window: Mapping[str, Any], start_day: date) -> tuple[datetime, datetime] | None:
    """Local naive `[start, end)` of the occurrence starting on `start_day`, or None if empty."""
    start_minute = _minutes(str(window["start"]))
    end_minute = _END_OF_DAY if str(window["end"]) == "24:00" else _minutes(str(window["end"]))
    if end_minute == start_minute:
        return None  # start = end is an empty window
    if end_minute < start_minute:
        end_day = start_day + timedelta(days=1)
    else:
        end_day = start_day
    return (
        datetime.combine(start_day, datetime.min.time()) + timedelta(minutes=start_minute),
        datetime.combine(end_day, datetime.min.time()) + timedelta(minutes=end_minute),
    )


def window_active(window: Mapping[str, Any], moment: datetime) -> bool:
    """True when `moment` (timezone-aware) falls inside one occurrence of `window`."""
    timezone = ZoneInfo(str(window["timezone"]))
    local = moment.astimezone(timezone).replace(tzinfo=None)
    days = {str(day).lower() for day in window.get("days") or ()}
    # A window can only contain `local` if it started today or yesterday (overnight windows).
    for offset in (0, -1):
        start_day = local.date() + timedelta(days=offset)
        if _DAY_KEYS[start_day.weekday()] not in days:
            continue
        bounds = _bounds(window, start_day)
        if bounds is None:
            continue
        start, end = bounds
        if start <= local < end:
            return True
    return False


def _any_active(windows: Sequence[Any], moment: datetime) -> bool:
    return any(window_active(dict(entry), moment) for entry in windows)


def blackout_active(policy: Mapping[str, Any], moment: datetime) -> bool:
    """True when a `blackout_windows` entry covers `moment`."""
    return _any_active(policy.get("blackout_windows") or (), moment)


def windows_open(policy: Mapping[str, Any], moment: datetime) -> bool:
    """False when dispatch is closed by the policy windows at `moment`.

    An absent or empty `allowed_windows` list means "any time"; a blackout entry always wins.
    """
    if blackout_active(policy, moment):
        return False
    allowed = list(policy.get("allowed_windows") or ())
    if not allowed:
        return True
    return _any_active(allowed, moment)


def utcnow() -> datetime:
    return datetime.now(UTC)
