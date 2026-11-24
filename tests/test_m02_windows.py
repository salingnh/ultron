"""roe-policy.v2 TimeWindow semantics used by the scheduler (no database)."""

from __future__ import annotations

from datetime import UTC, datetime

from aegis.m02_orchestrator.windows import blackout_active, windows_open


def _window(days: list[str], start: str, end: str, timezone: str = "UTC") -> dict[str, object]:
    return {"days": days, "start": start, "end": end, "timezone": timezone}


def _at(year: int, month: int, day: int, hour: int, minute: int = 0) -> datetime:
    return datetime(year, month, day, hour, minute, tzinfo=UTC)


def test_same_day_window_is_half_open() -> None:
    policy = {"allowed_windows": [_window(["mon"], "09:00", "17:00")]}
    assert windows_open(policy, _at(2026, 11, 23, 9, 0)) is True
    assert windows_open(policy, _at(2026, 11, 23, 16, 59)) is True
    assert windows_open(policy, _at(2026, 11, 23, 8, 59)) is False
    assert windows_open(policy, _at(2026, 11, 23, 17, 0)) is False
    assert windows_open(policy, _at(2026, 11, 24, 10, 0)) is False  # wrong day


def test_overnight_window_belongs_to_its_start_day() -> None:
    policy = {"allowed_windows": [_window(["sun"], "22:00", "02:00")]}
    assert windows_open(policy, _at(2026, 11, 22, 21, 59)) is False
    assert windows_open(policy, _at(2026, 11, 22, 22, 0)) is True
    assert windows_open(policy, _at(2026, 11, 23, 1, 59)) is True  # started Sunday
    assert windows_open(policy, _at(2026, 11, 23, 2, 0)) is False
    assert windows_open(policy, _at(2026, 11, 23, 22, 30)) is False  # Monday is not a start day


def test_end_of_day_and_empty_windows() -> None:
    assert windows_open(
        {"allowed_windows": [_window(["mon"], "22:00", "24:00")]}, _at(2026, 11, 23, 23, 59)
    )
    assert not windows_open(
        {"allowed_windows": [_window(["mon"], "22:00", "24:00")]}, _at(2026, 11, 24, 0, 0)
    )
    # start = end is an empty window: it never opens.
    assert (
        windows_open(
            {"allowed_windows": [_window(["mon"], "10:00", "10:00")]}, _at(2026, 11, 23, 10, 0)
        )
        is False
    )


def test_absent_or_empty_allowed_windows_mean_any_time() -> None:
    assert windows_open({}, _at(2026, 11, 23, 3, 0)) is True
    assert windows_open({"allowed_windows": []}, _at(2026, 11, 23, 3, 0)) is True


def test_blackout_always_wins() -> None:
    policy = {
        "allowed_windows": [_window(["mon"], "00:00", "24:00")],
        "blackout_windows": [_window(["mon"], "12:00", "13:00")],
    }
    assert windows_open(policy, _at(2026, 11, 23, 11, 59)) is True
    assert windows_open(policy, _at(2026, 11, 23, 12, 0)) is False
    assert blackout_active(policy, _at(2026, 11, 23, 12, 30)) is True
    assert blackout_active(policy, _at(2026, 11, 23, 13, 0)) is False


def test_windows_are_evaluated_in_their_timezone() -> None:
    # Asia/Ho_Chi_Minh is UTC+7: 09:00-10:00 local is 02:00-03:00 UTC.
    policy = {"allowed_windows": [_window(["mon"], "09:00", "10:00", "Asia/Ho_Chi_Minh")]}
    assert windows_open(policy, _at(2026, 11, 23, 1, 59)) is False
    assert windows_open(policy, _at(2026, 11, 23, 2, 0)) is True
    assert windows_open(policy, _at(2026, 11, 23, 2, 59)) is True
    assert windows_open(policy, _at(2026, 11, 23, 3, 0)) is False


def test_a_repeated_dst_hour_matches_both_occurrences() -> None:
    # Europe/Berlin, 2026-10-25: 03:00 CEST -> 02:00 CET, so 02:30 happens twice.
    policy = {"allowed_windows": [_window(["sun"], "02:00", "03:00", "Europe/Berlin")]}
    assert windows_open(policy, _at(2026, 10, 25, 0, 30)) is True  # 02:30 CEST
    assert windows_open(policy, _at(2026, 10, 25, 1, 30)) is True  # 02:30 CET


def test_a_window_inside_the_skipped_hour_matches_no_instant() -> None:
    # Europe/Berlin, 2026-03-29: 02:00 CET -> 03:00 CEST; no local time exists in [02:00, 03:00).
    policy = {"allowed_windows": [_window(["sun"], "02:00", "02:59", "Europe/Berlin")]}
    for hour, minute in ((0, 30), (1, 0), (1, 30), (2, 0), (3, 0)):
        assert windows_open(policy, _at(2026, 3, 29, hour, minute)) is False
