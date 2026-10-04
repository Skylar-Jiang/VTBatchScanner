from datetime import UTC, datetime

from app.services.quota import DailyQuota


def test_cverc_quota_counts_failed_retries_and_stops_at_daily_limit() -> None:
    quota = DailyQuota(limit=2)
    now = datetime(2026, 9, 14, 8, 0, tzinfo=UTC)

    assert quota.reserve(now, 1).allowed is True
    assert quota.reserve(now, 1).allowed is True

    blocked = quota.reserve(now, 1)
    assert blocked.allowed is False
    assert blocked.remaining == 0
