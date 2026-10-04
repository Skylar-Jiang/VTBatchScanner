from datetime import UTC, datetime
from pathlib import Path

from app.database import create_session_factory
from app.services.quota import PersistentDailyQuota


def test_persistent_cverc_quota_survives_new_service_instance(tmp_path: Path) -> None:
    factory = create_session_factory(f"sqlite:///{tmp_path / 'analysis.db'}")
    now = datetime(2026, 9, 14, 8, 0, tzinfo=UTC)
    quota = PersistentDailyQuota(factory, provider="cn_platform", limit=2)

    assert quota.reserve(now, 1).allowed is True
    restarted = PersistentDailyQuota(factory, provider="cn_platform", limit=2)
    assert restarted.reserve(now, 1).allowed is True
    assert restarted.reserve(now, 1).allowed is False
