from datetime import UTC, datetime
from pathlib import Path

import httpx

from app.database import create_session_factory
from app.providers.cn_platform import CnPlatformProvider
from app.services.batches import BatchService
from app.services.dispatcher import QueryDispatcher
from app.services.quota import PersistentDailyQuota


def test_dispatcher_uses_mock_cverc_once_and_persists_quota(tmp_path: Path) -> None:
    factory = create_session_factory(f"sqlite:///{tmp_path / 'analysis.db'}")
    service = BatchService(factory, ("reputation",))
    batch = service.create("课堂样本", "paste", ["b" * 64])
    provider = CnPlatformProvider(
        "secret",
        {"reputation"},
        httpx.Client(base_url="https://example.test", transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"code": 0, "data": {}}))),
    )
    quota = PersistentDailyQuota(factory, "cn_platform", 100)

    QueryDispatcher(factory, None, provider, quota).run_batch(batch.id)

    detail = service.detail(batch.id)
    assert detail is not None
    assert detail[1][0]["providerStatuses"]["cn_platform"] == "success"
    assert quota.remaining(datetime.now(UTC)) == 99
