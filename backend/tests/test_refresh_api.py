from pathlib import Path

from fastapi.testclient import TestClient

from app.main import create_app


def test_cverc_refresh_requires_quota_acknowledgement_and_never_marks_reanalysis(tmp_path: Path) -> None:
    client = TestClient(create_app(database_url=f"sqlite:///{tmp_path / 'analysis.db'}", cverc_enabled_reports=("reputation",)))
    created = client.post("/api/v1/batches", json={"name": "课堂样本", "inputSource": "paste", "sha256s": ["a" * 64]})
    batch_id = created.json()["data"]["id"]

    missing_ack = client.post(f"/api/v1/batches/{batch_id}/refresh", json={"providers": ["cn_platform"]})
    assert missing_ack.status_code == 400

    refresh = client.post(
        f"/api/v1/batches/{batch_id}/refresh",
        json={"providers": ["cn_platform"], "acknowledgeQuotaCost": True},
    )
    assert refresh.status_code == 202
    data = refresh.json()["data"]
    assert data["operation"] == "refresh"
    assert data["reanalysisTriggered"] is False
    assert data["quota"]["estimatedRequestCost"] == 1
    assert data["quota"]["used"] == 0
