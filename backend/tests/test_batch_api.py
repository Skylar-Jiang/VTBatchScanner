from pathlib import Path

from fastapi.testclient import TestClient

from app.main import create_app


def test_create_batch_persists_samples_and_only_enabled_cverc_jobs(tmp_path: Path) -> None:
    client = TestClient(
        create_app(
            database_url=f"sqlite:///{tmp_path / 'analysis.db'}",
            cverc_enabled_reports=("reputation",),
        )
    )

    response = client.post(
        "/api/v1/batches",
        json={
            "name": "课堂样本",
            "inputSource": "paste",
            "sha256s": ["c" * 64],
        },
    )

    assert response.status_code == 201
    batch = response.json()["data"]
    assert batch["sampleCount"] == 1
    assert batch["progress"]["totalProviderJobs"] == 2

    detail = client.get(f"/api/v1/batches/{batch['id']}")
    assert detail.status_code == 200
    assert detail.json()["data"]["samples"][0]["providerStatuses"] == {
        "virustotal": "pending",
        "cn_platform": "pending",
    }
