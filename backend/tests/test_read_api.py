from pathlib import Path

from fastapi.testclient import TestClient

from app.main import create_app


def test_local_read_endpoints_do_not_probe_providers(tmp_path: Path) -> None:
    client = TestClient(
        create_app(
            database_url=f"sqlite:///{tmp_path / 'analysis.db'}",
            cverc_enabled_reports=("reputation",),
        )
    )
    sha256 = "d" * 64
    client.post(
        "/api/v1/batches",
        json={"name": "课堂样本", "inputSource": "paste", "sha256s": [sha256]},
    )

    samples = client.get("/api/v1/samples")
    assert samples.status_code == 200
    assert samples.json()["data"][0]["sha256"] == sha256

    detail = client.get(f"/api/v1/samples/{sha256}")
    assert detail.status_code == 200
    assert detail.json()["data"]["providerResults"][0]["status"] == "pending"

    dashboard = client.get("/api/v1/dashboard")
    assert dashboard.status_code == 200
    assert dashboard.json()["data"]["samples"]["total"] == 1

    provider_status = client.get("/api/v1/providers/status")
    cverc = next(item for item in provider_status.json()["data"] if item["provider"] == "cn_platform")
    assert cverc["enabledReports"] == ["reputation"]
    assert cverc["quota"]["used"] == 0

    reanalysis = client.post(f"/api/v1/samples/{sha256}/reanalysis/prepare", json={"providers": ["cn_platform"]})
    assert reanalysis.status_code == 409
