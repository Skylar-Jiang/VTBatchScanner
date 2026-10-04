from fastapi.testclient import TestClient

from app.main import create_app


def test_hash_preview_endpoint_returns_contract_shape() -> None:
    client = TestClient(create_app())

    response = client.post(
        "/api/v1/batch-previews/hashes",
        json={"inputSource": "paste", "values": ["b" * 64, "invalid"]},
    )

    assert response.status_code == 200
    payload = response.json()["data"]
    assert payload["validSha256s"] == ["b" * 64]
    assert payload["invalid"][0]["reason"] == "invalid_format"
    assert payload["canCreate"] is True

