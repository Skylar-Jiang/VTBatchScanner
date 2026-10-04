import httpx

from app.providers.cn_platform import CnPlatformProvider
from app.providers.virustotal import VirusTotalProvider


def test_cverc_mock_request_uses_only_enabled_path_and_maps_business_code() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"code": 2, "msg": "not found", "data": {}})

    provider = CnPlatformProvider(
        api_key="secret",
        enabled_reports={"reputation"},
        client=httpx.Client(base_url="https://example.test", transport=httpx.MockTransport(handler)),
    )
    result = provider.fetch("e" * 64, "reputation")

    assert result.status == "not_found"
    assert seen[0].url.path == "/api/v1/file/report"
    assert result.error is None


def test_virustotal_mock_404_maps_to_not_found_without_exposing_key() -> None:
    provider = VirusTotalProvider(
        api_key="secret",
        client=httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(404))),
    )

    result = provider.fetch("f" * 64)

    assert result.status == "not_found"
    assert result.error is None
