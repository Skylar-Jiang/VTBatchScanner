from app.providers.cn_platform import CnPlatformProvider


def test_cverc_only_builds_requests_for_explicitly_enabled_reports() -> None:
    provider = CnPlatformProvider(
        api_key="test-key",
        enabled_reports={"reputation", "multiscan"},
    )

    assert provider.enabled_report_kinds == ("reputation", "multiscan")
    assert "static" not in provider.enabled_report_kinds
    assert "dynamics" not in provider.enabled_report_kinds
