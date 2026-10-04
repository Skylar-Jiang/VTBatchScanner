from __future__ import annotations

from collections.abc import Iterable

import httpx

from app.providers.result import ProviderFetch


REPORT_PATHS = {
    "reputation": "/api/v1/file/report",
    "multiscan": "/api/v1/file/multiscan/report",
    "static": "/api/v1/file/staticinfo/report",
    "dynamics": "/api/v1/file/dynamics/report",
}
REPORT_ORDER = tuple(REPORT_PATHS)


class CnPlatformProvider:
    def __init__(
        self,
        api_key: str,
        enabled_reports: Iterable[str],
        client: httpx.Client | None = None,
    ) -> None:
        self.api_key = api_key
        self._client = client or httpx.Client(base_url="https://virus.cverc.org.cn", timeout=20.0)
        enabled = set(enabled_reports)
        unknown = enabled.difference(REPORT_PATHS)
        if unknown:
            raise ValueError(f"Unsupported CVERC report kinds: {sorted(unknown)}")
        self.enabled_report_kinds = tuple(
            report_kind for report_kind in REPORT_ORDER if report_kind in enabled
        )

    def request_path_for(self, report_kind: str) -> str:
        if report_kind not in self.enabled_report_kinds:
            raise ValueError(f"CVERC report kind is not enabled: {report_kind}")
        return REPORT_PATHS[report_kind]

    def fetch(self, sha256: str, report_kind: str) -> ProviderFetch:
        try:
            response = self._client.post(
                self.request_path_for(report_kind),
                headers={"accept": "application/json"},
                json={"apikey": self.api_key, "hash": sha256},
            )
        except httpx.TimeoutException:
            return ProviderFetch(status="timeout", raw=None, error="Provider request timed out")
        except httpx.HTTPError:
            return ProviderFetch(status="failed", raw=None, error="Provider request failed")
        if response.status_code in {401, 403}:
            return ProviderFetch(status="authentication_error", raw=None, error="Provider authentication failed")
        if response.status_code == 429:
            return ProviderFetch(status="rate_limited", raw=None, error="Provider rate limit reached")
        if response.status_code >= 500:
            return ProviderFetch(status="failed", raw=None, error="Provider service error")
        if response.status_code >= 400:
            return ProviderFetch(status="failed", raw=None, error="Provider rejected the request")
        try:
            raw = response.json()
        except ValueError:
            return ProviderFetch(status="failed", raw=None, error="Provider returned invalid JSON")
        if not isinstance(raw, dict):
            return ProviderFetch(status="failed", raw=None, error="Provider returned unexpected JSON")
        return ProviderFetch(status=self._status_from_code(raw.get("code")), raw=raw)

    @staticmethod
    def _status_from_code(code: object) -> str:
        try:
            normalized = int(str(code))
        except (TypeError, ValueError):
            return "failed"
        return {
            0: "success",
            2: "not_found",
            3: "running",
            4: "running",
            5: "timeout",
            -1: "authentication_error",
        }.get(normalized, "failed")
