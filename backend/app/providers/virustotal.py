import httpx
import re
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

from app.providers.result import ProviderFetch


class VirusTotalProvider:
    def __init__(self, api_key: str, client: httpx.Client | None = None) -> None:
        self._api_key = api_key
        self._client = client or httpx.Client(base_url="https://www.virustotal.com/api/v3", timeout=20.0)

    def fetch(self, sha256: str) -> ProviderFetch:
        sha256 = sha256.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", sha256):
            return ProviderFetch(status="invalid_hash", raw=None, error="Invalid SHA256")
        try:
            response = self._client.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers={"x-apikey": self._api_key},
            )
        except httpx.TimeoutException:
            return ProviderFetch(status="timeout", raw=None, error="Provider request timed out")
        except httpx.HTTPError:
            return ProviderFetch(status="failed", raw=None, error="Provider request failed")
        if response.status_code in {401, 403}:
            return ProviderFetch(status="authentication_error", raw=None, error="Provider authentication failed")
        if response.status_code == 404:
            return ProviderFetch(status="not_found", raw=None)
        if response.status_code == 429:
            retry_after = None
            value = response.headers.get("Retry-After", "")
            try:
                retry_after = max(0.0, float(value))
            except ValueError:
                try:
                    retry_after = max(0.0, (parsedate_to_datetime(value) - datetime.now(UTC)).total_seconds())
                except (ValueError, TypeError, OverflowError):
                    pass
            return ProviderFetch(status="rate_limited", raw=None, error="Provider rate limit reached", retry_after=retry_after)
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
        try:
            report = normalize_report(raw, sha256)
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError, OSError):
            return ProviderFetch(status="failed", raw=None, error="Provider returned invalid file report")
        return ProviderFetch(status="success", raw=raw, report=report)


def normalize_report(raw: dict, sha256: str) -> dict:
    data = raw["data"]
    if data.get("id", "").lower() != sha256:
        raise ValueError("Mismatched file hash")
    attributes = data["attributes"]
    stats = attributes.get("last_analysis_stats", {})
    if not isinstance(stats, dict) or any(type(value) is not int or value < 0 for value in stats.values()):
        raise ValueError("Invalid statistics")
    risk = "unknown"
    if stats.get("malicious", 0):
        risk = "malicious"
    elif stats.get("suspicious", 0):
        risk = "suspicious"
    elif stats.get("undetected", 0) + stats.get("harmless", 0):
        risk = "undetected"
    timestamp = attributes.get("last_analysis_date")
    analysis_time = datetime.fromtimestamp(timestamp, UTC).isoformat().replace("+00:00", "Z") if timestamp is not None else None
    engines = attributes.get("last_analysis_results", {})
    if not isinstance(engines, dict) or any(not isinstance(engine, dict) for engine in engines.values()):
        raise ValueError("Invalid engine results")
    classification = attributes.get('popular_threat_classification')
    if classification is not None:
        if not isinstance(classification, dict):
            raise ValueError('Invalid threat classification')
        classification = {key: value for key, value in classification.items()
            if key in {'suggested_threat_label', 'popular_threat_category', 'popular_threat_name'}}
        if 'suggested_threat_label' in classification and not isinstance(classification['suggested_threat_label'], str):
            raise ValueError('Invalid threat label')
        for key in ('popular_threat_category', 'popular_threat_name'):
            values = classification.get(key, [])
            if not isinstance(values, list) or any(not isinstance(item, dict) or not isinstance(item.get('value'), str)
                or type(item.get('count')) is not int or item['count'] < 0 for item in values):
                raise ValueError('Invalid threat tokens')
    return {"sha256": sha256, "risk": risk, "stats": stats, "totalEngines": sum(stats.values()),
            "analysisTime": analysis_time, "engines": engines,
            "fileName": attributes.get("meaningful_name"), "size": attributes.get("size"),
            "fileType": attributes.get("type_description"), "threatClassification": classification}
