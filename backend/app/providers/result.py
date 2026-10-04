from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ProviderFetch:
    status: str
    raw: dict[str, Any] | None
    error: str | None = None
    report: dict[str, Any] | None = None
    retry_after: float | None = None
