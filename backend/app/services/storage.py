import json
from pathlib import Path
from typing import Any

from app.services.inputs import SHA256_PATTERN


class ReportStore:
    def __init__(self, root: Path) -> None:
        self._root = root.resolve()

    def save(self, sha256: str, provider: str, report_kind: str, raw: dict[str, Any]) -> str:
        if not SHA256_PATTERN.fullmatch(sha256):
            raise ValueError("Invalid SHA256 path")
        if provider == "virustotal" and report_kind == "report":
            relative = Path("virustotal") / f"{sha256}.json"
        elif provider == "cn_platform" and report_kind in {"reputation", "multiscan", "static", "dynamics"}:
            relative = Path("cn_platform") / sha256 / f"{report_kind}.json"
        else:
            raise ValueError("Unsupported report path")
        destination = (self._root / relative).resolve()
        if self._root not in destination.parents:
            raise ValueError("Invalid report path")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
        return relative.as_posix()
