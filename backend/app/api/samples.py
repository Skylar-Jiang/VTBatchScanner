from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request, BackgroundTasks
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from app.services.batches import BatchService
from app.services.inputs import SHA256_PATTERN
from app.services.quota import PersistentDailyQuota


router = APIRouter(prefix="/samples", tags=["samples"])


def _service(request: Request) -> BatchService:
    return request.app.state.batch_service


class RefreshRequest(BaseModel):
    providers: list[Literal["virustotal", "cn_platform"]] = ["virustotal"]
    acknowledge_quota_cost: bool = Field(default=False, alias="acknowledgeQuotaCost")


@router.get("")
def list_samples(request: Request) -> dict[str, object]:
    samples = _service(request).list_samples()
    return {
        "data": samples,
        "meta": {"page": 1, "pageSize": 20, "total": len(samples), "totalPages": 1, "requestId": f"req_{uuid4().hex}"},
    }


@router.get("/{sha256}")
def get_sample(request: Request, sha256: str) -> dict[str, object]:
    normalized = sha256.lower()
    if not SHA256_PATTERN.fullmatch(normalized):
        raise HTTPException(status_code=404, detail="sample_not_found")
    sample = _service(request).sample_detail(normalized)
    if sample is None:
        raise HTTPException(status_code=404, detail="sample_not_found")
    sample['detectionReports'] = [{'filename': row['filename'], 'source': row['source'],
        'url': f'/api/v1/reports/{"files" if row["filename"] else "hashes"}/{normalized}'
            + ('?filename='+quote(row['filename'], safe='') if row['filename'] else '')}
        for row in request.app.state.detection_reports.rows() if row['sha256'] == normalized]
    sample['reportError'] = request.app.state.detection_reports.last_error
    return {"data": sample, "meta": {"requestId": f"req_{uuid4().hex}"}}


@router.post("/{sha256}/refresh", status_code=202)
def refresh_sample(request: Request, background_tasks: BackgroundTasks, sha256: str, body: RefreshRequest) -> dict[str, object]:
    normalized = sha256.lower()
    if not SHA256_PATTERN.fullmatch(normalized) or not _service(request).has_sample(normalized):
        raise HTTPException(status_code=404, detail="sample_not_found")
    selected = list(dict.fromkeys(body.providers))
    cverc_cost = len(request.app.state.cverc_enabled_reports) if "cn_platform" in selected else 0
    if (cverc_cost or "virustotal" in selected) and not body.acknowledge_quota_cost:
        raise HTTPException(status_code=400, detail="confirmation_required")
    quota_payload: dict[str, int | str] | None = None
    if cverc_cost:
        quota: PersistentDailyQuota = request.app.state.cverc_quota
        remaining_before = quota.remaining(datetime.now(UTC))
        daily_limit = request.app.state.cverc_daily_quota
        quota_payload = {
            "provider": "cn_platform",
            "dailyLimit": daily_limit,
            "used": daily_limit - remaining_before,
            "remainingBefore": remaining_before,
            "estimatedRequestCost": cverc_cost,
            "remainingAfterSchedule": max(0, remaining_before - cverc_cost),
            "deferredRequestCount": max(0, cverc_cost - remaining_before),
        }
    batch = _service(request).create("刷新已有报告", "manual", [normalized])
    background_tasks.add_task(request.app.state.dispatcher.refresh_batch, batch.id, selected)
    return {
        "data": {
            "sha256": normalized,
            "operation": "refresh",
            "scheduledProviders": selected,
            "reanalysisTriggered": False,
            "quota": quota_payload,
        },
        "meta": {"requestId": f"req_{uuid4().hex}"},
    }


@router.get("/{sha256}/providers/{provider}/raw/{report_kind}")
def download_raw_report(request: Request, sha256: str, provider: str, report_kind: str) -> FileResponse:
    relative_path = _service(request).raw_report_path(sha256.lower(), provider, report_kind)
    if relative_path is None:
        raise HTTPException(status_code=404, detail="raw_report_not_found")
    path = (request.app.state.report_root / relative_path).resolve()
    if request.app.state.report_root not in path.parents or not path.is_file():
        raise HTTPException(status_code=404, detail="raw_report_not_found")
    return FileResponse(path, media_type="application/json", filename=f"{sha256.lower()}-{provider}-{report_kind}.json")
