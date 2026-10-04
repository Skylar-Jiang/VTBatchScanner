from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
import csv
import io
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from fastapi.responses import Response

from app.services.batches import BatchService, BatchSummary
from app.services.inputs import preview_hashes
from app.services.quota import PersistentDailyQuota
from app.services.result_exports import bundle_bytes, xlsx_bytes
from app.services.detection_reports import render_markdown


router = APIRouter(prefix="/batches", tags=["batches"])


class CreateBatchRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    input_source: Literal["manual", "paste", "txt", "csv"] = Field(alias="inputSource")
    sha256s: list[str] = Field(min_length=1, max_length=1000)

    @field_validator("sha256s")
    @classmethod
    def validate_sha256s(cls, values: list[str]) -> list[str]:
        preview = preview_hashes(values)
        if preview.invalid or preview.duplicates or len(preview.valid_sha256s) != len(values):
            raise ValueError("sha256s must contain unique valid SHA256 values")
        return preview.valid_sha256s


class RefreshRequest(BaseModel):
    providers: list[Literal["virustotal", "cn_platform"]] = ["virustotal"]
    acknowledge_quota_cost: bool = Field(default=False, alias="acknowledgeQuotaCost")


def _service(request: Request) -> BatchService:
    return request.app.state.batch_service


def _batch_payload(batch: BatchSummary, service: BatchService | None = None) -> dict[str, object]:
    progress = service.progress(batch.id) if service else {"totalProviderJobs":batch.total_provider_jobs,"terminalProviderJobs":0,"succeeded":0,"notFound":0,"failed":0,"percent":0}
    return {
        "id": batch.id,
        "name": batch.name,
        "inputSource": batch.input_source,
        "status": "completed" if progress["percent"] == 100 else "queued" if progress["terminalProviderJobs"] == 0 else "running",
        "sampleCount": batch.sample_count,
        "progress": progress,
        "createdAt": batch.created_at.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z"),
        "startedAt": None,
        "completedAt": None,
    }


@router.post("", status_code=status.HTTP_201_CREATED)
def create_batch(request: Request, background_tasks: BackgroundTasks, body: CreateBatchRequest) -> dict[str, object]:
    batch = _service(request).create(body.name, body.input_source, body.sha256s)
    background_tasks.add_task(request.app.state.dispatcher.run_batch, batch.id)
    return {"data": _batch_payload(batch), "meta": {"requestId": f"req_{uuid4().hex}"}}


@router.get("/{batch_id}")
def get_batch(request: Request, batch_id: str) -> dict[str, object]:
    result = _service(request).detail(batch_id)
    if result is None:
        raise HTTPException(status_code=404, detail="batch_not_found")
    batch, samples = result
    return {
        "data": {"batch": _batch_payload(batch, _service(request)), "samples": samples},
        "meta": {"requestId": f"req_{uuid4().hex}"},
    }


@router.post("/{batch_id}/refresh", status_code=status.HTTP_202_ACCEPTED)
def refresh_batch(request: Request, background_tasks: BackgroundTasks, batch_id: str, body: RefreshRequest) -> dict[str, object]:
    service = _service(request)
    if service.detail(batch_id) is None:
        raise HTTPException(status_code=404, detail="batch_not_found")
    selected = list(dict.fromkeys(body.providers))
    cverc_cost = service.provider_job_count(batch_id, "cn_platform") if "cn_platform" in selected else 0
    vt_cost = service.provider_job_count(batch_id, "virustotal") if "virustotal" in selected else 0
    if (cverc_cost or vt_cost) and not body.acknowledge_quota_cost:
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
    background_tasks.add_task(request.app.state.dispatcher.refresh_batch, batch_id, selected)
    return {
        "data": {
            "batchId": batch_id,
            "operation": "refresh",
            "scheduledProviders": selected,
            "reanalysisTriggered": False,
            "quota": quota_payload,
            "estimatedVirusTotalRequestCost": vt_cost,
        },
        "meta": {"requestId": f"req_{uuid4().hex}"},
    }


@router.get("")
def list_batches(request: Request) -> dict:
    service = _service(request)
    return {"data": [_batch_payload(batch, service) for batch in service.list_batches()]}


@router.post("/{batch_id}/resume", status_code=202)
def resume_batch(request: Request, background_tasks: BackgroundTasks, batch_id: str) -> dict:
    if _service(request).detail(batch_id) is None:
        raise HTTPException(404, "batch_not_found")
    background_tasks.add_task(request.app.state.dispatcher.run_batch, batch_id)
    return {"data": {"batchId": batch_id, "reanalysisTriggered": False}}


@router.get("/{batch_id}/export")
def export_batch(request: Request, batch_id: str, format: Literal["json", "csv", "xlsx", "zip"] = "json"):
    result = _service(request).export_batch(batch_id)
    if result is None:
        raise HTTPException(404, "batch_not_found")
    if format == "json":
        return result
    if format in {'xlsx', 'zip'}:
        store = request.app.state.detection_reports
        try:
            rows = store.batch_rows(result)
            contents = xlsx_bytes(rows) if format == 'xlsx' else bundle_bytes(store.root, rows,
                {row['report']:render_markdown(row,row['normalized_report']) for row in rows})
        except OSError:
            raise HTTPException(503, 'report_write_failed')
        media = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' if format == 'xlsx' else 'application/zip'
        return Response(contents, media_type=media, headers={'Content-Disposition': f'attachment; filename="{batch_id}.{format}"'})
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["sha256", "status", "risk", "malicious", "suspicious", "undetected", "totalEngines", "analysisTime", "queriedAt", "attempts", "fromCache", "error"])
    for row in result["samples"]:
        report = row["report"] or {}
        stats = report.get("stats", {})
        writer.writerow([row["sha256"], row["queryStatus"], row["risk"], stats.get("malicious"), stats.get("suspicious"), stats.get("undetected"), report.get("totalEngines"), report.get("analysisTime"), row["queriedAt"], row["attempts"], row["fromCache"], row["error"]])
    return Response('\ufeff' + output.getvalue(), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{batch_id}.csv"'})
