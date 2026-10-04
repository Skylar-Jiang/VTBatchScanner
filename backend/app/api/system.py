from datetime import UTC, datetime, timedelta
from uuid import uuid4

from fastapi import APIRouter, Request

from app.services.batches import BatchService
from app.services.quota import PersistentDailyQuota


router = APIRouter(tags=["system"])


@router.get("/dashboard")
def dashboard(request: Request) -> dict[str, object]:
    service: BatchService = request.app.state.batch_service
    data = service.dashboard()
    remaining = request.app.state.virustotal_quota.remaining(datetime.now(UTC))
    limit = int(request.app.state.virustotal_daily_budget)
    data["requestBudget"] = {"dailyLimit": limit, "used": limit - remaining, "remaining": remaining, "accountVerified": False}
    return {"data": data, "meta": {"requestId": f"req_{uuid4().hex}"}}


@router.get("/providers/status")
def provider_status(request: Request) -> dict[str, object]:
    quota: PersistentDailyQuota = request.app.state.cverc_quota
    now = datetime.now(UTC)
    remaining = quota.remaining(now)
    used = request.app.state.cverc_daily_quota - remaining
    reset = datetime.combine((now + timedelta(days=1)).date(), datetime.min.time(), tzinfo=UTC)
    return {
        "data": [
            {"provider": "virustotal", "status": "unknown", "enabledReports": ["report"]},
            {
                "provider": "cn_platform",
                "status": "unknown",
                "enabledReports": list(request.app.state.cverc_enabled_reports),
                "quota": {"dailyLimit": request.app.state.cverc_daily_quota, "used": used, "remaining": remaining, "resetsAt": reset.isoformat().replace("+00:00", "Z")},
            },
        ],
        "meta": {"requestId": f"req_{uuid4().hex}"},
    }
