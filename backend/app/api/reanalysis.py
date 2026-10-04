from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.services.batches import BatchService


router = APIRouter(prefix="/samples", tags=["reanalysis"])


class ReanalysisPrepareRequest(BaseModel):
    providers: list[str]


@router.post("/{sha256}/reanalysis/prepare")
def prepare_reanalysis(request: Request, sha256: str, body: ReanalysisPrepareRequest) -> dict[str, object]:
    service: BatchService = request.app.state.batch_service
    if not service.has_sample(sha256.lower()):
        raise HTTPException(status_code=404, detail="sample_not_found")
    raise HTTPException(status_code=409, detail="reanalysis_not_supported")
