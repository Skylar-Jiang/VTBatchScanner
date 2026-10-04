from __future__ import annotations

from dataclasses import asdict
from typing import Literal
from uuid import uuid4

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.inputs import preview_hashes


router = APIRouter(prefix="/batch-previews", tags=["batch-previews"])


class HashPreviewRequest(BaseModel):
    input_source: Literal["manual", "paste"] = Field(alias="inputSource")
    values: list[str] = Field(min_length=1, max_length=1000)


@router.post("/hashes")
def preview_hash_input(request: HashPreviewRequest) -> dict[str, object]:
    preview = preview_hashes(request.values)
    valid_count = len(preview.valid_sha256s)
    return {
        "data": {
            "inputSource": request.input_source,
            "validSha256s": preview.valid_sha256s,
            "validCount": valid_count,
            "duplicates": [asdict(item) for item in preview.duplicates],
            "invalid": [asdict(item) for item in preview.invalid],
            "canCreate": 0 < valid_count <= 1000,
        },
        "meta": {"requestId": f"req_{uuid4().hex}"},
    }
