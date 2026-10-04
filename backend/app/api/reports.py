"""Only generated text reports and indexes are exposed, never sample files."""
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse, Response

from app.services.result_exports import bundle_bytes, csv_bytes, xlsx_bytes
from app.services.detection_reports import render_markdown


router = APIRouter(prefix='/reports', tags=['reports'])


@router.get('/index')
def export_index(request: Request, format: Literal['csv', 'xlsx', 'zip'] = 'csv'):
    store = request.app.state.detection_reports
    try:
        rows = store.rows()
        if format == 'zip':
            contents, media = bundle_bytes(store.root, rows,
                {row['report']:render_markdown(row,row['normalized_report']) for row in rows}), 'application/zip'
        elif format == 'xlsx':
            contents, media = xlsx_bytes(rows), 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        else:
            contents, media = csv_bytes(rows), 'text/csv'
    except OSError:
        raise HTTPException(503, 'report_write_failed')
    return Response(contents, media_type=media, headers={'Content-Disposition': f'attachment; filename="summary.{format}"'})


@router.get('/{kind}/{sha256}')
def get_report(request: Request, kind: Literal['files', 'hashes'], sha256: str, filename: str | None = None, download: bool = False):
    store = request.app.state.detection_reports
    row = store.find(kind, sha256.lower(), filename)
    if row is None:
        raise HTTPException(404, 'detection_report_not_found')
    path = (store.root / row['report']).resolve()
    if store.root not in path.parents or not path.is_file() or path.suffix != '.md':
        raise HTTPException(404, 'detection_report_not_found')
    if download:
        return FileResponse(path, media_type='text/markdown', filename=path.name, headers={'X-Content-Type-Options':'nosniff'})
    return PlainTextResponse(path.read_text(encoding='utf-8'), headers={'X-Content-Type-Options':'nosniff'})
