"""Read-only experimental groups. Viewing these endpoints never requests VirusTotal."""
import json
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
from typing import Literal

router=APIRouter(prefix='/experiment',tags=['experiment'])

@router.get('/groups')
def groups(request:Request):
    root=request.app.state.experiment_root
    if not (root/'input-inventory.json').exists(): raise HTTPException(404,'experiment_inputs_missing')
    inventory=json.loads((root/'input-inventory.json').read_text(encoding='utf-8'))
    uploaded=json.loads((root/'group-a-upload-results.json').read_text(encoding='utf-8')) if (root/'group-a-upload-results.json').exists() else {'samples':[],'apiRequests':0}
    by_hash={row['sha256']:row for row in uploaded['samples']}
    queried=json.loads((root/'group-a-results.json').read_text(encoding='utf-8')) if (root/'group-a-results.json').exists() else {'samples':[]}
    reports={row['sha256']:row for row in queried['samples']}
    files=[]
    for file in inventory['groupA']['files']:
        row=by_hash.get(file['sha256'],{})
        query=reports.get(file['sha256'],{})
        files.append({**file,'status':row.get('status','pending'),'analysisId':row.get('analysisId'),'error':row.get('error'),'report':row.get('report'),'queryStatus':query.get('queryStatus','pending'),'queryReport':query.get('report')})
    ids=json.loads((root/'batch-ids.json').read_text(encoding='utf-8')) if (root/'batch-ids.json').exists() else {}
    batch=request.app.state.batch_service.detail(ids.get('B',''))
    return {'data':{'A':{'method':'file_upload','files':files,'readErrors':inventory['groupA']['errors'],'apiRequests':uploaded['apiRequests'],'pauseReason':uploaded.get('pauseReason'),'updatedAt':uploaded.get('updatedAt'),'reportError':uploaded.get('reportError')},'B':{'method':'hash_query','batchId':ids.get('B'),'samples':batch[1] if batch else []}}}

@router.get('/a-upload/export')
def export_upload(request:Request,format:Literal['csv','json']='csv'):
    path=request.app.state.experiment_root/f'group-a-upload-results.{format}'
    if not path.is_file(): raise HTTPException(404,'upload_results_missing')
    return FileResponse(path,media_type='application/json' if format=='json' else 'text/csv',filename=path.name)
