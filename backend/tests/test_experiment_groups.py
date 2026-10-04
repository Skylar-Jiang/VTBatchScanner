import json
from pathlib import Path
from fastapi.testclient import TestClient
from app.main import create_app

def test_default_experiment_directory_is_inside_project(tmp_path):
    app=create_app(database_url=f'sqlite:///{tmp_path}/default.db',virustotal_api_key='',cn_platform_api_key='')
    assert app.state.experiment_root == Path(__file__).resolve().parents[2]/'results'/'experiment-3'

def test_group_api_separates_file_upload_from_hash_query(tmp_path):
    root=tmp_path/'experiment'; root.mkdir()
    (root/'input-inventory.json').write_text(json.dumps({'groupA':{'files':[{'path':'sample.exe','sha256':'a'*64,'size':1}],'errors':[{'path':'locked.exe','error':'Bad password'}]}}))
    app=create_app(database_url=f'sqlite:///{tmp_path}/test.db',virustotal_api_key='',cn_platform_api_key='',experiment_root=root)
    service=app.state.batch_service
    batch=service.create('B','txt',['b'*64])
    (root/'batch-ids.json').write_text(json.dumps({'B':batch.id}))
    response=TestClient(app).get('/api/v1/experiment/groups')
    assert response.status_code==200
    data=response.json()['data']
    assert data['A']['method']=='file_upload'
    assert data['A']['files'][0]['status']=='pending'
    assert data['A']['files'][0]['report'] is None
    assert data['B']['method']=='hash_query'
    assert data['B']['samples'][0]['sha256']=='b'*64
    assert len(data['A']['readErrors'])==1

def test_group_api_keeps_existing_report_separate_from_upload(tmp_path):
    root=tmp_path/'experiment'; root.mkdir()
    sha='a'*64
    (root/'input-inventory.json').write_text(json.dumps({'groupA':{'files':[{'path':'sample.exe','sha256':sha,'size':1}],'errors':[]}}))
    (root/'group-a-results.json').write_text(json.dumps({'samples':[{'sha256':sha,'queryStatus':'success','report':{'risk':'malicious'}}]}))
    app=create_app(database_url=f'sqlite:///{tmp_path}/test.db',virustotal_api_key='',cn_platform_api_key='',experiment_root=root)
    file=TestClient(app).get('/api/v1/experiment/groups').json()['data']['A']['files'][0]
    assert file['queryStatus']=='success'
    assert file['queryReport']=={'risk':'malicious'}
    assert file['report'] is None


def test_upload_report_generation_error_is_visible_in_groups(tmp_path):
    root=tmp_path/'experiment'; root.mkdir()
    (root/'input-inventory.json').write_text(json.dumps({'groupA':{'files':[],'errors':[]}}))
    (root/'group-a-upload-results.json').write_text(json.dumps({'samples':[],'apiRequests':0,'reportError':'report_write_failed'}))
    app=create_app(database_url=f'sqlite:///{tmp_path}/errors.db',virustotal_api_key='',cn_platform_api_key='',experiment_root=root)
    assert TestClient(app).get('/api/v1/experiment/groups').json()['data']['A']['reportError']=='report_write_failed'
