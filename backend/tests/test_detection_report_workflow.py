import inspect
import io
import zipfile
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from app.main import create_app
from app.providers.virustotal import VirusTotalProvider


def app_with_reports(tmp_path, handler):
    assert 'detection_root' in inspect.signature(create_app).parameters, 'Reports are not integrated into the application'
    app = create_app(database_url=f"sqlite:///{tmp_path/'analysis.db'}", virustotal_api_key='',
        cn_platform_api_key='', detection_root=tmp_path/'results', experiment_root=tmp_path/'experiment')
    app.state.dispatcher._virustotal = VirusTotalProvider('mock', httpx.Client(transport=httpx.MockTransport(handler)))
    app.state.dispatcher._request_interval = 0
    app.state.dispatcher._sleeper = lambda _: None
    return app, TestClient(app)


def test_batch_automatically_generates_reports_and_exports_portable_bundle(tmp_path):
    requests = []
    def handler(request):
        sha = request.url.path.split('/')[-1]
        requests.append(sha)
        if sha.startswith('b'):
            return httpx.Response(500)
        if sha.startswith('c'):
            return httpx.Response(404)
        return httpx.Response(200, json={'data': {'id': sha, 'attributes': {'last_analysis_stats': {'malicious': 0, 'undetected': 70}}}})
    app, client = app_with_reports(tmp_path, handler)
    batch_id = client.post('/api/v1/batches', json={'name':'Mixed','inputSource':'paste','sha256s':['a'*64,'b'*64,'c'*64]}).json()['data']['id']
    assert len(requests) == 4
    assert (tmp_path/'results/summary.xlsx').is_file()
    for sha in ['a'*64, 'b'*64, 'c'*64]:
        assert (tmp_path/'results/reports/hashes'/f'{sha}.md').is_file()
    summary = client.get(f'/api/v1/batches/{batch_id}/export').json()['summary']
    assert (summary['successful'], summary['failed'], summary['notFound']) == (1, 1, 1)
    response = client.get('/api/v1/reports/hashes/' + 'a'*64)
    assert response.status_code == 200
    assert '未检出' in response.text
    assert response.headers['x-content-type-options'] == 'nosniff'
    assert client.get('/api/v1/reports/hashes/invalid').status_code == 404
    assert client.get('/api/v1/reports/files/'+'a'*64).status_code == 404
    archive = client.get(f'/api/v1/batches/{batch_id}/export?format=zip')
    assert archive.status_code == 200
    with zipfile.ZipFile(io.BytesIO(archive.content)) as bundle:
        assert 'summary.xlsx' in bundle.namelist()
        assert 'reports/hashes/'+'a'*64+'.md' in bundle.namelist()
    assert client.get(f'/api/v1/batches/{batch_id}/export?format=xlsx').status_code == 200
    assert len(requests) == 4


def test_cache_hit_still_generates_report_without_another_remote_request(tmp_path):
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={'data': {'id': 'a'*64, 'attributes': {'last_analysis_stats': {'malicious': 1}}}})
    app, client = app_with_reports(tmp_path, handler)
    for name in ['First', 'Cached']:
        client.post('/api/v1/batches', json={'name':name,'inputSource':'paste','sha256s':['a'*64]})
    assert len(requests) == 1
    detail = client.get('/api/v1/samples/'+'a'*64).json()['data']
    assert detail['detectionReports'][0]['url'] == '/api/v1/reports/hashes/'+'a'*64
    assert len(app.state.detection_reports.rows()) == 1


def test_report_export_failure_does_not_abort_saved_batch_results(tmp_path, monkeypatch):
    app, client = app_with_reports(tmp_path, lambda request: httpx.Response(404))
    def locked():
        raise PermissionError('Workbook is open')
    monkeypatch.setattr(app.state.detection_reports, 'export_indexes', locked)
    batch_id = client.post('/api/v1/batches', json={'name':'Locked','inputSource':'paste','sha256s':['a'*64,'b'*64]}).json()['data']['id']
    assert client.get(f'/api/v1/batches/{batch_id}').json()['data']['batch']['progress']['percent'] == 100
    assert app.state.detection_reports.last_error == 'report_write_failed'


def test_report_write_failure_remains_visible_after_index_export(tmp_path, monkeypatch):
    app, client = app_with_reports(tmp_path, lambda request: httpx.Response(404))
    def locked(*args, **kwargs):
        raise PermissionError('Report is locked')
    monkeypatch.setattr(app.state.detection_reports, 'save_query', locked)
    client.post('/api/v1/batches', json={'name':'Locked report','inputSource':'paste','sha256s':['a'*64]})
    assert app.state.detection_reports.last_error == 'report_write_failed'


def test_latest_success_replaces_old_failure_in_sample_status(tmp_path):
    response = [httpx.Response(500)]
    app, client = app_with_reports(tmp_path, lambda request: response[0])
    client.post('/api/v1/batches', json={'name':'Failed','inputSource':'paste','sha256s':['a'*64]})
    response[0] = httpx.Response(200, json={'data':{'id':'a'*64,'attributes':{'last_analysis_stats':{'malicious':1}}}})
    client.post('/api/v1/batches', json={'name':'Succeeded','inputSource':'paste','sha256s':['a'*64]})
    detail = client.get('/api/v1/samples/'+'a'*64).json()['data']
    assert detail['status'] == 'completed'
    assert detail['risk'] == 'malicious'


def test_file_alias_links_include_encoded_original_filename(tmp_path):
    app, client = app_with_reports(tmp_path, lambda request: httpx.Response(404))
    client.post('/api/v1/batches', json={'name':'Aliases','inputSource':'paste','sha256s':['a'*64]})
    app.state.detection_reports.save('a'*64, 'not_found', filename='one.exe')
    app.state.detection_reports.save('a'*64, 'not_found', filename='two name.exe')
    reports = client.get('/api/v1/samples/'+'a'*64).json()['data']['detectionReports']
    for row in reports:
        assert client.get(row['url']).status_code == 200
        if row['filename']:
            assert 'filename=' in row['url']
            assert 'Original Filename: '+row['filename'] in client.get(row['url']).text


def test_batch_exports_are_read_only_for_canonical_reports(tmp_path, monkeypatch):
    app, client=app_with_reports(tmp_path,lambda request:httpx.Response(404))
    batch_id=client.post('/api/v1/batches',json={'name':'Read only','inputSource':'paste','sha256s':['a'*64]}).json()['data']['id']
    before={path:path.read_bytes() for path in (tmp_path/'results').rglob('*') if path.is_file()}
    def never(*args, **kwargs):
        raise AssertionError('Exports must not write shared canonical files')
    monkeypatch.setattr(app.state.detection_reports,'save_batch',never)
    for format in ['xlsx','zip']:
        assert client.get(f'/api/v1/batches/{batch_id}/export?format={format}').status_code==200
    assert all(path.read_bytes()==contents for path,contents in before.items())


def test_global_bundle_uses_one_saved_row_snapshot(tmp_path):
    app,client=app_with_reports(tmp_path,lambda request:httpx.Response(404))
    client.post('/api/v1/batches',json={'name':'Snapshot','inputSource':'paste','sha256s':['a'*64]})
    row=app.state.detection_reports.rows()[0]
    (tmp_path/'results'/row['report']).write_text('Changed after index snapshot',encoding='utf-8')
    response=client.get('/api/v1/reports/index?format=zip')
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        text=archive.read(row['report']).decode('utf-8')
        assert 'not_found' in text and 'Changed after index snapshot' not in text
