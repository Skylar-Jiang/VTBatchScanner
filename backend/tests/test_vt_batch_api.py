from fastapi.testclient import TestClient
from app.main import create_app


def test_batch_list_export_and_resume_without_real_key(tmp_path):
    app = create_app(database_url=f"sqlite:///{tmp_path/'db.sqlite'}",virustotal_api_key='',cn_platform_api_key='',cverc_enabled_reports=())
    client = TestClient(app)
    body = {'name':'All A','inputSource':'paste','sha256s':[f'{i:064x}' for i in range(115)]}
    response = client.post('/api/v1/batches',json=body)
    assert response.status_code == 201
    batch_id = response.json()['data']['id']
    assert len(client.get('/api/v1/batches').json()['data']) == 1
    result = client.get(f'/api/v1/batches/{batch_id}/export?format=json').json()
    assert len(result['samples']) == 115
    assert result['summary']['pending'] == 115
    csv = client.get(f'/api/v1/batches/{batch_id}/export?format=csv')
    assert 'sha256,status,risk' in csv.text
    assert client.post(f'/api/v1/batches/{batch_id}/resume').status_code == 202
    assert client.post(f'/api/v1/batches/{batch_id}/refresh',json={'providers':['virustotal']}).status_code == 400
    assert client.post(f'/api/v1/batches/{batch_id}/refresh',json={'providers':['virustotal'],'acknowledgeQuotaCost':True}).status_code == 202


def test_vt_success_batch_progress_and_export(tmp_path):
    import httpx
    from app.providers.virustotal import VirusTotalProvider
    app = create_app(database_url=f"sqlite:///{tmp_path/'db.sqlite'}",virustotal_api_key='',cn_platform_api_key='',cverc_enabled_reports=())
    app.state.dispatcher._virustotal = VirusTotalProvider('mock',httpx.Client(transport=httpx.MockTransport(
        lambda _:httpx.Response(200,json={'data':{'id':'a'*64,'attributes':{'last_analysis_stats':{'undetected':2}}}}))))
    client = TestClient(app)
    batch_id = client.post('/api/v1/batches',json={'name':'A','inputSource':'paste','sha256s':['a'*64]}).json()['data']['id']
    data = client.get(f'/api/v1/batches/{batch_id}').json()['data']
    assert data['batch']['progress']['percent'] == 100
    assert data['samples'][0]['risk'] == 'undetected'
    assert client.get('/api/v1/dashboard').json()['data']['riskDistribution']['undetected'] == 1


def test_vt_only_default_ignores_legacy_cn_environment(tmp_path, monkeypatch):
    monkeypatch.setenv('CN_PLATFORM_ENABLED_REPORTS','static,dynamics')
    app = create_app(database_url=f"sqlite:///{tmp_path/'db.sqlite'}",virustotal_api_key='',cn_platform_api_key='')
    batch = app.state.batch_service.create('VT only','paste',['a'*64])
    assert batch.total_provider_jobs == 1


def test_preview_all_a_hashes_is_creatable(tmp_path):
    client = TestClient(create_app(database_url=f"sqlite:///{tmp_path/'db.sqlite'}",virustotal_api_key='',cn_platform_api_key='',cverc_enabled_reports=()))
    preview = client.post('/api/v1/batch-previews/hashes',json={'inputSource':'paste','values':[f'{i:064x}' for i in range(115)]})
    assert preview.json()['data']['canCreate'] is True
