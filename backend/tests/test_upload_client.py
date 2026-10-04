import hashlib
import httpx
import pytest
from app.providers.upload import FileUploadClient

HASH = hashlib.sha256(b'ordinary test bytes').hexdigest()

def test_upload_sends_bytes_and_returns_analysis_id():
    def handle(request):
        assert request.method == 'POST'
        assert request.url.path == '/api/v3/files'
        assert b'ordinary test bytes' in request.read()
        return httpx.Response(200,json={'data':{'type':'analysis','id':'analysis-1'}})
    result = FileUploadClient('mock',httpx.Client(transport=httpx.MockTransport(handle))).upload(b'ordinary test bytes',HASH)
    assert result.status == 'accepted'
    assert result.raw['data']['id'] == 'analysis-1'

def test_mismatched_hash_never_uploads():
    client = FileUploadClient('mock',httpx.Client(transport=httpx.MockTransport(lambda request:pytest.fail('must not call'))))
    assert client.upload(b'wrong bytes',HASH).status == 'invalid_file'

@pytest.mark.parametrize('code,status',[(401,'authentication_error'),(403,'authentication_error'),(429,'rate_limited'),(500,'failed')])
def test_http_errors(code,status):
    client=FileUploadClient('mock',httpx.Client(transport=httpx.MockTransport(lambda request:httpx.Response(code,headers={'Retry-After':'60'}))))
    result=client.upload(b'ordinary test bytes',HASH)
    assert result.status == status
    if code == 429: assert result.retry_after == 60

def test_queued_analysis_is_not_success_or_safe():
    raw={'data':{'id':'analysis-1','type':'analysis','attributes':{'status':'queued','stats':{},'results':{}}}}
    client=FileUploadClient('mock',httpx.Client(transport=httpx.MockTransport(lambda request:httpx.Response(200,json=raw))))
    result=client.analysis('analysis-1',HASH)
    assert result.status == 'queued'
    assert result.report is None

def test_completed_analysis_uses_this_analysis_not_cached_file_report():
    raw={'meta':{'file_info':{'sha256':HASH}},'data':{'id':'analysis-1','type':'analysis','attributes':{'status':'completed','date':1700000000,'stats':{'malicious':3,'undetected':1},'results':{'Engine':{'category':'malicious','result':'test'}}}}}
    client=FileUploadClient('mock',httpx.Client(transport=httpx.MockTransport(lambda request:httpx.Response(200,json=raw))))
    result=client.analysis('analysis-1',HASH)
    assert result.status == 'success'
    assert result.report['stats']['malicious'] == 3
    assert result.report['analysisTime'].endswith('Z')

def test_analysis_resource_can_return_canonical_id_different_from_upload_token():
    raw={'meta':{'file_info':{'sha256':HASH}},'data':{'id':'f-'+HASH+'-1700000000','type':'analysis','attributes':{'status':'completed','date':1700000000,'stats':{'malicious':1},'results':{}}}}
    result=FileUploadClient('mock',httpx.Client(transport=httpx.MockTransport(lambda request:httpx.Response(200,json=raw)))).analysis('opaque-upload-token',HASH)
    assert result.status=='success'

@pytest.mark.parametrize('exception',[httpx.ReadTimeout('timeout'),httpx.ConnectError('network')])
def test_upload_network_error_is_ambiguous_not_automatically_retried(exception):
    def handle(request): raise exception
    result=FileUploadClient('mock',httpx.Client(transport=httpx.MockTransport(handle))).upload(b'ordinary test bytes',HASH)
    assert result.status == 'submission_unknown'
