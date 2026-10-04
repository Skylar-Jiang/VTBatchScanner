import hashlib
from app.providers.result import ProviderFetch
from app.database import create_session_factory
from app.services.quota import PersistentDailyQuota
from run_file_uploads import make_state, run_uploads
from run_file_uploads import save_state
from app.services.detection_reports import DetectionReports

SHA=hashlib.sha256(b'fixture').hexdigest()
MANIFEST={'groupA':{'files':[{'path':'fixture.bin','sha256':SHA,'size':7},{'path':'duplicate.bin','sha256':SHA,'size':7}], 'errors':[]}}

def DailyQuota(limit):
    return PersistentDailyQuota(create_session_factory('sqlite://'),'virustotal',limit)

class Provider:
    def __init__(self,result): self.result=result; self.uploads=0
    def upload(self,data,sha): self.uploads+=1; assert data==b'fixture'; return self.result
    def analysis(self,identifier,sha): return ProviderFetch('success',{'data':{'id':identifier}},report={'sha256':sha,'risk':'malicious','stats':{'malicious':1},'totalEngines':1})

def run(state,provider,quota):
    return run_uploads(state,lambda:None,lambda row:b'fixture',provider,quota,max_uploads=100,interval=0,poll_delay=0,sleeper=lambda seconds:None)

def test_duplicate_bytes_uploaded_once_and_resume_never_uploads_again():
    state=make_state(MANIFEST)
    provider=Provider(ProviderFetch('accepted',{'data':{'id':'analysis-1'}}))
    run(state,provider,DailyQuota(10))
    run(state,provider,DailyQuota(10))
    assert len(state['samples'])==1
    assert provider.uploads==1
    assert state['samples'][0]['status']=='success'
    assert state['apiRequests']==2

def test_exhausted_budget_leaves_pending_without_reading_bytes():
    state=make_state(MANIFEST)
    def never(row): raise AssertionError('must not read')
    run_uploads(state,lambda:None,never,Provider(None),DailyQuota(0),100,0,0,lambda seconds:None)
    assert state['samples'][0]['status']=='pending'
    assert state['apiRequests']==0

def test_ambiguous_submission_is_not_retried_on_resume():
    state=make_state(MANIFEST)
    provider=Provider(ProviderFetch('submission_unknown',None,'timeout'))
    run(state,provider,DailyQuota(10)); run(state,provider,DailyQuota(10))
    assert provider.uploads==1
    assert state['samples'][0]['status']=='submission_unknown'

def test_auth_failure_halts_other_uploads():
    state=make_state(MANIFEST)
    state['samples'].append(dict(state['samples'][0],sha256='a'*64))
    provider=Provider(ProviderFetch('authentication_error',None,'forbidden'))
    run(state,provider,DailyQuota(10))
    assert provider.uploads==1
    assert state['samples'][1]['status']=='pending'

def test_future_cooldown_prevents_any_request():
    state=make_state(MANIFEST)
    state['cooldownUntil']='2999-01-01T00:00:00+00:00'
    provider=Provider(None)
    run(state,provider,DailyQuota(10))
    assert provider.uploads==0


def test_upload_save_generates_file_report_and_resume_uses_no_new_api(tmp_path):
    state=make_state(MANIFEST)
    store=DetectionReports(tmp_path/'results')
    provider=Provider(ProviderFetch('accepted',{'data':{'id':'analysis-1'}}))
    save=lambda:save_state(state,tmp_path,store)
    run_uploads(state,save,lambda row:b'fixture',provider,DailyQuota(10),100,0,0,lambda _:None)
    run_uploads(state,save,lambda row:b'fixture',provider,DailyQuota(10),100,0,0,lambda _:None)
    row=store.rows()[0]
    assert row['source']=='Uploaded File'
    assert row['query_status']=='success'
    assert row['queried_at']
    assert (store.root/'reports/files/fixture.bin.md').is_file()
    assert (store.root/'summary.xlsx').is_file()
    assert state['apiRequests']==2 and provider.uploads==1


def test_report_error_is_persisted_and_cleared_after_recovery(tmp_path):
    import json
    state=make_state(MANIFEST)
    class Locked:
        last_error=None
        def save_uploads(self,state): raise PermissionError('locked')
    save_state(state,tmp_path,Locked())
    saved=json.loads((tmp_path/'group-a-upload-results.json').read_text(encoding='utf-8'))
    assert saved['reportError']=='report_write_failed'
    save_state(state,tmp_path,DetectionReports(tmp_path/'results'))
    saved=json.loads((tmp_path/'group-a-upload-results.json').read_text(encoding='utf-8'))
    assert 'reportError' not in saved
