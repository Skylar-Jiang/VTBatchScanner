from datetime import UTC, datetime

import httpx
from sqlalchemy import select

from app.database import create_session_factory
from app.models import ProviderJob
from app.providers.virustotal import VirusTotalProvider
from app.services.batches import BatchService
from app.services.dispatcher import QueryDispatcher
from app.services.quota import PersistentDailyQuota
from app.services.storage import ReportStore


def setup(tmp_path, handler, limit=10):
    factory = create_session_factory(f"sqlite:///{tmp_path / 'db.sqlite'}")
    service = BatchService(factory, ())
    quota = PersistentDailyQuota(factory, 'virustotal', limit)
    provider = VirusTotalProvider('mock', httpx.Client(transport=httpx.MockTransport(handler)))
    dispatcher = QueryDispatcher(factory, provider, None, PersistentDailyQuota(factory,'cn_platform',100),
        ReportStore(tmp_path/'reports'), virustotal_quota=quota, request_interval=0, sleeper=lambda _: None)
    return factory, service, quota, dispatcher


def test_persistent_cache_reused_across_batches(tmp_path):
    seen = []
    def handler(request):
        seen.append(request)
        return httpx.Response(200,json={'data':{'id':'a'*64,'attributes':{'last_analysis_stats':{'malicious':1}}}})
    factory, service, quota, dispatcher = setup(tmp_path,handler)
    dispatcher.run_batch(service.create('A','paste',['a'*64]).id)
    dispatcher.run_batch(service.create('B','paste',['a'*64]).id)
    assert len(seen) == 1
    assert quota.remaining(datetime.now(UTC)) == 9
    assert service.sample_detail('a'*64)['risk'] == 'malicious'


def test_quota_exhaustion_keeps_pending_for_resume(tmp_path):
    factory, service, quota, dispatcher = setup(tmp_path,lambda _:httpx.Response(404),limit=1)
    batch = service.create('A','paste',['a'*64,'b'*64])
    dispatcher.run_batch(batch.id)
    with factory() as session:
        statuses = list(session.scalars(select(ProviderJob.status)))
    assert statuses == ['not_found','pending']
    dispatcher.run_batch(batch.id)
    assert quota.remaining(datetime.now(UTC)) == 0


def test_auth_failure_stops_remaining_requests(tmp_path):
    seen = []
    def handler(request):
        seen.append(request)
        return httpx.Response(401)
    factory, service, quota, dispatcher = setup(tmp_path,handler)
    dispatcher.run_batch(service.create('A','paste',['a'*64,'b'*64]).id)
    assert len(seen) == 1


def test_retry_after_is_obeyed_and_attempts_bounded(tmp_path):
    waits = []
    factory, service, quota, dispatcher = setup(tmp_path,lambda _:httpx.Response(429,headers={'Retry-After':'42'}))
    dispatcher._sleeper = waits.append
    dispatcher.run_batch(service.create('A','paste',['a'*64,'b'*64]).id)
    assert quota.remaining(datetime.now(UTC)) == 8
    assert 42 in waits
    with factory() as session:
        assert list(session.scalars(select(ProviderJob.status))) == ['rate_limited','pending']


def test_resume_recovers_interrupted_job_without_repeating_success(tmp_path):
    factory, service, quota, dispatcher = setup(tmp_path,lambda _:httpx.Response(404))
    batch = service.create('A','paste',['a'*64,'b'*64])
    with factory() as session:
        jobs = list(session.scalars(select(ProviderJob)))
        jobs[0].status='not_found'
        jobs[1].status='running'
        session.commit()
    dispatcher.run_batch(batch.id)
    with factory() as session:
        assert list(session.scalars(select(ProviderJob.status))) == ['not_found','not_found']
    assert quota.remaining(datetime.now(UTC)) == 9


def test_long_retry_after_pauses_and_persists_cooldown(tmp_path):
    waits = []
    factory, service, quota, dispatcher = setup(tmp_path,lambda _:httpx.Response(429,headers={'Retry-After':'3600'}))
    dispatcher._sleeper = waits.append
    batch = service.create('A','paste',['a'*64,'b'*64])
    dispatcher.run_batch(batch.id)
    assert quota.remaining(datetime.now(UTC)) == 9
    assert 3600 not in waits
    dispatcher.run_batch(batch.id)
    assert quota.remaining(datetime.now(UTC)) == 9
