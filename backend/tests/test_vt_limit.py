from test_vt_dispatcher import setup
import httpx
from datetime import UTC, datetime

def test_small_verification_job_limit_preserves_remaining(tmp_path):
    factory, service, quota, dispatcher = setup(tmp_path,lambda _:httpx.Response(404))
    batch = service.create('A','paste',['a'*64,'b'*64,'c'*64])
    dispatcher.run_batch(batch.id,max_jobs=1)
    assert quota.remaining(datetime.now(UTC)) == 9
    assert service.export_batch(batch.id)['summary']['pending'] == 2
