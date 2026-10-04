from datetime import datetime
from app.api.batches import _batch_payload
from app.services.batches import BatchSummary

def test_sqlite_naive_utc_created_time_not_reinterpreted_as_local():
    batch = BatchSummary('id','name','txt',1,1,datetime(2026,1,1,12))
    assert _batch_payload(batch)['createdAt'] == '2026-01-01T12:00:00Z'
