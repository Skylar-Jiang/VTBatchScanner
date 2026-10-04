from __future__ import annotations

from datetime import UTC, datetime, timedelta
from threading import Lock
from time import sleep

from sqlalchemy import select

from app.database import SessionFactory
from app.models import ProviderJob, RawReport, VirusTotalCache, QueryRecord, ProviderCooldown
from app.providers.cn_platform import CnPlatformProvider
from app.providers.virustotal import VirusTotalProvider
from app.services.quota import PersistentDailyQuota
from app.services.storage import ReportStore
from app.services.detection_reports import DetectionReports


class QueryDispatcher:
    """Runs locally queued report reads; it never creates third-party analyses."""

    def __init__(
        self,
        session_factory: SessionFactory,
        virustotal: VirusTotalProvider | None,
        cn_platform: CnPlatformProvider | None,
        cn_platform_quota: PersistentDailyQuota,
        report_store: ReportStore | None = None,
        virustotal_quota: PersistentDailyQuota | None = None,
        request_interval: float = 16.0,
        sleeper=sleep,
        detection_reports: DetectionReports | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._virustotal = virustotal
        self._cn_platform = cn_platform
        self._cn_platform_quota = cn_platform_quota
        self._report_store = report_store
        self._virustotal_quota = virustotal_quota or PersistentDailyQuota(session_factory, "virustotal", 500)
        self._request_interval = request_interval
        self._sleeper = sleeper
        self._lock = Lock()
        self._halted = False
        self._detection_reports = detection_reports

    def run_batch(self, batch_id: str, max_jobs: int | None = None) -> None:
        with self._lock:
            self._run_batch(batch_id, max_jobs)

    def refresh_batch(self, batch_id: str, providers: list[str]) -> None:
        with self._lock:
            with self._session_factory() as session:
                jobs = list(session.scalars(select(ProviderJob).where(ProviderJob.batch_id == batch_id, ProviderJob.provider.in_(providers))))
                for job in jobs:
                    job.status = "pending"
                    record = session.get(QueryRecord, job.id)
                    if record is not None:
                        session.delete(record)
                    if job.provider == "virustotal":
                        cache = session.get(VirusTotalCache, job.sha256)
                        if cache is not None:
                            session.delete(cache)
                session.commit()
            self._run_batch(batch_id)

    def _run_batch(self, batch_id: str, max_jobs: int | None = None) -> None:
        self._halted = False
        report_failed = False
        with self._session_factory() as session:
            for job in session.scalars(select(ProviderJob).where(ProviderJob.batch_id == batch_id, ProviderJob.status == "running")):
                job.status = "pending"
            session.commit()
            job_ids = list(
                session.scalars(
                    select(ProviderJob.id).where(
                        ProviderJob.batch_id == batch_id,
                        ProviderJob.status == "pending",
                    )
                )
            )
        for job_id in job_ids[:max_jobs] if max_jobs is not None else job_ids:
            if self._halted:
                break
            self._run_job(job_id)
            if self._detection_reports is not None:
                try:
                    with self._session_factory() as session:
                        job = session.get(ProviderJob, job_id)
                        record = session.get(QueryRecord, job_id)
                        if job.provider == 'virustotal':
                            self._detection_reports.save_query(job.sha256, job.status, record.report if record else None,
                                job.batch_id, record.queried_at.replace(tzinfo=UTC).isoformat() if record and record.queried_at else None,
                                record.error if record else None)
                except OSError:
                    report_failed = True
                    self._detection_reports.last_error = 'report_write_failed'
        if self._detection_reports is not None:
            try:
                self._detection_reports.export_indexes()
                if not report_failed:
                    self._detection_reports.last_error = None
            except OSError:
                self._detection_reports.last_error = 'report_write_failed'

    def _run_job(self, job_id: int) -> None:
        with self._session_factory() as session:
            job = session.get(ProviderJob, job_id)
            if job is None or job.status != "pending":
                return
            if job.provider == "virustotal":
                if self._virustotal is None:
                    return
                record = session.get(QueryRecord, job.id)
                if record is None:
                    record = QueryRecord(job_id=job.id, attempts=0, from_cache=0)
                    session.add(record)
                cache = session.get(VirusTotalCache, job.sha256)
                if cache is not None and (datetime.now(UTC) - cache.queried_at.replace(tzinfo=UTC)).total_seconds() < 7 * 86400:
                    record.report = cache.report
                    record.queried_at = cache.queried_at
                    record.from_cache = 1
                    job.status = "success"
                    session.commit()
                    return
                session.commit()
                cooldown = session.get(ProviderCooldown, "virustotal")
                if cooldown is not None and cooldown.available_after.replace(tzinfo=UTC) > datetime.now(UTC):
                    record.error = "Provider cooldown active; resume after Retry-After expires"
                    session.commit()
                    self._halted = True
                    return
                while record.attempts < 2:
                    if not self._virustotal_quota.reserve(datetime.now(UTC), 1).allowed:
                        job.status = "pending"
                        record.error = "Local request budget exhausted; resume after checking account quota"
                        session.commit()
                        self._halted = True
                        return
                    latest = session.scalar(select(QueryRecord.queried_at).where(QueryRecord.queried_at.is_not(None), QueryRecord.attempts > 0).order_by(QueryRecord.queried_at.desc()).limit(1))
                    if latest is not None:
                        elapsed = (datetime.now(UTC) - latest.replace(tzinfo=UTC)).total_seconds()
                        self._sleeper(max(0.0, self._request_interval - elapsed))
                    record.attempts += 1
                    record.queried_at = datetime.now(UTC)
                    job.status = "running"
                    session.commit()
                    result = self._virustotal.fetch(job.sha256)
                    record.error = result.error
                    record.report = result.report
                    job.status = result.status
                    if result.status == "rate_limited":
                        delay = max(self._request_interval, result.retry_after or 2 ** record.attempts)
                        if cooldown is None:
                            cooldown = ProviderCooldown(provider="virustotal", available_after=datetime.now(UTC) + timedelta(seconds=delay))
                            session.add(cooldown)
                        else:
                            cooldown.available_after = datetime.now(UTC) + timedelta(seconds=delay)
                    session.commit()
                    if result.status == "rate_limited" and delay > 60:
                        self._halted = True
                        break
                    if result.status not in {"timeout", "failed", "rate_limited"} or record.attempts >= 2:
                        break
                    self._sleeper(max(self._request_interval, result.retry_after or 2 ** record.attempts))
                else:
                    job.status = "failed"
                    record.error = "Attempt limit reached; explicit refresh required"
                    session.commit()
                    return
                if result.status in {"authentication_error", "rate_limited"}:
                    self._halted = True
                if result.status == "success" and result.report is not None:
                    if cache is None:
                        session.add(VirusTotalCache(sha256=job.sha256, queried_at=record.queried_at, report=result.report))
                    else:
                        cache.queried_at = record.queried_at
                        cache.report = result.report
            elif job.provider == "cn_platform":
                if self._cn_platform is None:
                    return
                reservation = self._cn_platform_quota.reserve(datetime.now(UTC), 1)
                if not reservation.allowed:
                    return
                job.status = "running"
                session.commit()
                result = self._cn_platform.fetch(job.sha256, job.report_kind)
            else:
                return
            if result.status == "success" and result.raw is not None and self._report_store is not None:
                relative_path = self._report_store.save(job.sha256, job.provider, job.report_kind, result.raw)
                existing = session.scalar(
                    select(RawReport).where(
                        RawReport.sha256 == job.sha256,
                        RawReport.provider == job.provider,
                        RawReport.report_kind == job.report_kind,
                    )
                )
                if existing is None:
                    session.add(RawReport(sha256=job.sha256, provider=job.provider, report_kind=job.report_kind, relative_path=relative_path, saved_at=datetime.now(UTC)))
                else:
                    existing.relative_path = relative_path
                    existing.saved_at = datetime.now(UTC)
            job.status = result.status
            session.commit()
