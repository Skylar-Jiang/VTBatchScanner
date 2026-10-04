from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select

from app.database import SessionFactory
from app.models import Batch, BatchSample, ProviderJob, RawReport, Sample, QueryRecord


@dataclass(frozen=True)
class BatchSummary:
    id: str
    name: str
    input_source: str
    sample_count: int
    total_provider_jobs: int
    created_at: datetime


class BatchService:
    def __init__(self, session_factory: SessionFactory, cverc_enabled_reports: tuple[str, ...]) -> None:
        self._session_factory = session_factory
        self._cverc_enabled_reports = cverc_enabled_reports

    def create(self, name: str, input_source: str, sha256s: list[str]) -> BatchSummary:
        created_at = datetime.now(UTC)
        batch_id = f"bat_{uuid4().hex}"
        with self._session_factory() as session:
            session.add(
                Batch(
                    id=batch_id,
                    name=name,
                    input_source=input_source,
                    created_at=created_at,
                )
            )
            for sha256 in sha256s:
                sample = session.get(Sample, sha256)
                if sample is None:
                    session.add(
                        Sample(
                            sha256=sha256,
                            created_at=created_at,
                            updated_at=created_at,
                        )
                    )
                session.add(BatchSample(batch_id=batch_id, sha256=sha256))
                session.add(
                    ProviderJob(
                        batch_id=batch_id,
                        sha256=sha256,
                        provider="virustotal",
                        report_kind="report",
                        status="pending",
                    )
                )
                for report_kind in self._cverc_enabled_reports:
                    session.add(
                        ProviderJob(
                            batch_id=batch_id,
                            sha256=sha256,
                            provider="cn_platform",
                            report_kind=report_kind,
                            status="pending",
                        )
                    )
            session.commit()

        return BatchSummary(
            id=batch_id,
            name=name,
            input_source=input_source,
            sample_count=len(sha256s),
            total_provider_jobs=len(sha256s) * (1 + len(self._cverc_enabled_reports)),
            created_at=created_at,
        )

    def detail(self, batch_id: str) -> tuple[BatchSummary, list[dict[str, object]]] | None:
        with self._session_factory() as session:
            batch = session.get(Batch, batch_id)
            if batch is None:
                return None
            sha256s = list(
                session.scalars(
                    select(BatchSample.sha256).where(BatchSample.batch_id == batch_id)
                )
            )
            jobs = list(
                session.scalars(select(ProviderJob).where(ProviderJob.batch_id == batch_id))
            )

        jobs_by_hash: dict[str, list[ProviderJob]] = {sha256: [] for sha256 in sha256s}
        for job in jobs:
            jobs_by_hash[job.sha256].append(job)
        samples = [
            self._sample_payload(Sample(sha256=sha256), jobs_by_hash[sha256])
            for sha256 in sha256s
        ]
        return (
            BatchSummary(
                id=batch.id,
                name=batch.name,
                input_source=batch.input_source,
                sample_count=len(sha256s),
                total_provider_jobs=len(jobs),
                created_at=batch.created_at,
            ),
            samples,
        )

    def list_batches(self) -> list[BatchSummary]:
        with self._session_factory() as session:
            ids = list(session.scalars(select(Batch.id).order_by(Batch.created_at.desc())))
        return [self.detail(batch_id)[0] for batch_id in ids]

    def progress(self, batch_id: str) -> dict:
        with self._session_factory() as session:
            statuses = list(session.scalars(select(ProviderJob.status).where(ProviderJob.batch_id == batch_id)))
        terminal = sum(status not in {"pending", "running", "retrying"} for status in statuses)
        return {"totalProviderJobs": len(statuses), "terminalProviderJobs": terminal,
                "succeeded": statuses.count("success"), "notFound": statuses.count("not_found"),
                "failed": terminal - statuses.count("success") - statuses.count("not_found"),
                "percent": round(100 * terminal / len(statuses), 1) if statuses else 0}

    def export_batch(self, batch_id: str) -> dict | None:
        detail = self.detail(batch_id)
        if detail is None:
            return None
        batch, samples = detail
        with self._session_factory() as session:
            jobs = list(session.scalars(select(ProviderJob).where(ProviderJob.batch_id == batch_id, ProviderJob.provider == "virustotal")))
            by_hash = {job.sha256: job for job in jobs}
            for sample in samples:
                job = by_hash[sample["sha256"]]
                record = session.get(QueryRecord, job.id)
                sample.update({"queryStatus": job.status, "report": record.report if record else None,
                               "attempts": record.attempts if record else 0,
                               "fromCache": bool(record.from_cache) if record else False,
                               "error": record.error if record else None,
                               "queriedAt": record.queried_at.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z") if record and record.queried_at else None})
        progress = self.progress(batch_id)
        return {"batchId": batch_id, "name": batch.name, "summary": {"total": batch.sample_count,
                "successful": progress["succeeded"], "notFound": progress["notFound"], "failed": progress["failed"],
                "pending": batch.total_provider_jobs - progress["terminalProviderJobs"],
                "apiAttempts": sum(row["attempts"] for row in samples), "cacheHits": sum(row["fromCache"] for row in samples)},
                "samples": samples}

    def list_samples(self) -> list[dict[str, object]]:
        with self._session_factory() as session:
            samples = list(session.scalars(select(Sample).order_by(Sample.updated_at.desc())))
            jobs = list(session.scalars(select(ProviderJob)))
        return [self._sample_payload(sample, jobs) for sample in samples]

    def sample_detail(self, sha256: str) -> dict[str, object] | None:
        with self._session_factory() as session:
            sample = session.get(Sample, sha256)
            if sample is None:
                return None
            jobs = list(session.scalars(select(ProviderJob).where(ProviderJob.sha256 == sha256).order_by(ProviderJob.id)))
        payload = self._sample_payload(sample, jobs)
        with self._session_factory() as session:
            records = {job.id: session.get(QueryRecord, job.id) for job in jobs}
        payload["providerResults"] = [
            {
                "provider": job.provider,
                "status": job.status,
                "fromCache": bool(records[job.id].from_cache) if records[job.id] else False,
                "queriedAt": records[job.id].queried_at.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z") if records[job.id] and records[job.id].queried_at else None,
                "analysisTime": (records[job.id].report or {}).get("analysisTime") if records[job.id] else None,
                "retryCount": max(0, records[job.id].attempts - 1) if records[job.id] else 0,
                "error": records[job.id].error if records[job.id] else None,
                "report": records[job.id].report if records[job.id] else None,
                "rawReports": [],
            }
            for job in jobs
        ]
        payload["createdAt"] = sample.created_at.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z")
        payload["updatedAt"] = sample.updated_at.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z")
        return payload

    def dashboard(self) -> dict[str, object]:
        samples = self.list_samples()
        status_counts = {"completed": 0, "running": 0, "failed": 0}
        risks = {"malicious": 0, "suspicious": 0, "undetected": 0, "clean": 0, "unknown": 0}
        for sample in samples:
            status = str(sample["status"])
            if status in status_counts:
                status_counts[status] += 1
            risks[str(sample["risk"])] += 1
        return {
            "samples": {
                "total": len(samples),
                "completed": status_counts["completed"],
                "analyzing": status_counts["running"],
                "failed": status_counts["failed"],
            },
            "riskDistribution": risks,
            "providers": [
                {"provider": "virustotal", "status": "unknown", "successful": 0, "failed": 0, "lastSuccessAt": None},
                {"provider": "cn_platform", "status": "unknown", "successful": 0, "failed": 0, "lastSuccessAt": None},
            ],
            "recentBatches": [],
        }

    def has_sample(self, sha256: str) -> bool:
        with self._session_factory() as session:
            return session.get(Sample, sha256) is not None

    def provider_job_count(self, batch_id: str, provider: str) -> int:
        with self._session_factory() as session:
            return len(
                list(
                    session.scalars(
                        select(ProviderJob).where(
                            ProviderJob.batch_id == batch_id,
                            ProviderJob.provider == provider,
                        )
                    )
                )
            )

    def raw_report_path(self, sha256: str, provider: str, report_kind: str) -> str | None:
        with self._session_factory() as session:
            report = session.scalar(
                select(RawReport).where(
                    RawReport.sha256 == sha256,
                    RawReport.provider == provider,
                    RawReport.report_kind == report_kind,
                )
            )
        return report.relative_path if report is not None else None

    def _sample_payload(self, sample: Sample, jobs: list[ProviderJob]) -> dict[str, object]:
        sample_jobs = [job for job in jobs if job.sha256 == sample.sha256]
        sample_jobs.sort(key=lambda job: job.id, reverse=True)
        latest = {}
        for job in sample_jobs:
            latest.setdefault((job.provider, job.report_kind), job)
        sample_jobs = list(latest.values())
        with self._session_factory() as session:
            latest_vt = next((job for job in sample_jobs if job.provider == "virustotal"), None)
            record = session.get(QueryRecord, latest_vt.id) if latest_vt else None
            report = record.report if record and latest_vt.status == "success" else None
        statuses = [job.status for job in sample_jobs]
        provider_statuses = {
            "virustotal": self._provider_status(sample_jobs, "virustotal"),
            "cn_platform": self._provider_status(sample_jobs, "cn_platform"),
        }
        return {
            "sha256": sample.sha256,
            "risk": report.get("risk", "unknown") if report else "unknown",
            "riskSources": ["virustotal"] if report else [],
            "status": self._aggregate_status(statuses),
            "lastAnalysisAt": report.get("analysisTime") if report else None,
            "providerStatuses": provider_statuses,
        }

    @staticmethod
    def _provider_status(jobs: list[ProviderJob], provider: str) -> str:
        provider_jobs = [job for job in jobs if job.provider == provider]
        if not provider_jobs:
            return "not_supported"
        if any(job.status in {"pending", "running", "retrying"} for job in provider_jobs):
            return "pending"
        return provider_jobs[0].status

    @staticmethod
    def _aggregate_status(statuses: list[str]) -> str:
        if not statuses:
            return "failed"
        if any(status in {"pending", "running", "retrying"} for status in statuses):
            return "running"
        if all(status in {"success", "not_found"} for status in statuses):
            return "completed"
        if any(status in {"success", "not_found"} for status in statuses):
            return "partial_failed"
        return "failed"
