from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, JSON
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Sample(Base):
    __tablename__ = "samples"

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Batch(Base):
    __tablename__ = "batches"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    input_source: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class BatchSample(Base):
    __tablename__ = "batch_samples"

    batch_id: Mapped[str] = mapped_column(ForeignKey("batches.id"), primary_key=True)
    sha256: Mapped[str] = mapped_column(ForeignKey("samples.sha256"), primary_key=True)


class ProviderJob(Base):
    __tablename__ = "provider_jobs"
    __table_args__ = (
        UniqueConstraint("batch_id", "sha256", "provider", "report_kind"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    batch_id: Mapped[str] = mapped_column(ForeignKey("batches.id"))
    sha256: Mapped[str] = mapped_column(ForeignKey("samples.sha256"))
    provider: Mapped[str] = mapped_column(String(30))
    report_kind: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(30), default="pending")


class ProviderDailyQuota(Base):
    __tablename__ = "provider_daily_quotas"
    __table_args__ = (UniqueConstraint("provider", "day"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    provider: Mapped[str] = mapped_column(String(30))
    day: Mapped[str] = mapped_column(String(10))
    used: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class RawReport(Base):
    __tablename__ = "raw_reports"
    __table_args__ = (UniqueConstraint("sha256", "provider", "report_kind"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sha256: Mapped[str] = mapped_column(ForeignKey("samples.sha256"))
    provider: Mapped[str] = mapped_column(String(30))
    report_kind: Mapped[str] = mapped_column(String(30))
    relative_path: Mapped[str] = mapped_column(Text)
    saved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class VirusTotalCache(Base):
    __tablename__ = "virustotal_cache"
    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    queried_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    report: Mapped[dict] = mapped_column(JSON)


class QueryRecord(Base):
    __tablename__ = "query_records"
    job_id: Mapped[int] = mapped_column(ForeignKey("provider_jobs.id"), primary_key=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    from_cache: Mapped[int] = mapped_column(Integer, default=0)
    queried_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    report: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class ProviderCooldown(Base):
    __tablename__ = "provider_cooldowns"
    provider: Mapped[str] = mapped_column(String(30), primary_key=True)
    available_after: Mapped[datetime] = mapped_column(DateTime(timezone=True))
