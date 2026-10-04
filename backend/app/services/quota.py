from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select

from app.database import SessionFactory
from app.models import ProviderDailyQuota


@dataclass(frozen=True)
class QuotaReservation:
    allowed: bool
    remaining: int


class DailyQuota:
    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._used_by_day: dict[str, int] = {}

    def reserve(self, requested_at: datetime, request_count: int) -> QuotaReservation:
        day_key = requested_at.date().isoformat()
        used = self._used_by_day.get(day_key, 0)
        if request_count <= 0 or used + request_count > self._limit:
            return QuotaReservation(allowed=False, remaining=self._limit - used)

        used += request_count
        self._used_by_day[day_key] = used
        return QuotaReservation(allowed=True, remaining=self._limit - used)


class PersistentDailyQuota:
    def __init__(self, session_factory: SessionFactory, provider: str, limit: int) -> None:
        self._session_factory = session_factory
        self._provider = provider
        self._limit = limit

    def reserve(self, requested_at: datetime, request_count: int) -> QuotaReservation:
        day_key = requested_at.date().isoformat()
        with self._session_factory() as session:
            usage = session.scalar(
                select(ProviderDailyQuota).where(
                    ProviderDailyQuota.provider == self._provider,
                    ProviderDailyQuota.day == day_key,
                )
            )
            used = usage.used if usage is not None else 0
            if request_count <= 0 or used + request_count > self._limit:
                return QuotaReservation(allowed=False, remaining=self._limit - used)
            if usage is None:
                usage = ProviderDailyQuota(
                    provider=self._provider,
                    day=day_key,
                    used=request_count,
                    updated_at=requested_at,
                )
                session.add(usage)
            else:
                usage.used += request_count
                usage.updated_at = requested_at
            session.commit()
            return QuotaReservation(allowed=True, remaining=self._limit - usage.used)

    def remaining(self, requested_at: datetime) -> int:
        day_key = requested_at.date().isoformat()
        with self._session_factory() as session:
            usage = session.scalar(
                select(ProviderDailyQuota).where(
                    ProviderDailyQuota.provider == self._provider,
                    ProviderDailyQuota.day == day_key,
                )
            )
        return self._limit - (usage.used if usage is not None else 0)
