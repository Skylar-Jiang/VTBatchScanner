import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.batches import router as batches_router
from app.api.previews import router as previews_router
from app.api.reanalysis import router as reanalysis_router
from app.api.samples import router as samples_router
from app.api.system import router as system_router
from app.api.experiment import router as experiment_router
from app.api.reports import router as reports_router
from app.database import create_session_factory
from app.providers.cn_platform import CnPlatformProvider
from app.providers.virustotal import VirusTotalProvider
from app.services.batches import BatchService
from app.services.dispatcher import QueryDispatcher
from app.services.quota import PersistentDailyQuota
from app.services.storage import ReportStore
from app.services.detection_reports import DetectionReports


DEFAULT_RESULTS_ROOT = Path(__file__).resolve().parents[2] / 'results'


def create_app(
    database_url: str = "sqlite:///./data/analysis.db",
    cverc_enabled_reports: tuple[str, ...] | None = None,
    cverc_daily_quota: int | None = None,
    virustotal_api_key: str | None = None,
    cn_platform_api_key: str | None = None,
    report_root: Path | None = None,
    experiment_root: Path | None = None,
    detection_root: Path | None = None,
) -> FastAPI:
    app = FastAPI(title="Malware SHA256 Analysis API", version="1.0.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_methods=["GET", "POST"],
        allow_headers=["content-type"],
    )
    enabled_reports = cverc_enabled_reports
    if enabled_reports is None:
        enabled_reports = ()  # This experiment is VT-only; legacy support requires explicit construction.
    daily_quota = cverc_daily_quota if cverc_daily_quota is not None else int(os.getenv("CN_PLATFORM_DAILY_QUOTA", "100"))
    session_factory = create_session_factory(database_url)
    app.state.batch_service = BatchService(
        session_factory,
        enabled_reports,
    )
    app.state.cverc_quota = PersistentDailyQuota(session_factory, "cn_platform", daily_quota)
    app.state.cverc_daily_quota = daily_quota
    app.state.cverc_enabled_reports = enabled_reports
    app.state.virustotal_daily_budget = int(os.getenv("VIRUSTOTAL_DAILY_BUDGET", "500"))
    app.state.virustotal_quota = PersistentDailyQuota(session_factory, "virustotal", app.state.virustotal_daily_budget)
    virustotal_key = virustotal_api_key if virustotal_api_key is not None else os.getenv("VIRUSTOTAL_API_KEY", "")
    cn_platform_key = cn_platform_api_key if cn_platform_api_key is not None else os.getenv("CN_PLATFORM_API_KEY", "")
    resolved_report_root = (report_root or Path(__file__).resolve().parents[2] / "data" / "reports").resolve()
    app.state.report_root = resolved_report_root
    app.state.experiment_root = (experiment_root or Path(__file__).resolve().parents[2] / 'results' / 'experiment-3').resolve()
    app.state.detection_reports = DetectionReports(detection_root or DEFAULT_RESULTS_ROOT, app.state.experiment_root)
    app.state.dispatcher = QueryDispatcher(
        session_factory,
        VirusTotalProvider(virustotal_key) if virustotal_key else None,
        CnPlatformProvider(cn_platform_key, enabled_reports) if cn_platform_key and enabled_reports else None,
        app.state.cverc_quota,
        ReportStore(resolved_report_root),
        virustotal_quota=app.state.virustotal_quota,
        request_interval=max(16.0, float(os.getenv("VIRUSTOTAL_REQUEST_INTERVAL", "16"))),
        detection_reports=app.state.detection_reports,
    )
    app.include_router(previews_router, prefix="/api/v1")
    app.include_router(batches_router, prefix="/api/v1")
    app.include_router(samples_router, prefix="/api/v1")
    app.include_router(reanalysis_router, prefix="/api/v1")
    app.include_router(system_router, prefix="/api/v1")
    app.include_router(experiment_router, prefix="/api/v1")
    app.include_router(reports_router, prefix="/api/v1")
    return app


app = create_app()
