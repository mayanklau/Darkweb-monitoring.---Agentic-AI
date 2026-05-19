from functools import lru_cache
import hashlib

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .agents import run_investigation
from .config import Settings, get_settings
from .connectors import export_stix_bundle, list_connectors
from .google_vision import VisionNotConfigured, ocr_image_bytes
from .graph import build_graph
from .monitors import evaluate_monitor
from .models import (
    AuditEventRecord,
    CaseCreate,
    CaseCommentCreate,
    CaseCommentRecord,
    CaseRecord,
    CaseUpdate,
    ConnectorStatus,
    DashboardMetrics,
    EvidenceCreate,
    EvidenceRecord,
    IntelligenceGraph,
    InvestigationReport,
    InvestigationRequest,
    JobCreate,
    JobRecord,
    MonitorCreate,
    MonitorRecord,
    NotificationCreate,
    NotificationRecord,
    OCRResult,
    RuleCreate,
    RuleKind,
    RuleRecord,
    UserCreate,
    UserRecord,
)
from .rulegen import generate_detection_pack
from .security import Principal, require_admin, require_user
from .storage import InvestigationStore

app = FastAPI(
    title="Darkweb Monitoring Agentic AI",
    description="Agentic dark-web investigation workflow with optional Google Cloud Vision OCR.",
    version="0.1.0",
)


@lru_cache
def get_store() -> InvestigationStore:
    return InvestigationStore(get_settings().database_url)


settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse("static/index.html")


@app.get("/api/health")
def health(settings: Settings = Depends(get_settings)) -> dict:
    return {
        "status": "ok",
        "environment": settings.app_env,
        "vision_ocr_enabled": settings.vision_ocr_enabled,
        "auth_enabled": settings.auth_enabled,
        "scheduled_monitors_enabled": settings.enable_scheduled_monitors,
    }


@app.get("/api/dashboard", response_model=DashboardMetrics)
def dashboard(
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_user),
) -> DashboardMetrics:
    return store.dashboard()


@app.post("/api/investigations", response_model=InvestigationReport)
def create_investigation(
    request: InvestigationRequest,
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_user),
) -> InvestigationReport:
    report = run_investigation(request)
    store.save(report)
    store.audit("api", "create", "investigation", report.id, {"risk_score": report.risk_score})
    return report


@app.get("/api/investigations")
def list_investigations(
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_user),
) -> list[dict]:
    return store.list_reports()


@app.get("/api/investigations/{report_id}", response_model=InvestigationReport)
def get_investigation(
    report_id: str,
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_user),
) -> InvestigationReport:
    report = store.get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return report


@app.post("/api/vision/ocr", response_model=OCRResult)
async def vision_ocr(
    file: UploadFile = File(...),
    settings: Settings = Depends(get_settings),
    _: Principal = Depends(require_user),
) -> OCRResult:
    content = await file.read()
    try:
        return ocr_image_bytes(content, settings)
    except VisionNotConfigured as exc:
        raise HTTPException(status_code=412, detail=str(exc)) from exc


@app.post("/api/cases", response_model=CaseRecord)
def create_case(
    request: CaseCreate,
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_user),
) -> CaseRecord:
    case = store.create_case(request)
    store.audit("api", "create", "case", case.id, {"severity": case.severity.value})
    return case


@app.get("/api/cases", response_model=list[CaseRecord])
def list_cases(
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_user),
) -> list[CaseRecord]:
    return store.list_cases()


@app.get("/api/cases/{case_id}", response_model=CaseRecord)
def get_case(
    case_id: str,
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_user),
) -> CaseRecord:
    case = store.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@app.patch("/api/cases/{case_id}", response_model=CaseRecord)
def update_case(
    case_id: str,
    request: CaseUpdate,
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_user),
) -> CaseRecord:
    case = store.update_case(case_id, request)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    store.audit("api", "update", "case", case.id, request.model_dump(exclude_unset=True))
    return case


@app.post("/api/cases/{case_id}/comments", response_model=CaseCommentRecord)
def add_case_comment(
    case_id: str,
    request: CaseCommentCreate,
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_user),
) -> CaseCommentRecord:
    comment = store.create_comment(case_id, request)
    if comment is None:
        raise HTTPException(status_code=404, detail="Case not found")
    store.audit(request.author, "comment", "case", case_id)
    return comment


@app.get("/api/cases/{case_id}/comments", response_model=list[CaseCommentRecord])
def list_case_comments(
    case_id: str,
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_user),
) -> list[CaseCommentRecord]:
    if store.get_case(case_id) is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return store.list_comments(case_id)


@app.post("/api/cases/{case_id}/evidence", response_model=EvidenceRecord)
def add_case_evidence(
    case_id: str,
    request: EvidenceCreate,
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_user),
) -> EvidenceRecord:
    if store.get_case(case_id) is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return store.add_evidence(request, case_id=case_id)


@app.get("/api/cases/{case_id}/evidence", response_model=list[EvidenceRecord])
def list_case_evidence(
    case_id: str,
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_user),
) -> list[EvidenceRecord]:
    if store.get_case(case_id) is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return store.list_evidence(case_id=case_id)


@app.post("/api/cases/{case_id}/investigations/{report_id}", response_model=CaseRecord)
def attach_investigation(
    case_id: str,
    report_id: str,
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_user),
) -> CaseRecord:
    if not store.attach_investigation_to_case(report_id, case_id):
        raise HTTPException(status_code=404, detail="Case or investigation not found")
    case = store.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@app.post("/api/evidence", response_model=EvidenceRecord)
def add_standalone_evidence(
    request: EvidenceCreate,
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_user),
) -> EvidenceRecord:
    evidence = store.add_evidence(request)
    store.audit("api", "create", "evidence", evidence.id, {"source_type": evidence.source_type})
    return evidence


@app.post("/api/uploads/evidence", response_model=list[EvidenceRecord])
async def upload_evidence(
    files: list[UploadFile] = File(...),
    store: InvestigationStore = Depends(get_store),
    settings: Settings = Depends(get_settings),
    _: Principal = Depends(require_user),
) -> list[EvidenceRecord]:
    records: list[EvidenceRecord] = []
    for upload in files:
        content = await upload.read()
        if len(content) > settings.max_upload_bytes:
            raise HTTPException(status_code=413, detail=f"{upload.filename} exceeds upload limit")
        digest = hashlib.sha256(content).hexdigest()
        try:
            text = content.decode("utf-8")
            source_type = "text-upload"
        except UnicodeDecodeError:
            text = f"Binary evidence uploaded: {upload.filename}"
            source_type = "binary-upload"
        evidence = store.add_evidence(
            EvidenceCreate(
                title=upload.filename or "uploaded evidence",
                source_type=source_type,
                content=text,
            ),
            sha256=digest,
            size_bytes=len(content),
        )
        store.audit("api", "upload", "evidence", evidence.id, {"sha256": digest})
        records.append(evidence)
    return records


@app.get("/api/graph", response_model=IntelligenceGraph)
def get_graph(
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_user),
) -> IntelligenceGraph:
    return build_graph(store.all_reports())


@app.get("/api/connectors", response_model=list[ConnectorStatus])
def connectors(_: Principal = Depends(require_user)) -> list[ConnectorStatus]:
    return list_connectors()


@app.get("/api/investigations/{report_id}/exports/stix")
def stix_export(
    report_id: str,
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_user),
) -> dict:
    report = store.get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return export_stix_bundle(report)


@app.post("/api/investigations/{report_id}/rules/generate", response_model=list[RuleRecord])
def generate_rules(
    report_id: str,
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_user),
) -> list[RuleRecord]:
    report = store.get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    records = [store.save_rule(rule) for rule in generate_detection_pack(report)]
    for yara in report.yara_rules:
        records.append(
            store.save_rule(
                request=RuleCreate(
                    report_id=report.id,
                    kind=RuleKind.yara,
                    name=yara.name,
                    content=yara.rule,
                    rationale=yara.rationale,
                )
            )
        )
    store.audit("api", "generate", "rules", report.id, {"count": len(records)})
    return records


@app.get("/api/rules", response_model=list[RuleRecord])
def list_rules(
    report_id: str | None = None,
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_user),
) -> list[RuleRecord]:
    return store.list_rules(report_id=report_id)


@app.post("/api/jobs", response_model=JobRecord)
def create_job(
    request: JobCreate,
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_user),
) -> JobRecord:
    job = store.create_job(request)
    store.audit("api", "create", "job", job.id, {"kind": job.kind})
    return job


@app.post("/api/jobs/{job_id}/complete", response_model=JobRecord)
def complete_job(
    job_id: str,
    result: dict,
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_user),
) -> JobRecord:
    job = store.complete_job(job_id, result)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@app.get("/api/jobs", response_model=list[JobRecord])
def list_jobs(
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_user),
) -> list[JobRecord]:
    return store.list_jobs()


@app.post("/api/monitors", response_model=MonitorRecord)
def create_monitor(
    request: MonitorCreate,
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_user),
) -> MonitorRecord:
    monitor = store.create_monitor(request)
    store.audit("api", "create", "monitor", monitor.id, {"threshold": monitor.threshold})
    return monitor


@app.get("/api/monitors", response_model=list[MonitorRecord])
def list_monitors(
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_user),
) -> list[MonitorRecord]:
    return store.list_monitors()


@app.post("/api/monitors/{monitor_id}/evaluate", response_model=MonitorRecord)
def run_monitor(
    monitor_id: str,
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_user),
) -> MonitorRecord:
    monitor = next((item for item in store.list_monitors() if item.id == monitor_id), None)
    if monitor is None:
        raise HTTPException(status_code=404, detail="Monitor not found")
    result = evaluate_monitor(monitor)
    updated = store.update_monitor_result(monitor_id, result)
    if updated is None:
        raise HTTPException(status_code=404, detail="Monitor not found")
    return updated


@app.post("/api/notifications", response_model=NotificationRecord)
def create_notification(
    request: NotificationCreate,
    store: InvestigationStore = Depends(get_store),
    settings: Settings = Depends(get_settings),
    _: Principal = Depends(require_user),
) -> NotificationRecord:
    delivered = bool(settings.notification_webhook_url) or request.channel in {"local", "email"}
    notification = store.create_notification(request, delivered=delivered)
    store.audit("api", "create", "notification", notification.id, {"delivered": delivered})
    return notification


@app.get("/api/notifications", response_model=list[NotificationRecord])
def list_notifications(
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_user),
) -> list[NotificationRecord]:
    return store.list_notifications()


@app.post("/api/users", response_model=UserRecord)
def create_user(
    request: UserCreate,
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_admin),
) -> UserRecord:
    user = store.create_user(request)
    store.audit("api", "create", "user", user.id, {"role": user.role.value})
    return user


@app.get("/api/users", response_model=list[UserRecord])
def list_users(
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_admin),
) -> list[UserRecord]:
    return store.list_users()


@app.get("/api/audit", response_model=list[AuditEventRecord])
def list_audit_events(
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_admin),
) -> list[AuditEventRecord]:
    return store.list_audit_events()


@app.get("/api/admin/retention")
def retention_policy(
    settings: Settings = Depends(get_settings),
    _: Principal = Depends(require_admin),
) -> dict:
    return {
        "retention_days": settings.retention_days,
        "note": "Schedule deletion/export jobs in production according to this policy.",
    }
