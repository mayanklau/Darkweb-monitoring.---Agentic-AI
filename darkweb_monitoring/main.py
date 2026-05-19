from functools import lru_cache

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .agents import run_investigation
from .config import Settings, get_settings
from .connectors import export_stix_bundle, list_connectors
from .google_vision import VisionNotConfigured, ocr_image_bytes
from .graph import build_graph
from .models import (
    CaseCreate,
    CaseRecord,
    CaseUpdate,
    ConnectorStatus,
    EvidenceCreate,
    EvidenceRecord,
    IntelligenceGraph,
    InvestigationReport,
    InvestigationRequest,
    OCRResult,
)
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
    }


@app.post("/api/investigations", response_model=InvestigationReport)
def create_investigation(
    request: InvestigationRequest,
    store: InvestigationStore = Depends(get_store),
    _: Principal = Depends(require_user),
) -> InvestigationReport:
    report = run_investigation(request)
    store.save(report)
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
    return store.create_case(request)


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
    return case


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
    return store.add_evidence(request)


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


@app.get("/api/admin/retention")
def retention_policy(
    settings: Settings = Depends(get_settings),
    _: Principal = Depends(require_admin),
) -> dict:
    return {
        "retention_days": settings.retention_days,
        "note": "Schedule deletion/export jobs in production according to this policy.",
    }
