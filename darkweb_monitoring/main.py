from functools import lru_cache

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .agents import run_investigation
from .config import Settings, get_settings
from .google_vision import VisionNotConfigured, ocr_image_bytes
from .models import InvestigationReport, InvestigationRequest, OCRResult
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
    }


@app.post("/api/investigations", response_model=InvestigationReport)
def create_investigation(
    request: InvestigationRequest,
    store: InvestigationStore = Depends(get_store),
) -> InvestigationReport:
    report = run_investigation(request)
    store.save(report)
    return report


@app.get("/api/investigations")
def list_investigations(store: InvestigationStore = Depends(get_store)) -> list[dict]:
    return store.list_reports()


@app.get("/api/investigations/{report_id}", response_model=InvestigationReport)
def get_investigation(
    report_id: str,
    store: InvestigationStore = Depends(get_store),
) -> InvestigationReport:
    report = store.get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return report


@app.post("/api/vision/ocr", response_model=OCRResult)
async def vision_ocr(
    file: UploadFile = File(...),
    settings: Settings = Depends(get_settings),
) -> OCRResult:
    content = await file.read()
    try:
        return ocr_image_bytes(content, settings)
    except VisionNotConfigured as exc:
        raise HTTPException(status_code=412, detail=str(exc)) from exc

