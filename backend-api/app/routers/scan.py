from fastapi import APIRouter, HTTPException
from app.schemas.scan import ScanRequest, ScanResponse
from app.services.ai_checker import analyze_with_ai
from app.services.rule_checker import check_rules

router = APIRouter(prefix="/api/v1", tags=["scan"])


@router.get("/health")
async def health() -> dict:
    return {"ok": True, "service": "phishing-guard-backend"}


@router.post("/scan", response_model=ScanResponse)
async def scan(payload: ScanRequest) -> ScanResponse:
    if not payload.url.strip():
        raise HTTPException(status_code=400, detail="url is required")
    return await analyze_with_ai(payload)


@router.post("/scan/rules", response_model=ScanResponse)
async def scan_rules(payload: ScanRequest) -> ScanResponse:
    if not payload.url.strip():
        raise HTTPException(status_code=400, detail="url is required")
    return check_rules(payload)
