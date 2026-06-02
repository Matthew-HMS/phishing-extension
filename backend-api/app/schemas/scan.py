from typing import Literal
from pydantic import BaseModel, Field

RiskLevel = Literal["LOW", "MEDIUM", "HIGH"]


class LocalFinding(BaseModel):
    url: str | None = None
    riskLevel: RiskLevel | None = None
    score: int | None = None
    reasons: list[str] = Field(default_factory=list)


class ScanRequest(BaseModel):
    url: str
    pageTitle: str | None = ""
    context: str | None = ""
    links: list[str] = Field(default_factory=list)
    localFindings: list[LocalFinding] = Field(default_factory=list)


class ScanResponse(BaseModel):
    riskLevel: RiskLevel
    score: int = Field(ge=0, le=100)
    reasons: list[str] = Field(default_factory=list)
    aiSummary: str = ""
    source: str = "backend+ai"
