from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class InvestigationFocus(str, Enum):
    scoping = "scoping"
    actor = "actor"
    technical = "technical"
    financial = "financial"


class Indicator(BaseModel):
    kind: str
    value: str
    confidence: float = Field(ge=0, le=1)
    evidence: str


class YaraRule(BaseModel):
    name: str
    family: str
    rule: str
    rationale: str


class AgentFinding(BaseModel):
    agent: str
    finding: str
    confidence: float = Field(ge=0, le=1)
    recommended_action: str


class InvestigationRequest(BaseModel):
    title: str = Field(default="Dark-web shell-sale investigation", min_length=3)
    seed_text: str = Field(min_length=10)
    organization_profile: str = Field(
        default="Enterprise with public web properties, email infrastructure, and cloud workloads."
    )
    focus: InvestigationFocus = InvestigationFocus.scoping
    generate_yara: bool = True
    run_swarm_simulation: bool = True


class InvestigationReport(BaseModel):
    id: str
    title: str
    created_at: datetime
    focus: InvestigationFocus
    executive_summary: str
    risk_score: int = Field(ge=0, le=100)
    indicators: list[Indicator]
    findings: list[AgentFinding]
    pivots: list[str]
    yara_rules: list[YaraRule]
    next_actions: list[str]


class OCRResult(BaseModel):
    text: str
    pages_or_images: int
    provider: str

