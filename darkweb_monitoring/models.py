from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class InvestigationFocus(str, Enum):
    scoping = "scoping"
    actor = "actor"
    technical = "technical"
    financial = "financial"


class CaseStatus(str, Enum):
    draft = "draft"
    triaged = "triaged"
    escalated = "escalated"
    closed = "closed"


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


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


class CaseCreate(BaseModel):
    title: str = Field(min_length=3)
    description: str = ""
    owner: str = "unassigned"
    severity: Severity = Severity.medium
    tags: list[str] = []


class CaseUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    owner: str | None = None
    severity: Severity | None = None
    status: CaseStatus | None = None
    tags: list[str] | None = None


class CaseRecord(BaseModel):
    id: str
    title: str
    description: str
    owner: str
    severity: Severity
    status: CaseStatus
    tags: list[str]
    created_at: datetime
    updated_at: datetime
    investigation_ids: list[str] = []
    evidence_ids: list[str] = []


class EvidenceCreate(BaseModel):
    title: str = Field(min_length=3)
    source_type: str = "manual"
    content: str = Field(min_length=1)
    source_uri: str | None = None


class EvidenceRecord(BaseModel):
    id: str
    case_id: str | None = None
    title: str
    source_type: str
    content: str
    source_uri: str | None = None
    created_at: datetime


class GraphNode(BaseModel):
    id: str
    label: str
    kind: str
    properties: dict[str, Any] = {}


class GraphEdge(BaseModel):
    source: str
    target: str
    relationship: str
    confidence: float = Field(ge=0, le=1)


class IntelligenceGraph(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class ConnectorStatus(BaseModel):
    name: str
    kind: str
    enabled: bool
    mode: str
    description: str

