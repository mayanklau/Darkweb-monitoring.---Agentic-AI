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


class UserRole(str, Enum):
    admin = "admin"
    manager = "manager"
    analyst = "analyst"
    viewer = "viewer"


class JobStatus(str, Enum):
    queued = "queued"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"


class RuleKind(str, Enum):
    yara = "yara"
    sigma = "sigma"
    kql = "kql"
    spl = "spl"
    suricata = "suricata"
    snort = "snort"


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
    sha256: str | None = None
    size_bytes: int | None = None
    created_at: datetime


class CaseCommentCreate(BaseModel):
    author: str = "analyst"
    body: str = Field(min_length=1)


class CaseCommentRecord(BaseModel):
    id: str
    case_id: str
    author: str
    body: str
    created_at: datetime


class UserCreate(BaseModel):
    email: str = Field(min_length=3)
    name: str = Field(min_length=1)
    role: UserRole = UserRole.analyst
    team: str = "default"


class UserRecord(BaseModel):
    id: str
    email: str
    name: str
    role: UserRole
    team: str
    active: bool
    created_at: datetime


class AuditEventRecord(BaseModel):
    id: str
    actor: str
    action: str
    resource_type: str
    resource_id: str | None = None
    metadata: dict[str, Any] = {}
    created_at: datetime


class JobCreate(BaseModel):
    kind: str
    payload: dict[str, Any] = {}


class JobRecord(BaseModel):
    id: str
    kind: str
    status: JobStatus
    payload: dict[str, Any]
    result: dict[str, Any] = {}
    created_at: datetime
    updated_at: datetime


class MonitorCreate(BaseModel):
    name: str = Field(min_length=3)
    query: str = Field(min_length=3)
    threshold: int = Field(default=70, ge=0, le=100)
    cadence: str = "daily"
    enabled: bool = True


class MonitorRecord(BaseModel):
    id: str
    name: str
    query: str
    threshold: int
    cadence: str
    enabled: bool
    last_result: dict[str, Any] = {}
    created_at: datetime
    updated_at: datetime


class NotificationCreate(BaseModel):
    channel: str = "webhook"
    target: str = "default"
    title: str = Field(min_length=3)
    body: str = Field(min_length=1)


class NotificationRecord(BaseModel):
    id: str
    channel: str
    target: str
    title: str
    body: str
    delivered: bool
    created_at: datetime


class RuleCreate(BaseModel):
    report_id: str
    kind: RuleKind
    name: str
    content: str
    rationale: str = ""


class RuleRecord(BaseModel):
    id: str
    report_id: str
    kind: RuleKind
    name: str
    content: str
    rationale: str
    version: int
    created_at: datetime


class DashboardMetrics(BaseModel):
    investigations: int
    cases: int
    evidence: int
    monitors: int
    open_cases_by_severity: dict[str, int]
    average_risk_score: float


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
