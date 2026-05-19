import json
import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, Integer, String, Text, create_engine, inspect, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from .models import (
    AuditEventRecord,
    CaseCreate,
    CaseCommentCreate,
    CaseCommentRecord,
    CaseRecord,
    CaseStatus,
    CaseUpdate,
    DashboardMetrics,
    EvidenceCreate,
    EvidenceRecord,
    InvestigationReport,
    JobCreate,
    JobRecord,
    JobStatus,
    MonitorCreate,
    MonitorRecord,
    NotificationCreate,
    NotificationRecord,
    RuleCreate,
    RuleKind,
    RuleRecord,
    Severity,
    UserCreate,
    UserRecord,
    UserRole,
)


class Base(DeclarativeBase):
    pass


class InvestigationRow(Base):
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    case_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    payload: Mapped[str] = mapped_column(Text, nullable=False)


class CaseRow(Base):
    __tablename__ = "cases"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    owner: Mapped[str] = mapped_column(String(200), nullable=False, default="unassigned")
    severity: Mapped[str] = mapped_column(String(40), nullable=False, default=Severity.medium.value)
    status: Mapped[str] = mapped_column(String(40), nullable=False, default=CaseStatus.draft.value)
    tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class EvidenceRow(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    case_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    source_type: Mapped[str] = mapped_column(String(80), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    source_uri: Mapped[str | None] = mapped_column(Text, nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(128), nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CaseCommentRow(Base):
    __tablename__ = "case_comments"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    case_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    author: Mapped[str] = mapped_column(String(200), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class UserRow(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    email: Mapped[str] = mapped_column(String(300), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    role: Mapped[str] = mapped_column(String(40), nullable=False)
    team: Mapped[str] = mapped_column(String(120), nullable=False)
    active: Mapped[bool] = mapped_column(default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AuditEventRow(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(120), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    event_metadata: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class JobRow(Base):
    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(40), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    result: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class MonitorRow(Base):
    __tablename__ = "monitors"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(220), nullable=False)
    query: Mapped[str] = mapped_column(Text, nullable=False)
    threshold: Mapped[int] = mapped_column(Integer, nullable=False)
    cadence: Mapped[str] = mapped_column(String(80), nullable=False)
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False)
    last_result: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class NotificationRow(Base):
    __tablename__ = "notifications"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    channel: Mapped[str] = mapped_column(String(80), nullable=False)
    target: Mapped[str] = mapped_column(String(300), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    delivered: Mapped[bool] = mapped_column(default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RuleRow(Base):
    __tablename__ = "rules"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    report_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    name: Mapped[str] = mapped_column(String(220), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class InvestigationStore:
    def __init__(self, database_url: str):
        connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
        self.engine = create_engine(database_url, connect_args=connect_args, future=True)
        self.session_factory = sessionmaker(self.engine, expire_on_commit=False)
        Base.metadata.create_all(self.engine)
        self._migrate_existing_schema()

    def _migrate_existing_schema(self) -> None:
        inspector = inspect(self.engine)
        if "investigations" not in inspector.get_table_names():
            return
        columns = {column["name"] for column in inspector.get_columns("investigations")}
        if "case_id" not in columns:
            with self.engine.begin() as conn:
                conn.execute(text("ALTER TABLE investigations ADD COLUMN case_id VARCHAR(64)"))
        if "evidence" in inspector.get_table_names():
            evidence_columns = {column["name"] for column in inspector.get_columns("evidence")}
            with self.engine.begin() as conn:
                if "sha256" not in evidence_columns:
                    conn.execute(text("ALTER TABLE evidence ADD COLUMN sha256 VARCHAR(128)"))
                if "size_bytes" not in evidence_columns:
                    conn.execute(text("ALTER TABLE evidence ADD COLUMN size_bytes INTEGER"))

    def save(self, report: InvestigationReport, case_id: str | None = None) -> None:
        with self.session_factory.begin() as session:
            session.merge(
                InvestigationRow(
                    id=report.id,
                    title=report.title,
                    created_at=report.created_at,
                    risk_score=report.risk_score,
                    case_id=case_id,
                    payload=report.model_dump_json(),
                )
            )

    def list_reports(self) -> list[dict]:
        with self.session_factory() as session:
            rows = session.scalars(
                select(InvestigationRow).order_by(InvestigationRow.created_at.desc()).limit(100)
            ).all()
        return [
            {
                "id": row.id,
                "title": row.title,
                "created_at": row.created_at.isoformat(),
                "risk_score": row.risk_score,
                "case_id": row.case_id,
            }
            for row in rows
        ]

    def get(self, report_id: str) -> InvestigationReport | None:
        with self.session_factory() as session:
            row = session.get(InvestigationRow, report_id)
        if row is None:
            return None
        return InvestigationReport.model_validate(json.loads(row.payload))

    def create_case(self, request: CaseCreate) -> CaseRecord:
        now = datetime.now(UTC)
        row = CaseRow(
            id=uuid.uuid4().hex[:16],
            title=request.title,
            description=request.description,
            owner=request.owner,
            severity=request.severity.value,
            status=CaseStatus.draft.value,
            tags=request.tags,
            created_at=now,
            updated_at=now,
        )
        with self.session_factory.begin() as session:
            session.add(row)
        return self._case_record(row, [], [])

    def update_case(self, case_id: str, request: CaseUpdate) -> CaseRecord | None:
        with self.session_factory.begin() as session:
            row = session.get(CaseRow, case_id)
            if row is None:
                return None
            updates = request.model_dump(exclude_unset=True)
            for key, value in updates.items():
                if value is None:
                    continue
                setattr(row, key, value.value if hasattr(value, "value") else value)
            row.updated_at = datetime.now(UTC)
            case = self._case_record(
                row,
                self._case_investigation_ids(session, case_id),
                self._case_evidence_ids(session, case_id),
            )
        return case

    def list_cases(self) -> list[CaseRecord]:
        with self.session_factory() as session:
            rows = session.scalars(select(CaseRow).order_by(CaseRow.updated_at.desc())).all()
            return [
                self._case_record(
                    row,
                    self._case_investigation_ids(session, row.id),
                    self._case_evidence_ids(session, row.id),
                )
                for row in rows
            ]

    def get_case(self, case_id: str) -> CaseRecord | None:
        with self.session_factory() as session:
            row = session.get(CaseRow, case_id)
            if row is None:
                return None
            return self._case_record(
                row,
                self._case_investigation_ids(session, case_id),
                self._case_evidence_ids(session, case_id),
            )

    def add_evidence(
        self,
        request: EvidenceCreate,
        case_id: str | None = None,
        sha256: str | None = None,
        size_bytes: int | None = None,
    ) -> EvidenceRecord:
        row = EvidenceRow(
            id=uuid.uuid4().hex[:16],
            case_id=case_id,
            title=request.title,
            source_type=request.source_type,
            content=request.content,
            source_uri=request.source_uri,
            sha256=sha256,
            size_bytes=size_bytes,
            created_at=datetime.now(UTC),
        )
        with self.session_factory.begin() as session:
            session.add(row)
        return self._evidence_record(row)

    def list_evidence(self, case_id: str | None = None) -> list[EvidenceRecord]:
        with self.session_factory() as session:
            statement = select(EvidenceRow).order_by(EvidenceRow.created_at.desc())
            if case_id:
                statement = statement.where(EvidenceRow.case_id == case_id)
            rows = session.scalars(statement).all()
        return [self._evidence_record(row) for row in rows]

    def attach_investigation_to_case(self, report_id: str, case_id: str) -> bool:
        with self.session_factory.begin() as session:
            if session.get(CaseRow, case_id) is None:
                return False
            row = session.get(InvestigationRow, report_id)
            if row is None:
                return False
            row.case_id = case_id
        return True

    def all_reports(self) -> list[InvestigationReport]:
        with self.session_factory() as session:
            rows = session.scalars(select(InvestigationRow)).all()
        return [InvestigationReport.model_validate(json.loads(row.payload)) for row in rows]

    def create_comment(self, case_id: str, request: CaseCommentCreate) -> CaseCommentRecord | None:
        with self.session_factory.begin() as session:
            if session.get(CaseRow, case_id) is None:
                return None
            row = CaseCommentRow(
                id=uuid.uuid4().hex[:16],
                case_id=case_id,
                author=request.author,
                body=request.body,
                created_at=datetime.now(UTC),
            )
            session.add(row)
        return self._comment_record(row)

    def list_comments(self, case_id: str) -> list[CaseCommentRecord]:
        with self.session_factory() as session:
            rows = session.scalars(
                select(CaseCommentRow)
                .where(CaseCommentRow.case_id == case_id)
                .order_by(CaseCommentRow.created_at.asc())
            ).all()
        return [self._comment_record(row) for row in rows]

    def create_user(self, request: UserCreate) -> UserRecord:
        row = UserRow(
            id=uuid.uuid4().hex[:16],
            email=request.email.lower(),
            name=request.name,
            role=request.role.value,
            team=request.team,
            active=True,
            created_at=datetime.now(UTC),
        )
        with self.session_factory.begin() as session:
            session.add(row)
        return self._user_record(row)

    def list_users(self) -> list[UserRecord]:
        with self.session_factory() as session:
            rows = session.scalars(select(UserRow).order_by(UserRow.created_at.desc())).all()
        return [self._user_record(row) for row in rows]

    def audit(
        self,
        actor: str,
        action: str,
        resource_type: str,
        resource_id: str | None = None,
        metadata: dict | None = None,
    ) -> AuditEventRecord:
        row = AuditEventRow(
            id=uuid.uuid4().hex[:16],
            actor=actor,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            event_metadata=metadata or {},
            created_at=datetime.now(UTC),
        )
        with self.session_factory.begin() as session:
            session.add(row)
        return self._audit_record(row)

    def list_audit_events(self) -> list[AuditEventRecord]:
        with self.session_factory() as session:
            rows = session.scalars(
                select(AuditEventRow).order_by(AuditEventRow.created_at.desc()).limit(250)
            ).all()
        return [self._audit_record(row) for row in rows]

    def create_job(self, request: JobCreate) -> JobRecord:
        now = datetime.now(UTC)
        row = JobRow(
            id=uuid.uuid4().hex[:16],
            kind=request.kind,
            status=JobStatus.queued.value,
            payload=request.payload,
            result={},
            created_at=now,
            updated_at=now,
        )
        with self.session_factory.begin() as session:
            session.add(row)
        return self._job_record(row)

    def complete_job(self, job_id: str, result: dict, failed: bool = False) -> JobRecord | None:
        with self.session_factory.begin() as session:
            row = session.get(JobRow, job_id)
            if row is None:
                return None
            row.status = JobStatus.failed.value if failed else JobStatus.succeeded.value
            row.result = result
            row.updated_at = datetime.now(UTC)
            job = self._job_record(row)
        return job

    def list_jobs(self) -> list[JobRecord]:
        with self.session_factory() as session:
            rows = session.scalars(select(JobRow).order_by(JobRow.created_at.desc()).limit(250)).all()
        return [self._job_record(row) for row in rows]

    def create_monitor(self, request: MonitorCreate) -> MonitorRecord:
        now = datetime.now(UTC)
        row = MonitorRow(
            id=uuid.uuid4().hex[:16],
            name=request.name,
            query=request.query,
            threshold=request.threshold,
            cadence=request.cadence,
            enabled=request.enabled,
            last_result={},
            created_at=now,
            updated_at=now,
        )
        with self.session_factory.begin() as session:
            session.add(row)
        return self._monitor_record(row)

    def list_monitors(self) -> list[MonitorRecord]:
        with self.session_factory() as session:
            rows = session.scalars(select(MonitorRow).order_by(MonitorRow.created_at.desc())).all()
        return [self._monitor_record(row) for row in rows]

    def update_monitor_result(self, monitor_id: str, result: dict) -> MonitorRecord | None:
        with self.session_factory.begin() as session:
            row = session.get(MonitorRow, monitor_id)
            if row is None:
                return None
            row.last_result = result
            row.updated_at = datetime.now(UTC)
            monitor = self._monitor_record(row)
        return monitor

    def create_notification(self, request: NotificationCreate, delivered: bool = False) -> NotificationRecord:
        row = NotificationRow(
            id=uuid.uuid4().hex[:16],
            channel=request.channel,
            target=request.target,
            title=request.title,
            body=request.body,
            delivered=delivered,
            created_at=datetime.now(UTC),
        )
        with self.session_factory.begin() as session:
            session.add(row)
        return self._notification_record(row)

    def list_notifications(self) -> list[NotificationRecord]:
        with self.session_factory() as session:
            rows = session.scalars(
                select(NotificationRow).order_by(NotificationRow.created_at.desc()).limit(250)
            ).all()
        return [self._notification_record(row) for row in rows]

    def save_rule(self, request: RuleCreate) -> RuleRecord:
        with self.session_factory() as session:
            existing = session.scalars(
                select(RuleRow)
                .where(RuleRow.report_id == request.report_id)
                .where(RuleRow.kind == request.kind.value)
                .where(RuleRow.name == request.name)
            ).all()
            version = len(existing) + 1
        row = RuleRow(
            id=uuid.uuid4().hex[:16],
            report_id=request.report_id,
            kind=request.kind.value,
            name=request.name,
            content=request.content,
            rationale=request.rationale,
            version=version,
            created_at=datetime.now(UTC),
        )
        with self.session_factory.begin() as session:
            session.add(row)
        return self._rule_record(row)

    def list_rules(self, report_id: str | None = None) -> list[RuleRecord]:
        with self.session_factory() as session:
            statement = select(RuleRow).order_by(RuleRow.created_at.desc())
            if report_id:
                statement = statement.where(RuleRow.report_id == report_id)
            rows = session.scalars(statement).all()
        return [self._rule_record(row) for row in rows]

    def dashboard(self) -> DashboardMetrics:
        with self.session_factory() as session:
            investigation_rows = session.scalars(select(InvestigationRow)).all()
            case_rows = session.scalars(select(CaseRow)).all()
            evidence_rows = session.scalars(select(EvidenceRow)).all()
            monitor_rows = session.scalars(select(MonitorRow)).all()
        open_cases: dict[str, int] = {}
        for row in case_rows:
            if row.status != CaseStatus.closed.value:
                open_cases[row.severity] = open_cases.get(row.severity, 0) + 1
        average = (
            sum(row.risk_score for row in investigation_rows) / len(investigation_rows)
            if investigation_rows
            else 0
        )
        return DashboardMetrics(
            investigations=len(investigation_rows),
            cases=len(case_rows),
            evidence=len(evidence_rows),
            monitors=len(monitor_rows),
            open_cases_by_severity=open_cases,
            average_risk_score=round(average, 2),
        )

    def _case_investigation_ids(self, session: Session, case_id: str) -> list[str]:
        return list(
            session.scalars(select(InvestigationRow.id).where(InvestigationRow.case_id == case_id))
        )

    def _case_evidence_ids(self, session: Session, case_id: str) -> list[str]:
        return list(session.scalars(select(EvidenceRow.id).where(EvidenceRow.case_id == case_id)))

    def _case_record(
        self,
        row: CaseRow,
        investigation_ids: list[str],
        evidence_ids: list[str],
    ) -> CaseRecord:
        return CaseRecord(
            id=row.id,
            title=row.title,
            description=row.description,
            owner=row.owner,
            severity=Severity(row.severity),
            status=CaseStatus(row.status),
            tags=row.tags or [],
            created_at=row.created_at,
            updated_at=row.updated_at,
            investigation_ids=investigation_ids,
            evidence_ids=evidence_ids,
        )

    def _evidence_record(self, row: EvidenceRow) -> EvidenceRecord:
        return EvidenceRecord(
            id=row.id,
            case_id=row.case_id,
            title=row.title,
            source_type=row.source_type,
            content=row.content,
            source_uri=row.source_uri,
            sha256=row.sha256,
            size_bytes=row.size_bytes,
            created_at=row.created_at,
        )

    def _comment_record(self, row: CaseCommentRow) -> CaseCommentRecord:
        return CaseCommentRecord(
            id=row.id,
            case_id=row.case_id,
            author=row.author,
            body=row.body,
            created_at=row.created_at,
        )

    def _user_record(self, row: UserRow) -> UserRecord:
        return UserRecord(
            id=row.id,
            email=row.email,
            name=row.name,
            role=UserRole(row.role),
            team=row.team,
            active=row.active,
            created_at=row.created_at,
        )

    def _audit_record(self, row: AuditEventRow) -> AuditEventRecord:
        return AuditEventRecord(
            id=row.id,
            actor=row.actor,
            action=row.action,
            resource_type=row.resource_type,
            resource_id=row.resource_id,
            metadata=row.event_metadata or {},
            created_at=row.created_at,
        )

    def _job_record(self, row: JobRow) -> JobRecord:
        return JobRecord(
            id=row.id,
            kind=row.kind,
            status=JobStatus(row.status),
            payload=row.payload or {},
            result=row.result or {},
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    def _monitor_record(self, row: MonitorRow) -> MonitorRecord:
        return MonitorRecord(
            id=row.id,
            name=row.name,
            query=row.query,
            threshold=row.threshold,
            cadence=row.cadence,
            enabled=row.enabled,
            last_result=row.last_result or {},
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    def _notification_record(self, row: NotificationRow) -> NotificationRecord:
        return NotificationRecord(
            id=row.id,
            channel=row.channel,
            target=row.target,
            title=row.title,
            body=row.body,
            delivered=row.delivered,
            created_at=row.created_at,
        )

    def _rule_record(self, row: RuleRow) -> RuleRecord:
        return RuleRecord(
            id=row.id,
            report_id=row.report_id,
            kind=RuleKind(row.kind),
            name=row.name,
            content=row.content,
            rationale=row.rationale,
            version=row.version,
            created_at=row.created_at,
        )
