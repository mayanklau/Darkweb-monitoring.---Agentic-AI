import json
import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, Integer, String, Text, create_engine, inspect, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from .models import (
    CaseCreate,
    CaseRecord,
    CaseStatus,
    CaseUpdate,
    EvidenceCreate,
    EvidenceRecord,
    InvestigationReport,
    Severity,
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

    def add_evidence(self, request: EvidenceCreate, case_id: str | None = None) -> EvidenceRecord:
        row = EvidenceRow(
            id=uuid.uuid4().hex[:16],
            case_id=case_id,
            title=request.title,
            source_type=request.source_type,
            content=request.content,
            source_uri=request.source_uri,
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
            created_at=row.created_at,
        )
