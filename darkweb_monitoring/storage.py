import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from .models import InvestigationReport


def _sqlite_path(database_url: str) -> Path:
    if not database_url.startswith("sqlite:///"):
        raise ValueError("Only sqlite:/// database URLs are supported by the bundled storage engine.")
    return Path(database_url.removeprefix("sqlite:///")).resolve()


class InvestigationStore:
    def __init__(self, database_url: str):
        self.path = _sqlite_path(database_url)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS investigations (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )

    def save(self, report: InvestigationReport) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO investigations (id, title, created_at, risk_score, payload)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    report.id,
                    report.title,
                    report.created_at.isoformat(),
                    report.risk_score,
                    report.model_dump_json(),
                ),
            )

    def list_reports(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, title, created_at, risk_score
                FROM investigations
                ORDER BY created_at DESC
                LIMIT 100
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def get(self, report_id: str) -> InvestigationReport | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM investigations WHERE id = ?",
                (report_id,),
            ).fetchone()
        if row is None:
            return None
        return InvestigationReport.model_validate(json.loads(row["payload"]))

