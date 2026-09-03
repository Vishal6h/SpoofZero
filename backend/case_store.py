"""Local SQLite case storage. No EML bodies or attachment payloads are stored."""

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sqlite3
from uuid import uuid4


MAX_CASE_EMAILS = 200
DEFAULT_DB_PATH = Path(__file__).resolve().parents[1] / "data" / "cases" / "spoofzero.sqlite3"


class CaseStore:
    def __init__(self, db_path=None):
        self.path = Path(db_path or os.getenv("SPOOFZERO_CASE_DB") or DEFAULT_DB_PATH)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS case_emails (
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    email_id TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    analyzed_at TEXT NOT NULL,
                    analysis_json TEXT NOT NULL,
                    PRIMARY KEY (case_id, email_id)
                );
            """)

    @contextmanager
    def connection(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def create_case(self, name):
        name = name.strip()
        if not name or len(name) > 120:
            raise ValueError("Case name must contain 1 to 120 characters")
        case_id = uuid4().hex
        with self.connection() as connection:
            connection.execute("INSERT INTO cases VALUES (?, ?, ?)",
                               (case_id, name, datetime.now(timezone.utc).isoformat()))
        return case_id

    def list_cases(self):
        with self.connection() as connection:
            return [dict(row) for row in connection.execute("""
                SELECT c.*, count(e.email_id) AS email_count
                FROM cases c LEFT JOIN case_emails e ON c.case_id = e.case_id
                GROUP BY c.case_id ORDER BY c.created_at DESC, c.case_id
            """)]

    def _require_case(self, connection, case_id):
        if not connection.execute("SELECT 1 FROM cases WHERE case_id = ?", (case_id,)).fetchone():
            raise ValueError("Case does not exist")

    def list_analyses(self, case_id):
        with self.connection() as connection:
            self._require_case(connection, case_id)
            rows = connection.execute("""
                SELECT * FROM case_emails WHERE case_id = ? ORDER BY analyzed_at, email_id
            """, (case_id,)).fetchall()
        return [self._record(row) for row in rows]

    @staticmethod
    def _record(row):
        record = dict(row)
        record["analysis"] = json.loads(record.pop("analysis_json"))
        return record

    def get_analysis(self, case_id, email_id):
        with self.connection() as connection:
            self._require_case(connection, case_id)
            row = connection.execute("SELECT * FROM case_emails WHERE case_id = ? AND email_id = ?",
                                     (case_id, email_id)).fetchone()
        return self._record(row) if row else None

    def add_analysis(self, case_id, filename, analysis):
        email_id = (analysis.get("email") or {}).get("sha256") or ""
        if not re.fullmatch(r"[a-f0-9]{64}", email_id):
            raise ValueError("Analyze the email again to obtain its raw EML SHA-256")
        serialized = json.dumps(analysis, ensure_ascii=False, allow_nan=False)
        with self.connection() as connection:
            # Serialize the capacity check and insert across simultaneous sessions.
            connection.execute("BEGIN IMMEDIATE")
            self._require_case(connection, case_id)
            if connection.execute("SELECT 1 FROM case_emails WHERE case_id = ? AND email_id = ?",
                                  (case_id, email_id)).fetchone():
                return False
            count = connection.execute("SELECT count(*) FROM case_emails WHERE case_id = ?", (case_id,)).fetchone()[0]
            if count >= MAX_CASE_EMAILS:
                raise ValueError(f"Each case supports up to {MAX_CASE_EMAILS} unique emails")
            connection.execute("INSERT INTO case_emails VALUES (?, ?, ?, ?, ?)",
                               (case_id, email_id, filename, datetime.now(timezone.utc).isoformat(), serialized))
        return True
