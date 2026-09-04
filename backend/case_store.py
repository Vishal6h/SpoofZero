"""Versioned local cases and append-only analysis history.

The original case_emails rows remain an immutable compatibility record. Runtime
analysis does not retain EML bodies or attachment payloads.
"""
from contextlib import contextmanager
from datetime import date, datetime, timezone
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import re
import sqlite3
from uuid import uuid4

DB_SCHEMA_VERSION = 1
MAX_CASE_EMAILS = 200
MAX_ANALYSES_PER_EMAIL = 100
DEFAULT_DB_PATH = Path(__file__).resolve().parents[1] / "data" / "cases" / "spoofzero.sqlite3"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def _text(value, label, maximum, required=False):
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    value = value.strip()
    if (required and not value) or len(value) > maximum:
        raise ValueError(f"{label} must contain {'1' if required else '0'} to {maximum} characters")
    return value


class CaseStore:
    def __init__(self, db_path=None):
        self.path = Path(db_path or os.getenv("SPOOFZERO_CASE_DB") or DEFAULT_DB_PATH)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.migration_backup = None
        self._initialize()

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

    def _backup(self):
        backup = self.path.with_name(self.path.name + ".pre-v1-" + uuid4().hex + ".bak")
        # The migration connection holds BEGIN IMMEDIATE, preventing concurrent
        # writes. A separate read connection snapshots committed legacy data.
        try:
            with sqlite3.connect(self.path) as source, sqlite3.connect(backup) as target:
                source.backup(target)
                if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValueError("Case backup failed its integrity check")
        except Exception:
            # Keep any partial backup for inspection; never remove user evidence.
            raise
        self.migration_backup = backup

    def _initialize(self):
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version == DB_SCHEMA_VERSION:
                return
            if version != 0:
                raise ValueError(f"Unsupported case database schema version: {version}")
            tables = {r[0] for r in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )}
            if tables and tables != {"cases", "case_emails"}:
                raise ValueError("Unrecognized legacy case schema; database was not modified")
            if tables:
                columns = {
                    table: {r[1] for r in connection.execute(f"PRAGMA table_info({table})")}
                    for table in ("cases", "case_emails")
                }
                if columns != {
                    "cases": {"case_id", "name", "created_at"},
                    "case_emails": {"case_id", "email_id", "filename", "analyzed_at", "analysis_json"},
                }:
                    raise ValueError("Unrecognized legacy case columns; database was not modified")
                self._backup()
                connection.execute("ALTER TABLE cases ADD COLUMN description TEXT NOT NULL DEFAULT ''")
                connection.execute("ALTER TABLE cases ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''")
                connection.execute("ALTER TABLE cases ADD COLUMN archived INTEGER NOT NULL DEFAULT 0")
                connection.execute("""UPDATE cases SET updated_at = max(created_at, coalesce(
                    (SELECT max(analyzed_at) FROM case_emails WHERE case_emails.case_id=cases.case_id),
                    created_at))""")
            else:
                connection.execute("""CREATE TABLE cases (
                    case_id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL,
                    archived INTEGER NOT NULL DEFAULT 0 CHECK(archived IN (0, 1))
                )""")
                connection.execute("""CREATE TABLE case_emails (
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    email_id TEXT NOT NULL, filename TEXT NOT NULL,
                    analyzed_at TEXT NOT NULL, analysis_json TEXT NOT NULL,
                    PRIMARY KEY (case_id, email_id)
                )""")
            connection.execute("""CREATE TABLE analysis_versions (
                case_id TEXT NOT NULL, email_id TEXT NOT NULL,
                analysis_id TEXT NOT NULL, version INTEGER NOT NULL CHECK(version > 0),
                filename TEXT NOT NULL, analyzed_at TEXT NOT NULL,
                analysis_json TEXT NOT NULL,
                PRIMARY KEY (case_id, analysis_id),
                UNIQUE(case_id, email_id, version),
                FOREIGN KEY (case_id, email_id) REFERENCES case_emails(case_id, email_id)
            )""")
            for row in connection.execute("SELECT * FROM case_emails").fetchall():
                identity = sha256(("legacy:" + row["case_id"] + ":" + row["email_id"]).encode()).hexdigest()[:32]
                connection.execute("INSERT INTO analysis_versions VALUES (?, ?, ?, 1, ?, ?, ?)",
                                   (row["case_id"], row["email_id"], identity, row["filename"],
                                    row["analyzed_at"], row["analysis_json"]))
            connection.execute("CREATE INDEX analysis_timeline ON analysis_versions(case_id, analyzed_at)")
            # Immutable evidence is enforced at the storage boundary as well as
            # by the public append-only API. Case metadata remains editable.
            for table in ("case_emails", "analysis_versions"):
                for operation in ("UPDATE", "DELETE"):
                    connection.execute(f"""CREATE TRIGGER preserve_{table}_{operation.lower()}
                        BEFORE {operation} ON {table} BEGIN
                        SELECT RAISE(ABORT, 'Historical email evidence is immutable'); END""")
            connection.execute(f"PRAGMA user_version = {DB_SCHEMA_VERSION}")

    def create_case(self, name, description=""):
        name = _text(name, "Case name", 120, True)
        description = _text(description, "Case description", 1000)
        case_id, now = uuid4().hex, utc_now()
        with self.connection() as connection:
            connection.execute("""INSERT INTO cases
                (case_id, name, created_at, description, updated_at, archived)
                VALUES (?, ?, ?, ?, ?, 0)""", (case_id, name, now, description, now))
        return case_id

    def _require_case(self, connection, case_id, *, writable=False):
        row = connection.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
        if row is None:
            raise ValueError("Case does not exist")
        if writable and row["archived"]:
            raise ValueError("Restore this archived case before adding evidence")
        return dict(row)

    def get_case(self, case_id):
        with self.connection() as connection:
            return self._require_case(connection, case_id)

    def rename_case(self, case_id, name, description=None):
        name = _text(name, "Case name", 120, True)
        with self.connection() as connection:
            previous = self._require_case(connection, case_id)
            description = previous["description"] if description is None else _text(
                description, "Case description", 1000)
            connection.execute("UPDATE cases SET name=?, description=?, updated_at=? WHERE case_id=?",
                               (name, description, utc_now(), case_id))

    def archive_case(self, case_id, archived=True):
        if type(archived) is not bool:
            raise ValueError("Archive state must be a Boolean")
        with self.connection() as connection:
            self._require_case(connection, case_id)
            connection.execute("UPDATE cases SET archived=?, updated_at=? WHERE case_id=?",
                               (int(archived), utc_now(), case_id))

    def list_cases(self, *, query="", verdict=None, sender="", date_from=None,
                   date_to=None, campaign=None, sort="newest", include_archived=False):
        if sort not in {"newest", "oldest", "highest_risk", "recently_updated"}:
            raise ValueError("Unsupported case sort")
        start = date.fromisoformat(str(date_from)) if date_from else None
        end = date.fromisoformat(str(date_to)) if date_to else None
        if start and end and start > end:
            raise ValueError("Start date must not be after end date")
        with self.connection() as connection:
            cases = [dict(row) for row in connection.execute("SELECT * FROM cases")]
        results = []
        for case in cases:
            if case["archived"] and not include_archived:
                continue
            records = self.list_analyses(case["case_id"])
            history = self.list_analysis_history(case["case_id"])
            case["email_count"] = len(records)
            case["analysis_count"] = len(history)
            scores = [r["analysis"].get("final_assessment", {}).get("risk_score") for r in history]
            scores = [x for x in scores if isinstance(x, (int, float))
                      and not isinstance(x, bool) and math.isfinite(x)]
            case["highest_risk"] = max(scores) if scores else None
            searchable = [case["case_id"], case["name"], case["description"]]
            searchable += [
                str(r["analysis"].get("email", {}).get(key) or "")
                for r in history for key in ("from", "subject")
            ]
            if query and str(query).casefold() not in " ".join(searchable).casefold():
                continue
            if verdict and not any(
                r["analysis"].get("final_assessment", {}).get("verdict") == verdict for r in history
            ):
                continue
            if sender and not any(
                str(sender).casefold() in " ".join([
                    str(r["analysis"].get("email", {}).get("from") or ""),
                    *map(str, r["analysis"].get("iocs", {}).get("domains") or []),
                ]).casefold() for r in history
            ):
                continue
            # Date filters refer to UTC analysis timestamps, not untrusted Date headers.
            dates = [r["analyzed_at"][:10] for r in history] or [case["created_at"][:10]]
            if (start or end) and not any(
                (not start or str(start) <= d) and (not end or d <= str(end)) for d in dates
            ):
                continue
            if campaign is not None:
                from .analyzers.campaign_correlator import correlate_emails
                case["has_campaign"] = bool(correlate_emails(records)["campaigns"])
                if case["has_campaign"] is not campaign:
                    continue
            results.append(case)
        if sort == "oldest":
            key, reverse = lambda c: (c["created_at"], c["case_id"]), False
        elif sort == "recently_updated":
            key, reverse = lambda c: (c["updated_at"], c["case_id"]), True
        elif sort == "highest_risk":
            key, reverse = lambda c: (c["highest_risk"] if c["highest_risk"] is not None else -1,
                                     c["updated_at"], c["case_id"]), True
        else:
            key, reverse = lambda c: (c["created_at"], c["case_id"]), True
        return sorted(results, key=key, reverse=reverse)

    def list_analysis_history(self, case_id, email_id=None):
        with self.connection() as connection:
            self._require_case(connection, case_id)
            query = """SELECT v.*, e.analyzed_at AS first_analyzed_at,
                (v.version=(SELECT max(x.version) FROM analysis_versions x
                  WHERE x.case_id=v.case_id AND x.email_id=v.email_id)) AS is_latest
                FROM analysis_versions v JOIN case_emails e
                  ON v.case_id=e.case_id AND v.email_id=e.email_id
                WHERE v.case_id=?"""
            args = [case_id]
            if email_id is not None:
                query += " AND v.email_id=?"
                args.append(email_id)
            rows = connection.execute(query + " ORDER BY v.analyzed_at, v.email_id, v.version", args).fetchall()
        return [self._record(row) for row in rows]

    def list_analyses(self, case_id):
        """Compatibility view: the latest snapshot for each distinct raw email."""
        return [r for r in self.list_analysis_history(case_id) if r["is_latest"]]

    @staticmethod
    def _record(row):
        record = dict(row)
        record["analysis"] = json.loads(record.pop("analysis_json"))
        record["is_latest"] = bool(record["is_latest"])
        return record

    def get_analysis(self, case_id, email_id, analysis_id=None):
        records = self.list_analysis_history(case_id, email_id)
        if analysis_id:
            return next((r for r in records if r["analysis_id"] == analysis_id), None)
        return next((r for r in records if r["is_latest"]), None)

    def add_analysis(self, case_id, filename, analysis, *, allow_reanalysis=False,
                     analysis_id=None, analyzed_at=None):
        email_id = (analysis.get("email") or {}).get("sha256") or ""
        if not re.fullmatch(r"[a-f0-9]{64}", email_id):
            raise ValueError("Analyze the email again to obtain its raw EML SHA-256")
        serialized = json.dumps(analysis, ensure_ascii=False, allow_nan=False)
        identity = analysis_id or uuid4().hex
        if not re.fullmatch(r"[a-f0-9]{32}", identity):
            raise ValueError("Analysis identifier must be a 32-character hexadecimal ID")
        when = analyzed_at or utc_now()
        try:
            stamp = datetime.fromisoformat(when)
            if stamp.tzinfo is None:
                raise ValueError()
            when = stamp.astimezone(timezone.utc).isoformat()
        except (TypeError, ValueError):
            raise ValueError("Analysis timestamp must include a timezone") from None
        with self.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_case(connection, case_id, writable=True)
            duplicate = connection.execute(
                "SELECT email_id, analysis_json FROM analysis_versions WHERE case_id=? AND analysis_id=?",
                (case_id, identity)).fetchone()
            if duplicate:
                if duplicate["email_id"] != email_id or duplicate["analysis_json"] != serialized:
                    raise ValueError("Analysis identifier is already bound to different evidence")
                return False
            original = connection.execute(
                "SELECT 1 FROM case_emails WHERE case_id=? AND email_id=?", (case_id, email_id)
            ).fetchone()
            if original and not allow_reanalysis:
                return False
            if not original:
                count = connection.execute(
                    "SELECT count(*) FROM case_emails WHERE case_id=?", (case_id,)
                ).fetchone()[0]
                if count >= MAX_CASE_EMAILS:
                    raise ValueError(f"Each case supports up to {MAX_CASE_EMAILS} unique emails")
                connection.execute("INSERT INTO case_emails VALUES (?, ?, ?, ?, ?)",
                                   (case_id, email_id, filename, when, serialized))
            version = connection.execute("""SELECT coalesce(max(version),0)+1
                FROM analysis_versions WHERE case_id=? AND email_id=?""",
                                         (case_id, email_id)).fetchone()[0]
            if version > MAX_ANALYSES_PER_EMAIL:
                raise ValueError(f"Each email supports up to {MAX_ANALYSES_PER_EMAIL} analysis versions")
            connection.execute("INSERT INTO analysis_versions VALUES (?, ?, ?, ?, ?, ?, ?)",
                               (case_id, email_id, identity, version, filename, when, serialized))
            connection.execute("UPDATE cases SET updated_at=? WHERE case_id=?", (utc_now(), case_id))
        return True
