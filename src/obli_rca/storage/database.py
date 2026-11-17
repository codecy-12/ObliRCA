"""Storage schema and connection handling.

SQLite is the default for a self-contained prototype.  The same schema can be
deployed on MySQL by setting ``OBLIRCA_DB_URL``; the paper's implementation uses
separate obligation-library and investigation tables, which is mirrored here.
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator

SCHEMA: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS obl_entries (
        id TEXT PRIMARY KEY,
        category TEXT NOT NULL,
        category_id INTEGER NOT NULL DEFAULT 0,
        version TEXT NOT NULL,
        semantic_hash TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'accepted',
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS obl_graphs (
        entry_id TEXT NOT NULL,
        graph_id TEXT NOT NULL,
        semantic_hash TEXT NOT NULL,
        payload TEXT NOT NULL,
        PRIMARY KEY (entry_id, graph_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS obl_cases (
        entry_id TEXT NOT NULL,
        case_ref TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'source',
        source TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (entry_id, case_ref, role)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS inv_investigations (
        id TEXT PRIMARY KEY,
        scenario_id TEXT NOT NULL,
        source_version TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'running',
        created_at TEXT NOT NULL,
        metadata TEXT NOT NULL DEFAULT '{}'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS inv_framework (
        investigation_id TEXT NOT NULL,
        node_id TEXT NOT NULL,
        app TEXT NOT NULL,
        source_version TEXT NOT NULL DEFAULT '',
        file TEXT NOT NULL,
        function TEXT NOT NULL,
        start_line INTEGER NOT NULL DEFAULT 0,
        end_line INTEGER NOT NULL DEFAULT 0,
        kind TEXT NOT NULL DEFAULT 'function_slice',
        snippet TEXT NOT NULL DEFAULT '',
        event_ids TEXT NOT NULL DEFAULT '[]',
        parent_id TEXT,
        metadata TEXT NOT NULL DEFAULT '{}',
        PRIMARY KEY (investigation_id, node_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS inv_log_refs (
        investigation_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        app TEXT NOT NULL,
        tid INTEGER NOT NULL DEFAULT 0,
        syscall TEXT NOT NULL,
        object TEXT,
        payload TEXT NOT NULL,
        PRIMARY KEY (investigation_id, event_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS inv_hypotheses (
        investigation_id TEXT NOT NULL,
        hypothesis_id TEXT NOT NULL,
        obligation_id TEXT NOT NULL,
        location TEXT NOT NULL,
        mechanism TEXT NOT NULL,
        gap_type TEXT NOT NULL,
        status TEXT NOT NULL,
        confidence REAL NOT NULL DEFAULT 0,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (investigation_id, hypothesis_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS inv_feedback (
        investigation_id TEXT NOT NULL,
        hypothesis_id TEXT NOT NULL,
        round INTEGER NOT NULL,
        request TEXT NOT NULL,
        response TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (investigation_id, hypothesis_id, round)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS inv_rankings (
        investigation_id TEXT NOT NULL,
        hypothesis_id TEXT NOT NULL,
        rank INTEGER NOT NULL,
        score REAL NOT NULL DEFAULT 0,
        explanation TEXT NOT NULL DEFAULT '',
        fix TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (investigation_id, hypothesis_id)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_obl_entries_hash ON obl_entries(semantic_hash)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_inv_framework_app ON inv_framework(investigation_id, app)
    """,
]


class Database:
    def __init__(self, url: str):
        self.url = url
        self.backend = "mysql" if url.startswith("mysql") else "sqlite"
        self._conn: Any = None
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    def connect(self) -> Any:
        if self._conn is not None:
            return self._conn
        if self.backend == "mysql":
            try:
                import pymysql  # type: ignore
            except ImportError as exc:  # pragma: no cover - optional dependency
                raise RuntimeError("pymysql is required for MySQL storage") from exc
            from urllib.parse import urlparse

            parsed = urlparse(self.url.replace("mysql+pymysql://", "mysql://"))
            self._conn = pymysql.connect(
                host=parsed.hostname or "127.0.0.1",
                port=parsed.port or 3306,
                user=parsed.username or "root",
                password=parsed.password or "",
                database=(parsed.path or "/obli_rca").lstrip("/"),
                autocommit=False,
                charset="utf8mb4",
            )
        else:
            path = self.url.replace("sqlite:///", "").replace("sqlite://", "")
            db_path = Path(path)
            db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
        return self._conn

    def init_schema(self) -> None:
        conn = self.connect()
        cursor = conn.cursor()
        for statement in SCHEMA:
            cursor.execute(self._adapt(statement))
        conn.commit()

    def _adapt(self, sql: str) -> str:
        return sql.replace("?", "%s") if self.backend == "mysql" else sql

    def execute(self, sql: str, params: Iterable[Any] = ()) -> Any:
        with self._lock:
            conn = self.connect()
            cursor = conn.cursor()
            cursor.execute(self._adapt(sql), tuple(params))
            return cursor

    def executemany(self, sql: str, rows: Iterable[Iterable[Any]]) -> Any:
        with self._lock:
            conn = self.connect()
            cursor = conn.cursor()
            cursor.executemany(self._adapt(sql), [tuple(r) for r in rows])
            return cursor

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
        with self._lock:
            cursor = self.execute(sql, params)
            columns = [d[0] for d in cursor.description or []]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def query_one(self, sql: str, params: Iterable[Any] = ()) -> dict[str, Any] | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def commit(self) -> None:
        with self._lock:
            self.connect().commit()

    @contextmanager
    def transaction(self) -> Iterator[Any]:
        conn = self.connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
