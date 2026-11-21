"""SQLite connection management.

Repositories are storage-agnostic in shape (explicit SQL, no ORM). PostgreSQL can
be introduced by reimplementing :class:`Database` and the repository classes; the
domain, policy and orchestration layers do not depend on SQLite specifics.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sentinel.errors import ConfigError

SCHEMA_VERSION = 1
_SCHEMA_PATH = Path(__file__).with_name("schema.sql")


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._local = threading.local()
        self._write_lock = threading.RLock()
        self._init_lock = threading.Lock()
        self._initialized = False

    # -- connections ------------------------------------------------------
    def connect(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                self.path,
                timeout=15,
                isolation_level=None,
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=15000")
            if self.path != ":memory:":
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = conn
        return conn

    def initialize(self) -> None:
        with self._init_lock:
            if self._initialized:
                return
            if self.path != ":memory:":
                Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            conn = self.connect()
            schema = _SCHEMA_PATH.read_text(encoding="utf-8")
            conn.executescript(schema)
            conn.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, datetime('now'))",
                (SCHEMA_VERSION,),
            )
            self._initialized = True

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    # -- transactions -----------------------------------------------------
    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """Serialised write transaction (BEGIN IMMEDIATE)."""
        self.initialize()
        conn = self.connect()
        with self._write_lock:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            else:
                conn.execute("COMMIT")

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        self.initialize()
        return list(self.connect().execute(sql, params).fetchall())

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def execute(self, sql: str, params: Sequence[Any] = ()) -> int:
        with self.tx() as conn:
            cursor = conn.execute(sql, params)
            return cursor.rowcount

    def health(self) -> bool:
        try:
            row = self.query_one("SELECT 1 AS ok")
            return bool(row and row["ok"] == 1)
        except sqlite3.Error:
            return False

    def require_initialized(self) -> None:
        try:
            row = self.query_one("SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1")
        except sqlite3.Error as exc:  # pragma: no cover - defensive
            raise ConfigError("database is not initialised") from exc
        if row is None or int(row["version"]) != SCHEMA_VERSION:
            raise ConfigError("database schema version mismatch; run `sentinel init-db`")


def open_database(path: str | Path) -> Database:
    db = Database(path)
    db.initialize()
    return db
